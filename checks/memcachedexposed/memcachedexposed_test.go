// Tests the Memcached exposed check against fake TCP servers.

package memcachedexposed

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nuqs-org/nuqs/internal/check"
	"github.com/nuqs-org/nuqs/internal/model"
)

type fakeMemcached struct {
	reply      string
	silent     bool
	closeEarly bool

	mu   sync.Mutex
	got  []string
	addr string
}

func startMemcached(t *testing.T, f *fakeMemcached) *fakeMemcached {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	f.addr = l.Addr().String()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go f.handle(conn)
		}
	}()
	return f
}

func (f *fakeMemcached) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if f.closeEarly {
		return
	}
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}
	f.mu.Lock()
	f.got = append(f.got, string(buf[:n]))
	f.mu.Unlock()
	if f.silent {
		_, _ = conn.Read(buf)
		return
	}
	_, _ = conn.Write([]byte(f.reply))
}

func (f *fakeMemcached) target(t *testing.T) check.Target {
	t.Helper()
	host, port, _ := net.SplitHostPort(f.addr)
	p, _ := strconv.Atoi(port)
	return check.Target{Host: host, Service: model.Service{Port: p, Protocol: "tcp", Name: "memcached"}}
}

func TestInfo(t *testing.T) {
	in := Check{}.Info()
	if err := check.Validate([]check.Check{Check{}}); err != nil {
		t.Fatal(err)
	}
	if in.ID != "memcached-exposed" || in.Severity != model.High {
		t.Fatalf("unexpected info: %+v", in)
	}
	if !check.Applies(in, model.Service{Port: 11211}) {
		t.Error("should apply to port 11211")
	}
	if !check.Applies(in, model.Service{Port: 21211, Name: "memcached"}) {
		t.Error("should apply to memcached on a non-standard port")
	}
	if check.Applies(in, model.Service{Port: 80, Name: "http"}) {
		t.Error("should not apply to http")
	}
}

func TestPositive(t *testing.T) {
	cases := []struct {
		name string
		wire string
		want string
	}{
		{
			name: "version and uptime",
			wire: "STAT pid 1\r\nSTAT uptime 42\r\nSTAT time 1732820000\r\nSTAT version 1.6.38\r\nEND\r\n",
			want: "sent stats and got Memcached 1.6.38 (uptime 42s)",
		},
		{
			name: "version only",
			wire: "STAT version 1.6.22\r\nEND\r\n",
			want: "sent stats and got Memcached 1.6.22",
		},
		{
			name: "uptime only",
			wire: "STAT uptime 99\r\nEND\r\n",
			want: "sent stats and got Memcached stats (uptime 99s)",
		},
		{
			name: "other stats only",
			wire: "STAT pid 7\r\nEND\r\n",
			want: "sent stats and got Memcached stats reply without authentication",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := startMemcached(t, &fakeMemcached{reply: tc.wire})
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			res, err := Check{}.Run(ctx, f.target(t))
			if err != nil || res == nil {
				t.Fatalf("expected finding, got res=%+v err=%v", res, err)
			}
			if res.Evidence != tc.want {
				t.Errorf("evidence = %q, want %q", res.Evidence, tc.want)
			}
			f.mu.Lock()
			got := append([]string(nil), f.got...)
			f.mu.Unlock()
			if len(got) == 0 || got[0] != "stats\r\n" {
				t.Errorf("commands sent = %q, want stats\\r\\n", got)
			}
		})
	}
}

func TestAuthRejectedIsClean(t *testing.T) {
	for _, reply := range []string{
		"CLIENT_ERROR authentication required\r\n",
		"CLIENT_ERROR unauthorized\r\n",
	} {
		f := startMemcached(t, &fakeMemcached{reply: reply})
		res, err := Check{}.Run(context.Background(), f.target(t))
		if err != nil || res != nil {
			t.Errorf("reply %q: expected clean result, got res=%+v err=%v", reply, res, err)
		}
	}
}

func TestErrors(t *testing.T) {
	t.Run("garbage replies", func(t *testing.T) {
		for _, reply := range []string{
			"SSH-2.0-OpenSSH_9.6\r\n",
			"HTTP/1.1 400 Bad Request\r\n",
			"ERROR\r\n",
			"STAT pid 1\r\n", // truncated before END with no version/uptime
		} {
			f := startMemcached(t, &fakeMemcached{reply: reply})
			res, err := Check{}.Run(context.Background(), f.target(t))
			if err == nil || res != nil {
				t.Errorf("reply %q: expected error, got res=%+v err=%v", reply, res, err)
			}
		}
	})

	t.Run("early close", func(t *testing.T) {
		f := startMemcached(t, &fakeMemcached{closeEarly: true})
		res, err := Check{}.Run(context.Background(), f.target(t))
		if err == nil || res != nil {
			t.Fatalf("expected error on early close, got res=%+v err=%v", res, err)
		}
	})

	t.Run("server down", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := l.Addr().String()
		l.Close()
		host, port, _ := net.SplitHostPort(addr)
		p, _ := strconv.Atoi(port)
		res, err := Check{}.Run(context.Background(), check.Target{Host: host, Service: model.Service{Port: p, Protocol: "tcp", Name: "memcached"}})
		if err == nil || res != nil {
			t.Fatalf("expected error on closed port, got res=%+v err=%v", res, err)
		}
	})

	t.Run("respects context timeout", func(t *testing.T) {
		f := startMemcached(t, &fakeMemcached{silent: true})
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		start := time.Now()
		res, err := Check{}.Run(ctx, f.target(t))
		if err == nil || res != nil || time.Since(start) > 2*time.Second {
			t.Fatalf("expected fast timeout, got res=%+v err=%v after %s", res, err, time.Since(start))
		}
	})

	t.Run("TLS not supported", func(t *testing.T) {
		res, err := Check{}.Run(context.Background(), check.Target{
			Host:    "127.0.0.1",
			Service: model.Service{Port: 11211, Name: "memcached", Tunnel: "ssl"},
		})
		if err == nil || res != nil || !strings.Contains(err.Error(), "TLS") {
			t.Fatalf("expected TLS error, got res=%+v err=%v", res, err)
		}
	})
}
