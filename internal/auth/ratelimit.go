// Sliding-window rate limiter protecting login, setup and password reset endpoints.

package auth

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	defaultRateWindow   = 15 * time.Minute
	defaultMaxPerIP     = 15
	defaultMaxPerIPUser = 5
	maxTrackedBuckets   = 4096
)

// RateLimiter tracks failed authentication attempts per client IP and per
// (client IP, username) pair within a sliding time window.
type RateLimiter struct {
	Window       time.Duration
	MaxPerIP     int
	MaxPerIPUser int
	Now          func() time.Time

	mu      sync.Mutex
	buckets map[string][]time.Time
}

// NewRateLimiter returns a RateLimiter with safe defaults for auth endpoints.
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		Window:       defaultRateWindow,
		MaxPerIP:     defaultMaxPerIP,
		MaxPerIPUser: defaultMaxPerIPUser,
		Now:          time.Now,
		buckets:      map[string][]time.Time{},
	}
}

// Allow reports whether an attempt from ip (optionally targeting username) is
// allowed right now. When denied, retryAfter is how long the caller must wait.
func (rl *RateLimiter) Allow(ip, username string) (bool, time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.now()
	win := rl.window()
	if wait := rl.checkBucket("ip:"+ip, rl.maxPerIP(), now, win); wait > 0 {
		return false, wait
	}
	if u := strings.ToLower(strings.TrimSpace(username)); u != "" {
		if wait := rl.checkBucket("u:"+ip+"|"+u, rl.maxPerIPUser(), now, win); wait > 0 {
			return false, wait
		}
	}
	return true, 0
}

// RecordFailure records a failed authentication attempt for ip and username.
func (rl *RateLimiter) RecordFailure(ip, username string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.now()
	win := rl.window()
	if len(rl.buckets) >= maxTrackedBuckets {
		rl.pruneAll(now, win)
	}
	rl.addEvent("ip:"+ip, now, win)
	if u := strings.ToLower(strings.TrimSpace(username)); u != "" {
		rl.addEvent("u:"+ip+"|"+u, now, win)
	}
}

// RecordSuccess clears the per-(IP, username) failure history after a valid login.
func (rl *RateLimiter) RecordSuccess(ip, username string) {
	u := strings.ToLower(strings.TrimSpace(username))
	if u == "" {
		return
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.buckets, "u:"+ip+"|"+u)
}

// ClientIP extracts the remote IP address from an HTTP request without trusting
// spoofable forwarding headers.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return host
}

func (rl *RateLimiter) now() time.Time {
	if rl.Now != nil {
		return rl.Now()
	}
	return time.Now()
}

func (rl *RateLimiter) window() time.Duration {
	if rl.Window > 0 {
		return rl.Window
	}
	return defaultRateWindow
}

func (rl *RateLimiter) maxPerIP() int {
	if rl.MaxPerIP > 0 {
		return rl.MaxPerIP
	}
	return defaultMaxPerIP
}

func (rl *RateLimiter) maxPerIPUser() int {
	if rl.MaxPerIPUser > 0 {
		return rl.MaxPerIPUser
	}
	return defaultMaxPerIPUser
}

func (rl *RateLimiter) checkBucket(key string, limit int, now time.Time, win time.Duration) time.Duration {
	ts := pruneSlice(rl.buckets[key], now.Add(-win))
	if len(ts) == 0 {
		delete(rl.buckets, key)
		return 0
	}
	rl.buckets[key] = ts
	if len(ts) < limit {
		return 0
	}
	wait := ts[0].Add(win).Sub(now)
	if wait < time.Second {
		wait = time.Second
	}
	return wait
}

func (rl *RateLimiter) addEvent(key string, now time.Time, win time.Duration) {
	ts := pruneSlice(rl.buckets[key], now.Add(-win))
	rl.buckets[key] = append(ts, now)
}

func (rl *RateLimiter) pruneAll(now time.Time, win time.Duration) {
	cutoff := now.Add(-win)
	for k, ts := range rl.buckets {
		ts = pruneSlice(ts, cutoff)
		if len(ts) == 0 {
			delete(rl.buckets, k)
		} else {
			rl.buckets[k] = ts
		}
	}
	// If still at capacity under a flood of distinct keys, shed entries to cap RAM.
	for k := range rl.buckets {
		if len(rl.buckets) < maxTrackedBuckets {
			break
		}
		delete(rl.buckets, k)
	}
}

func pruneSlice(ts []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for i < len(ts) && !ts[i].After(cutoff) {
		i++
	}
	if i == 0 {
		return ts
	}
	return append([]time.Time(nil), ts[i:]...)
}
