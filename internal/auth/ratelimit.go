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

// Allow checks whether an attempt from ip (optionally targeting username) is
// within the rate limit and atomically counts the attempt when permitted.
// Call RecordSuccess after authentication succeeds to clear the counted attempt.
// When denied, retryAfter is how long the caller must wait.
func (rl *RateLimiter) Allow(ip, username string) (bool, time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.now()
	win := rl.window()
	ipKey := "ip:" + ip
	if wait := rl.checkBucket(ipKey, rl.maxPerIP(), now, win); wait > 0 {
		return false, wait
	}
	u := strings.ToLower(strings.TrimSpace(username))
	userKey := ""
	if u != "" {
		userKey = "u:" + ip + "|" + u
		if wait := rl.checkBucket(userKey, rl.maxPerIPUser(), now, win); wait > 0 {
			return false, wait
		}
	}
	if len(rl.buckets) >= maxTrackedBuckets {
		rl.pruneAll(now, win)
	}
	rl.addEvent(ipKey, now, win)
	if userKey != "" {
		rl.addEvent(userKey, now, win)
	}
	return true, 0
}

// RecordSuccess clears the per-(IP, username) attempt history and releases the
// IP slot counted by Allow after a valid authentication.
func (rl *RateLimiter) RecordSuccess(ip, username string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if u := strings.ToLower(strings.TrimSpace(username)); u != "" {
		delete(rl.buckets, "u:"+ip+"|"+u)
	}
	ipKey := "ip:" + ip
	if ts := rl.buckets[ipKey]; len(ts) > 1 {
		rl.buckets[ipKey] = ts[:len(ts)-1]
	} else {
		delete(rl.buckets, ipKey)
	}
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
