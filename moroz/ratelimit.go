package moroz

import (
	"context"
	"sync"
	"time"
)

// semaphoreWait bounds how long a request waits for a decode slot before it
// is told to retry.
const semaphoreWait = 5 * time.Second

// RateLimiter combines a per-machine token bucket with a global bound on
// concurrently handled request bodies. Santa performs three to four requests
// per full sync, so a small burst with a slow refill covers normal clients.
type RateLimiter struct {
	mu      sync.Mutex
	burst   float64
	refill  time.Duration // time to earn one token
	buckets map[string]*bucket
	sem     chan struct{}
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewRateLimiter allows burst requests per machine, refilling one every
// refill, and at most concurrency requests in flight. A burst below one
// disables the per-machine limit; a concurrency below one disables the bound.
func NewRateLimiter(burst int, refill time.Duration, concurrency int) *RateLimiter {
	l := &RateLimiter{burst: float64(burst), refill: refill, buckets: make(map[string]*bucket)}
	if refill <= 0 {
		l.refill = time.Second
	}
	if concurrency > 0 {
		l.sem = make(chan struct{}, concurrency)
	}
	return l
}

// Allow reports whether the machine may proceed at now and, if not, how long
// until its next token.
func (l *RateLimiter) Allow(id string, now time.Time) (bool, time.Duration) {
	if l.burst < 1 {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[id]
	if !ok {
		if len(l.buckets) >= 4096 {
			l.pruneIdle(now)
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[id] = b
	}
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens += float64(elapsed) / float64(l.refill)
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	return false, time.Duration((1 - b.tokens) * float64(l.refill))
}

// pruneIdle drops buckets that have refilled completely; they are
// indistinguishable from a fresh bucket.
func (l *RateLimiter) pruneIdle(now time.Time) {
	for id, b := range l.buckets {
		if b.tokens+float64(now.Sub(b.last))/float64(l.refill) >= l.burst {
			delete(l.buckets, id)
		}
	}
}

// acquire takes a concurrency slot, waiting up to semaphoreWait.
func (l *RateLimiter) acquire(ctx context.Context) (release func(), ok bool) {
	if l.sem == nil {
		return func() {}, true
	}
	timer := time.NewTimer(semaphoreWait)
	defer timer.Stop()
	select {
	case l.sem <- struct{}{}:
		return func() { <-l.sem }, true
	case <-timer.C:
		return nil, false
	case <-ctx.Done():
		return nil, false
	}
}
