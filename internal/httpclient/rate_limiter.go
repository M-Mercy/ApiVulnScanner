package httpclient

import (
	"context"
	"sync"
	"time"
)

// RateLimiter implements a simple token bucket algorithm.
//
// Why a token bucket instead of a fixed delay?
// A fixed delay of 100ms gives exactly 10 req/s but is rigid.
// A token bucket allows short bursts (consuming pre-accumulated tokens)
// while enforcing the average rate over time. This is more realistic
// to how real users and rate limit policies work.
//
// For a security scanner, we actually want the OPPOSITE of a burst —
// we want steady, predictable traffic that doesn't spike.
// So we initialize the bucket with capacity=1 (no burst) and a slow refill.
type RateLimiter struct {
	tokens     float64
	maxTokens  float64
	refillRate float64 // tokens per second
	lastRefill time.Time
	mu         sync.Mutex
}

// NewRateLimiter creates a rate limiter allowing rps requests per second.
// With capacity=1, there is no burst — requests are metered evenly.
func NewRateLimiter(rps int) *RateLimiter {
	if rps <= 0 {
		rps = 1
	}
	return &RateLimiter{
		tokens:     float64(rps),  // Start full
		maxTokens:  float64(rps),
		refillRate: float64(rps),
		lastRefill: time.Now(),
	}
}

// Wait blocks until a token is available or the context is cancelled.
// Returns an error only if the context is cancelled.
func (r *RateLimiter) Wait(ctx context.Context) error {
	for {
		r.mu.Lock()
		r.refill()

		if r.tokens >= 1.0 {
			r.tokens -= 1.0
			r.mu.Unlock()
			return nil
		}

		// Calculate wait time until next token is available
		waitTime := time.Duration((1.0-r.tokens)/r.refillRate*1000) * time.Millisecond
		r.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(waitTime):
			// Try again after wait
		}
	}
}

// refill adds tokens based on time elapsed since last refill.
// Must be called with r.mu held.
func (r *RateLimiter) refill() {
	now := time.Now()
	elapsed := now.Sub(r.lastRefill).Seconds()
	r.tokens = min(r.maxTokens, r.tokens+elapsed*r.refillRate)
	r.lastRefill = now
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
