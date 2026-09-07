// Package ratelimit provides a fixed-window request counter shared by the HTTP
// middleware and the password-reset service.
package ratelimit

import (
	"sync"
	"time"
)

type counter struct {
	count     int
	windowEnd time.Time
}

// Limiter allows up to limit events per key within each window. State is
// in-memory and per-process: a multi-instance deployment limits per instance,
// so treat it as a brake on abuse rather than a hard quota.
type Limiter struct {
	mu        sync.Mutex
	limit     int
	window    time.Duration
	counters  map[string]*counter
	lastSweep time.Time
}

func New(limit int, window time.Duration) *Limiter {
	return &Limiter{
		limit:     limit,
		window:    window,
		counters:  make(map[string]*counter),
		lastSweep: time.Now(),
	}
}

// Allow reports whether the event is within the allowance for key, counting it
// when it is. A limit of zero or less disables limiting.
func (l *Limiter) Allow(key string) bool {
	if l == nil || l.limit <= 0 {
		return true
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	l.sweep(now)

	c, ok := l.counters[key]
	if !ok || now.After(c.windowEnd) {
		l.counters[key] = &counter{count: 1, windowEnd: now.Add(l.window)}
		return true
	}

	if c.count >= l.limit {
		return false
	}

	c.count++

	return true
}

// sweep drops expired counters. Without it the map would grow with every
// distinct key seen, which an attacker controls by varying source addresses.
// The caller must hold l.mu.
func (l *Limiter) sweep(now time.Time) {
	if now.Sub(l.lastSweep) < l.window {
		return
	}

	for key, c := range l.counters {
		if now.After(c.windowEnd) {
			delete(l.counters, key)
		}
	}

	l.lastSweep = now
}
