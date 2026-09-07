package ratelimit

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLimiterAllowsUpToLimit(t *testing.T) {
	limiter := New(3, time.Minute)

	for i := range 3 {
		assert.True(t, limiter.Allow("key"), "request %d should be allowed", i+1)
	}

	assert.False(t, limiter.Allow("key"))
}

func TestLimiterKeysAreIndependent(t *testing.T) {
	limiter := New(1, time.Minute)

	assert.True(t, limiter.Allow("first"))
	assert.False(t, limiter.Allow("first"))
	assert.True(t, limiter.Allow("second"))
}

func TestLimiterResetsAfterWindow(t *testing.T) {
	limiter := New(1, 20*time.Millisecond)

	assert.True(t, limiter.Allow("key"))
	assert.False(t, limiter.Allow("key"))

	time.Sleep(30 * time.Millisecond)
	assert.True(t, limiter.Allow("key"))
}

// Expired entries must not accumulate: keys are attacker-controlled.
func TestLimiterSweepsExpiredCounters(t *testing.T) {
	limiter := New(1, 10*time.Millisecond)

	limiter.Allow("first")
	time.Sleep(20 * time.Millisecond)
	limiter.Allow("second")

	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	assert.NotContains(t, limiter.counters, "first")
}

func TestLimiterZeroLimitDisablesLimiting(t *testing.T) {
	limiter := New(0, time.Minute)

	for range 100 {
		assert.True(t, limiter.Allow("key"))
	}
}

func TestLimiterNilIsPermissive(t *testing.T) {
	var limiter *Limiter
	assert.True(t, limiter.Allow("key"))
}

func TestLimiterIsSafeForConcurrentUse(t *testing.T) {
	limiter := New(50, time.Minute)

	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0

	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if limiter.Allow("shared") {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, 50, allowed)
}
