package server

import (
	"sync"
	"time"
)

// ReplayCache rejects salts that have been seen within the TTL window.
type ReplayCache struct {
	mu          sync.Mutex
	seen        map[string]time.Time
	ttl         time.Duration
	lastCleanup time.Time
}

func NewReplayCache(ttl time.Duration) *ReplayCache {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &ReplayCache{
		seen:        make(map[string]time.Time),
		ttl:         ttl,
		lastCleanup: time.Now(),
	}
}

// Add records salt and reports whether it is new. It returns false when the
// salt was already seen within the TTL window.
func (c *ReplayCache) Add(salt []byte) bool {
	key := string(salt)
	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	if seenAt, ok := c.seen[key]; ok && now.Sub(seenAt) < c.ttl {
		return false
	}
	c.seen[key] = now

	if now.Sub(c.lastCleanup) >= c.ttl {
		for k, t := range c.seen {
			if now.Sub(t) >= c.ttl {
				delete(c.seen, k)
			}
		}
		c.lastCleanup = now
	}
	return true
}

func (c *ReplayCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.seen)
}
