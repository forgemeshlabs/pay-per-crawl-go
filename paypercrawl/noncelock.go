package paypercrawl

import (
	"sync"
	"time"
)

// NonceLock stops one authorization from being presented twice (and so settled twice) while
// a first attempt is in flight or has just succeeded. Implement it over Redis, a database or
// a shared cache to span several instances; MemoryLock covers a single process.
type NonceLock interface {
	// Acquire returns true if the key was free and is now held for ttl, false if already held.
	Acquire(key string, ttl time.Duration) bool
	// Release frees the key (used when the facilitator was unreachable so the client can retry).
	Release(key string)
}

// MemoryLock is an in-process NonceLock.
type MemoryLock struct {
	mu  sync.Mutex
	m   map[string]time.Time
	now func() time.Time
}

// NewMemoryLock returns an empty in-memory lock.
func NewMemoryLock() *MemoryLock { return &MemoryLock{m: map[string]time.Time{}, now: time.Now} }

// Acquire implements NonceLock.
func (l *MemoryLock) Acquire(key string, ttl time.Duration) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if exp, ok := l.m[key]; ok && now.Before(exp) {
		return false
	}
	if len(l.m) > 10000 { // sweep expired entries
		for k, e := range l.m {
			if !now.Before(e) {
				delete(l.m, k)
			}
		}
	}
	l.m[key] = now.Add(ttl)
	return true
}

// Release implements NonceLock.
func (l *MemoryLock) Release(key string) {
	l.mu.Lock()
	delete(l.m, key)
	l.mu.Unlock()
}
