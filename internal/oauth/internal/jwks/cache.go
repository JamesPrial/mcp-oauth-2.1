package jwks

import (
	"sync"
	"time"
)

// cacheEntry represents a cached JWKS key with expiration.
type cacheEntry struct {
	key       any
	expiresAt time.Time
}

// Cache provides an in-memory cache for JWKS keys with TTL.
// It is safe for concurrent use by multiple goroutines.
type Cache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
	ttl     time.Duration
}

// NewCache creates a new JWKS cache with the specified TTL.
func NewCache(ttl time.Duration) *Cache {
	return &Cache{
		entries: make(map[string]*cacheEntry),
		ttl:     ttl,
	}
}

// Get retrieves a key from the cache by key ID.
// Returns nil if the key is not found or has expired.
func (c *Cache) Get(keyID string) any {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[keyID]
	if !ok {
		return nil
	}

	// Check if expired
	if time.Now().After(entry.expiresAt) {
		return nil
	}

	return entry.key
}

// Set stores a key in the cache with the configured TTL.
func (c *Cache) Set(keyID string, key any) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[keyID] = &cacheEntry{
		key:       key,
		expiresAt: time.Now().Add(c.ttl),
	}
}

// Delete removes a key from the cache.
func (c *Cache) Delete(keyID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.entries, keyID)
}

// Clear removes all keys from the cache.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[string]*cacheEntry)
}

// Cleanup removes all expired entries from the cache.
// This method should be called periodically to prevent memory leaks.
func (c *Cache) Cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for keyID, entry := range c.entries {
		if now.After(entry.expiresAt) {
			delete(c.entries, keyID)
		}
	}
}

// Size returns the number of entries currently in the cache.
// Note: This includes expired entries that haven't been cleaned up yet.
func (c *Cache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.entries)
}
