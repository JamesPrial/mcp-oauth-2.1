// Package jwks provides JWKS (JSON Web Key Set) client functionality
// for fetching and caching public keys from authorization servers.
// This test file tests the JWKS cache functionality.
package jwks

import (
	"crypto/rand"
	"crypto/rsa"
	"sync"
	"testing"
	"time"
)

func TestCache_SetAndGet(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	tests := []struct {
		name    string
		keyID   string
		key     any
		ttl     time.Duration
		wantNil bool
	}{
		{
			name:    "set and get key",
			keyID:   "key1",
			key:     &privateKey.PublicKey,
			ttl:     1 * time.Hour,
			wantNil: false,
		},
		{
			name:    "get non-existent key",
			keyID:   "nonexistent",
			key:     nil,
			ttl:     0,
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cache := NewCache(tt.ttl)

			if tt.key != nil {
				cache.Set(tt.keyID, tt.key)
			}

			got := cache.Get(tt.keyID)

			if tt.wantNil {
				if got != nil {
					t.Errorf("Get(%q) = %v, want nil", tt.keyID, got)
				}
			} else {
				if got == nil {
					t.Errorf("Get(%q) = nil, want non-nil", tt.keyID)
				}
			}
		})
	}
}

func TestCache_ExpiredEntry(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create cache with very short TTL
	cache := NewCache(10 * time.Millisecond)

	// Set key
	cache.Set("key1", &privateKey.PublicKey)

	// Verify key is present initially
	got := cache.Get("key1")
	if got == nil {
		t.Fatal("Get() immediately after Set() returned nil")
	}

	// Wait for expiration
	time.Sleep(20 * time.Millisecond)

	// Verify key has expired
	got = cache.Get("key1")
	if got != nil {
		t.Error("Get() after TTL expiration should return nil")
	}
}

func TestCache_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	cache := NewCache(1 * time.Hour)
	const numGoroutines = 100
	const numOperations = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines * 2) // readers and writers

	// Start writers
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				keyID := "key" + string(rune('0'+id%10))
				cache.Set(keyID, &privateKey.PublicKey)
			}
		}(i)
	}

	// Start readers
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				keyID := "key" + string(rune('0'+id%10))
				_ = cache.Get(keyID)
			}
		}(i)
	}

	// Wait for all goroutines to complete
	wg.Wait()

	// If we get here without a race condition panic, the test passes
}

func TestCache_Delete(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	cache := NewCache(1 * time.Hour)

	// Set a key
	cache.Set("key1", &privateKey.PublicKey)

	// Verify it exists
	if got := cache.Get("key1"); got == nil {
		t.Fatal("Get() after Set() returned nil")
	}

	// Delete the key
	cache.Delete("key1")

	// Verify it's gone
	if got := cache.Get("key1"); got != nil {
		t.Error("Get() after Delete() should return nil")
	}
}

func TestCache_Delete_NonExistent(t *testing.T) {
	t.Parallel()

	cache := NewCache(1 * time.Hour)

	// Delete a non-existent key should not panic
	cache.Delete("nonexistent")

	// Verify cache is still functional
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	cache.Set("key1", &privateKey.PublicKey)
	if got := cache.Get("key1"); got == nil {
		t.Error("Cache should still work after deleting non-existent key")
	}
}

func TestCache_Clear(t *testing.T) {
	t.Parallel()

	privateKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key 1: %v", err)
	}
	privateKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key 2: %v", err)
	}

	cache := NewCache(1 * time.Hour)

	// Add multiple keys
	cache.Set("key1", &privateKey1.PublicKey)
	cache.Set("key2", &privateKey2.PublicKey)

	// Verify keys exist
	if cache.Size() != 2 {
		t.Fatalf("Cache size = %d, want 2", cache.Size())
	}

	// Clear the cache
	cache.Clear()

	// Verify all keys are gone
	if cache.Size() != 0 {
		t.Errorf("Cache size after Clear() = %d, want 0", cache.Size())
	}
	if got := cache.Get("key1"); got != nil {
		t.Error("Get(key1) after Clear() should return nil")
	}
	if got := cache.Get("key2"); got != nil {
		t.Error("Get(key2) after Clear() should return nil")
	}
}

func TestCache_Size(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	tests := []struct {
		name     string
		setup    func(*Cache)
		wantSize int
	}{
		{
			name:     "empty cache",
			setup:    func(c *Cache) {},
			wantSize: 0,
		},
		{
			name: "one entry",
			setup: func(c *Cache) {
				c.Set("key1", &privateKey.PublicKey)
			},
			wantSize: 1,
		},
		{
			name: "multiple entries",
			setup: func(c *Cache) {
				c.Set("key1", &privateKey.PublicKey)
				c.Set("key2", &privateKey.PublicKey)
				c.Set("key3", &privateKey.PublicKey)
			},
			wantSize: 3,
		},
		{
			name: "after delete",
			setup: func(c *Cache) {
				c.Set("key1", &privateKey.PublicKey)
				c.Set("key2", &privateKey.PublicKey)
				c.Delete("key1")
			},
			wantSize: 1,
		},
		{
			name: "overwrite same key",
			setup: func(c *Cache) {
				c.Set("key1", &privateKey.PublicKey)
				c.Set("key1", &privateKey.PublicKey) // Overwrite
			},
			wantSize: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cache := NewCache(1 * time.Hour)
			tt.setup(cache)

			if got := cache.Size(); got != tt.wantSize {
				t.Errorf("Size() = %d, want %d", got, tt.wantSize)
			}
		})
	}
}

func TestCache_Overwrite(t *testing.T) {
	t.Parallel()

	privateKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key 1: %v", err)
	}
	privateKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key 2: %v", err)
	}

	cache := NewCache(1 * time.Hour)

	// Set initial key
	cache.Set("key1", &privateKey1.PublicKey)

	// Overwrite with new key
	cache.Set("key1", &privateKey2.PublicKey)

	// Verify we get the new key
	got := cache.Get("key1")
	if got == nil {
		t.Fatal("Get() after overwrite returned nil")
	}

	rsaKey, ok := got.(*rsa.PublicKey)
	if !ok {
		t.Fatal("Get() did not return *rsa.PublicKey")
	}

	if rsaKey.N.Cmp(privateKey2.N) != 0 {
		t.Error("Get() returned old key instead of new key after overwrite")
	}
}

func TestCache_EmptyKeyID(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	cache := NewCache(1 * time.Hour)

	// Setting and getting with empty key ID should still work
	// (it's the implementation's job to validate if needed)
	cache.Set("", &privateKey.PublicKey)

	got := cache.Get("")
	if got == nil {
		t.Error("Get(\"\") after Set(\"\", ...) should return the key")
	}
}

func TestCache_ZeroTTL(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create cache with zero TTL - entries should expire immediately
	cache := NewCache(0)

	cache.Set("key1", &privateKey.PublicKey)

	// Even a tiny delay should make it expired
	time.Sleep(1 * time.Millisecond)

	got := cache.Get("key1")
	if got != nil {
		t.Error("Get() with zero TTL should return nil after any delay")
	}
}

func TestCache_NegativeTTL(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create cache with negative TTL - entries should be immediately expired
	cache := NewCache(-1 * time.Hour)

	cache.Set("key1", &privateKey.PublicKey)

	got := cache.Get("key1")
	if got != nil {
		t.Error("Get() with negative TTL should return nil immediately")
	}
}

func TestCache_Cleanup(t *testing.T) {
	t.Parallel()

	privateKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key 1: %v", err)
	}
	privateKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key 2: %v", err)
	}

	// Create cache with short TTL
	cache := NewCache(100 * time.Millisecond)

	// Set first key
	cache.Set("key1", &privateKey1.PublicKey)

	// Wait a bit
	time.Sleep(50 * time.Millisecond)

	// Set second key (will expire later than first)
	cache.Set("key2", &privateKey2.PublicKey)

	// Wait for first key to expire
	time.Sleep(60 * time.Millisecond)

	// At this point, key1 has expired but key2 has not
	// Size should still be 2 because expired entries aren't automatically removed
	if cache.Size() != 2 {
		t.Errorf("Size() before Cleanup() = %d, want 2", cache.Size())
	}

	// Run cleanup
	cache.Cleanup()

	// After cleanup, only non-expired entries should remain
	if cache.Size() != 1 {
		t.Errorf("Size() after Cleanup() = %d, want 1", cache.Size())
	}

	// Verify key1 is gone
	if got := cache.Get("key1"); got != nil {
		t.Error("Get(key1) should return nil after Cleanup()")
	}

	// Verify key2 is still there
	if got := cache.Get("key2"); got == nil {
		t.Error("Get(key2) should not return nil after Cleanup()")
	}
}

func TestCache_Cleanup_EmptyCache(t *testing.T) {
	t.Parallel()

	cache := NewCache(1 * time.Hour)

	// Cleanup on empty cache should not panic
	cache.Cleanup()

	if cache.Size() != 0 {
		t.Errorf("Size() after Cleanup() on empty cache = %d, want 0", cache.Size())
	}
}

func TestCache_Cleanup_AllExpired(t *testing.T) {
	t.Parallel()

	privateKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key 1: %v", err)
	}
	privateKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key 2: %v", err)
	}

	// Create cache with short TTL
	cache := NewCache(10 * time.Millisecond)

	// Set multiple keys
	cache.Set("key1", &privateKey1.PublicKey)
	cache.Set("key2", &privateKey2.PublicKey)

	// Wait for all to expire
	time.Sleep(20 * time.Millisecond)

	// Run cleanup
	cache.Cleanup()

	// All entries should be removed
	if cache.Size() != 0 {
		t.Errorf("Size() after Cleanup() with all expired = %d, want 0", cache.Size())
	}
}

func TestCache_Cleanup_NoneExpired(t *testing.T) {
	t.Parallel()

	privateKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key 1: %v", err)
	}
	privateKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key 2: %v", err)
	}

	// Create cache with long TTL
	cache := NewCache(1 * time.Hour)

	// Set multiple keys
	cache.Set("key1", &privateKey1.PublicKey)
	cache.Set("key2", &privateKey2.PublicKey)

	// Run cleanup immediately
	cache.Cleanup()

	// No entries should be removed
	if cache.Size() != 2 {
		t.Errorf("Size() after Cleanup() with none expired = %d, want 2", cache.Size())
	}
}

// Benchmark tests for cache operations
func BenchmarkCache_Get(b *testing.B) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	cache := NewCache(1 * time.Hour)
	cache.Set("key1", &privateKey.PublicKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cache.Get("key1")
	}
}

func BenchmarkCache_Set(b *testing.B) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	cache := NewCache(1 * time.Hour)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Set("key1", &privateKey.PublicKey)
	}
}

func BenchmarkCache_ConcurrentReadWrite(b *testing.B) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	cache := NewCache(1 * time.Hour)
	cache.Set("key1", &privateKey.PublicKey)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			cache.Set("key1", &privateKey.PublicKey)
			_ = cache.Get("key1")
		}
	})
}
