package jwks

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClient_GetKey_Integration(t *testing.T) {
	t.Parallel()

	// Generate test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create mock authorization server
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			metadata := AuthorizationServerMetadata{
				Issuer:  "https://auth.example.com",
				JWKSURI: server.URL + "/jwks",
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(metadata); err != nil {
				t.Errorf("failed to encode metadata: %v", err)
			}

		case "/jwks":
			jwks := JWKS{
				Keys: []JWK{
					{
						KeyType:   "RSA",
						Use:       "sig",
						KeyID:     "test-key-1",
						Algorithm: "RS256",
						N:         encodeBase64URL(privateKey.N.Bytes()),
						E:         encodeBase64URL([]byte{1, 0, 1}), // 65537
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(jwks); err != nil {
				t.Errorf("failed to encode jwks: %v", err)
			}

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewClient([]string{server.URL}, 5*time.Minute)

	key, err := client.GetKey(context.Background(), "test-key-1")
	if err != nil {
		t.Fatalf("GetKey() unexpected error: %v", err)
	}

	if key == nil {
		t.Fatal("GetKey() returned nil key")
	}

	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("GetKey() returned wrong key type: %T", key)
	}

	if rsaKey.N.Cmp(privateKey.N) != 0 {
		t.Error("GetKey() returned key with wrong modulus")
	}
}

func TestClient_GetKey_KeyNotFound(t *testing.T) {
	t.Parallel()

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			metadata := AuthorizationServerMetadata{
				Issuer:  "https://auth.example.com",
				JWKSURI: server.URL + "/jwks",
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(metadata); err != nil {
				t.Errorf("failed to encode metadata: %v", err)
			}

		case "/jwks":
			jwks := JWKS{
				Keys: []JWK{},
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(jwks); err != nil {
				t.Errorf("failed to encode jwks: %v", err)
			}

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewClient([]string{server.URL}, 5*time.Minute)

	_, err := client.GetKey(context.Background(), "nonexistent-key")
	if err == nil {
		t.Fatal("GetKey() expected error for nonexistent key, got nil")
	}

	if !strings.Contains(strings.ToLower(err.Error()), "not found") {
		t.Errorf("GetKey() error = %q, want error containing 'not found'", err.Error())
	}
}

func TestClient_GetKey_Cache(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	requestCount := 0
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			requestCount++
			metadata := AuthorizationServerMetadata{
				Issuer:  "https://auth.example.com",
				JWKSURI: server.URL + "/jwks",
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(metadata); err != nil {
				t.Errorf("failed to encode metadata: %v", err)
			}

		case "/jwks":
			requestCount++
			jwks := JWKS{
				Keys: []JWK{
					{
						KeyType:   "RSA",
						Use:       "sig",
						KeyID:     "test-key-1",
						Algorithm: "RS256",
						N:         encodeBase64URL(privateKey.N.Bytes()),
						E:         encodeBase64URL([]byte{1, 0, 1}),
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(jwks); err != nil {
				t.Errorf("failed to encode jwks: %v", err)
			}

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewClient([]string{server.URL}, 5*time.Minute)

	// First call should fetch from server
	_, err = client.GetKey(context.Background(), "test-key-1")
	if err != nil {
		t.Fatalf("GetKey() unexpected error: %v", err)
	}

	firstRequestCount := requestCount

	// Second call should use cache
	_, err = client.GetKey(context.Background(), "test-key-1")
	if err != nil {
		t.Fatalf("GetKey() unexpected error: %v", err)
	}

	if requestCount != firstRequestCount {
		t.Errorf("GetKey() made additional requests when cache should be used. Requests: %d", requestCount)
	}
}

func TestClient_RefreshKeys(t *testing.T) {
	t.Parallel()

	privateKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key 1: %v", err)
	}

	privateKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key 2: %v", err)
	}

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			metadata := AuthorizationServerMetadata{
				Issuer:  "https://auth.example.com",
				JWKSURI: server.URL + "/jwks",
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(metadata); err != nil {
				t.Errorf("failed to encode metadata: %v", err)
			}

		case "/jwks":
			jwks := JWKS{
				Keys: []JWK{
					{
						KeyType:   "RSA",
						Use:       "sig",
						KeyID:     "test-key-1",
						Algorithm: "RS256",
						N:         encodeBase64URL(privateKey1.N.Bytes()),
						E:         encodeBase64URL([]byte{1, 0, 1}),
					},
					{
						KeyType:   "RSA",
						Use:       "sig",
						KeyID:     "test-key-2",
						Algorithm: "RS256",
						N:         encodeBase64URL(privateKey2.N.Bytes()),
						E:         encodeBase64URL([]byte{1, 0, 1}),
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(jwks); err != nil {
				t.Errorf("failed to encode jwks: %v", err)
			}

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewClient([]string{server.URL}, 5*time.Minute)

	// Refresh keys
	err = client.RefreshKeys(context.Background())
	if err != nil {
		t.Fatalf("RefreshKeys() unexpected error: %v", err)
	}

	// Both keys should now be available in cache
	key1, err := client.GetKey(context.Background(), "test-key-1")
	if err != nil {
		t.Fatalf("GetKey(test-key-1) unexpected error: %v", err)
	}

	if key1 == nil {
		t.Fatal("GetKey(test-key-1) returned nil")
	}

	key2, err := client.GetKey(context.Background(), "test-key-2")
	if err != nil {
		t.Fatalf("GetKey(test-key-2) unexpected error: %v", err)
	}

	if key2 == nil {
		t.Fatal("GetKey(test-key-2) returned nil")
	}
}

func TestClient_GetKey_ServerError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient([]string{server.URL}, 5*time.Minute)

	_, err := client.GetKey(context.Background(), "test-key-1")
	if err == nil {
		t.Fatal("GetKey() expected error for server error, got nil")
	}
}

func TestClient_GetKey_InvalidMetadata(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"invalid": "json`)) // Malformed JSON

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewClient([]string{server.URL}, 5*time.Minute)

	_, err := client.GetKey(context.Background(), "test-key-1")
	if err == nil {
		t.Fatal("GetKey() expected error for invalid metadata, got nil")
	}
}

func TestClient_GetKey_MissingJWKSURI(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			metadata := AuthorizationServerMetadata{
				Issuer: "https://auth.example.com",
				// Missing JWKSURI
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(metadata); err != nil {
				t.Errorf("failed to encode metadata: %v", err)
			}

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewClient([]string{server.URL}, 5*time.Minute)

	_, err := client.GetKey(context.Background(), "test-key-1")
	if err == nil {
		t.Fatal("GetKey() expected error for missing jwks_uri, got nil")
	}

	if !strings.Contains(err.Error(), "jwks_uri") {
		t.Errorf("GetKey() error = %q, want error containing 'jwks_uri'", err.Error())
	}
}

func TestClient_GetKey_MultipleServers(t *testing.T) {
	t.Parallel()

	privateKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key 1: %v", err)
	}

	privateKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key 2: %v", err)
	}

	// Server 1 has key1
	var server1 *httptest.Server
	server1 = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			metadata := AuthorizationServerMetadata{
				Issuer:  "https://auth1.example.com",
				JWKSURI: server1.URL + "/jwks",
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(metadata); err != nil {
				t.Errorf("failed to encode metadata: %v", err)
			}

		case "/jwks":
			jwks := JWKS{
				Keys: []JWK{
					{
						KeyType:   "RSA",
						KeyID:     "test-key-1",
						Algorithm: "RS256",
						N:         encodeBase64URL(privateKey1.N.Bytes()),
						E:         encodeBase64URL([]byte{1, 0, 1}),
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(jwks); err != nil {
				t.Errorf("failed to encode jwks: %v", err)
			}

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server1.Close()

	// Server 2 has key2
	var server2 *httptest.Server
	server2 = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			metadata := AuthorizationServerMetadata{
				Issuer:  "https://auth2.example.com",
				JWKSURI: server2.URL + "/jwks",
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(metadata); err != nil {
				t.Errorf("failed to encode metadata: %v", err)
			}

		case "/jwks":
			jwks := JWKS{
				Keys: []JWK{
					{
						KeyType:   "RSA",
						KeyID:     "test-key-2",
						Algorithm: "RS256",
						N:         encodeBase64URL(privateKey2.N.Bytes()),
						E:         encodeBase64URL([]byte{1, 0, 1}),
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(jwks); err != nil {
				t.Errorf("failed to encode jwks: %v", err)
			}

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server2.Close()

	client := NewClient([]string{server1.URL, server2.URL}, 5*time.Minute)

	// Should find key1 from server1
	key1, err := client.GetKey(context.Background(), "test-key-1")
	if err != nil {
		t.Fatalf("GetKey(test-key-1) unexpected error: %v", err)
	}
	if key1 == nil {
		t.Fatal("GetKey(test-key-1) returned nil")
	}

	// Should find key2 from server2
	key2, err := client.GetKey(context.Background(), "test-key-2")
	if err != nil {
		t.Fatalf("GetKey(test-key-2) unexpected error: %v", err)
	}
	if key2 == nil {
		t.Fatal("GetKey(test-key-2) returned nil")
	}
}

func TestClient_GetKey_JWKSURICache(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	metadataRequestCount := 0
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			metadataRequestCount++
			metadata := AuthorizationServerMetadata{
				Issuer:  "https://auth.example.com",
				JWKSURI: server.URL + "/jwks",
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(metadata); err != nil {
				t.Errorf("failed to encode metadata: %v", err)
			}

		case "/jwks":
			jwks := JWKS{
				Keys: []JWK{
					{
						KeyType:   "RSA",
						KeyID:     "test-key-1",
						Algorithm: "RS256",
						N:         encodeBase64URL(privateKey.N.Bytes()),
						E:         encodeBase64URL([]byte{1, 0, 1}),
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(jwks); err != nil {
				t.Errorf("failed to encode jwks: %v", err)
			}

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewClient([]string{server.URL}, 5*time.Minute)

	// First GetKey should fetch metadata
	_, err = client.GetKey(context.Background(), "test-key-1")
	if err != nil {
		t.Fatalf("GetKey() unexpected error: %v", err)
	}

	if metadataRequestCount != 1 {
		t.Errorf("First GetKey() metadata requests = %d, want 1", metadataRequestCount)
	}

	// Clear key cache but keep JWKS URI cache
	client.cache.Clear()

	// Second GetKey should not fetch metadata again (JWKS URI is cached)
	_, err = client.GetKey(context.Background(), "test-key-1")
	if err != nil {
		t.Fatalf("GetKey() unexpected error: %v", err)
	}

	if metadataRequestCount != 1 {
		t.Errorf("Second GetKey() metadata requests = %d, want 1 (should use cached JWKS URI)", metadataRequestCount)
	}
}

func TestClient_NewClient(t *testing.T) {
	t.Parallel()

	serverURLs := []string{"https://auth1.example.com", "https://auth2.example.com"}
	cacheTTL := 10 * time.Minute

	client := NewClient(serverURLs, cacheTTL)

	if client == nil {
		t.Fatal("NewClient() returned nil")
	}

	if len(client.serverURLs) != len(serverURLs) {
		t.Errorf("client.serverURLs length = %d, want %d", len(client.serverURLs), len(serverURLs))
	}

	if client.cacheTTL != cacheTTL {
		t.Errorf("client.cacheTTL = %v, want %v", client.cacheTTL, cacheTTL)
	}

	if client.cache == nil {
		t.Error("client.cache should not be nil")
	}

	if client.httpClient == nil {
		t.Error("client.httpClient should not be nil")
	}
}

func TestClient_RefreshKeys_ClearsCache(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			metadata := AuthorizationServerMetadata{
				Issuer:  "https://auth.example.com",
				JWKSURI: server.URL + "/jwks",
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(metadata); err != nil {
				t.Errorf("failed to encode metadata: %v", err)
			}

		case "/jwks":
			jwks := JWKS{
				Keys: []JWK{
					{
						KeyType:   "RSA",
						KeyID:     "test-key-1",
						Algorithm: "RS256",
						N:         encodeBase64URL(privateKey.N.Bytes()),
						E:         encodeBase64URL([]byte{1, 0, 1}),
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(jwks); err != nil {
				t.Errorf("failed to encode jwks: %v", err)
			}

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewClient([]string{server.URL}, 5*time.Minute)

	// Populate cache
	_, err = client.GetKey(context.Background(), "test-key-1")
	if err != nil {
		t.Fatalf("GetKey() unexpected error: %v", err)
	}

	// Verify key is in cache
	cachedKey := client.cache.Get("test-key-1")
	if cachedKey == nil {
		t.Fatal("Key should be in cache after GetKey()")
	}

	// Refresh should clear cache
	err = client.RefreshKeys(context.Background())
	if err != nil {
		t.Fatalf("RefreshKeys() unexpected error: %v", err)
	}

	// Verify key is still available (refreshed from server)
	refreshedKey, err := client.GetKey(context.Background(), "test-key-1")
	if err != nil {
		t.Fatalf("GetKey() after refresh unexpected error: %v", err)
	}

	if refreshedKey == nil {
		t.Fatal("GetKey() after refresh returned nil")
	}
}

func BenchmarkClient_GetKey_Integration(b *testing.B) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			metadata := AuthorizationServerMetadata{
				Issuer:  "https://auth.example.com",
				JWKSURI: server.URL + "/jwks",
			}
			if err := json.NewEncoder(w).Encode(metadata); err != nil {
				b.Errorf("failed to encode metadata: %v", err)
			}

		case "/jwks":
			jwks := JWKS{
				Keys: []JWK{
					{
						KeyType:   "RSA",
						KeyID:     "test-key-1",
						Algorithm: "RS256",
						N:         encodeBase64URL(privateKey.N.Bytes()),
						E:         encodeBase64URL([]byte{1, 0, 1}),
					},
				},
			}
			if err := json.NewEncoder(w).Encode(jwks); err != nil {
				b.Errorf("failed to encode jwks: %v", err)
			}
		}
	}))
	defer server.Close()

	client := NewClient([]string{server.URL}, 5*time.Minute)
	ctx := context.Background()

	// Warm up cache
	_, _ = client.GetKey(ctx, "test-key-1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = client.GetKey(ctx, "test-key-1")
	}
}

// Helper to encode bytes as base64url
func encodeBase64URL(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}
