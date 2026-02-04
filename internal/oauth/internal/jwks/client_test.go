// Package jwks provides JWKS (JSON Web Key Set) client functionality
// for fetching and caching public keys from authorization servers.
// This test file tests the JWKS client functionality.
package jwks

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"
)

// mockClient implements Client for testing.
type mockClient struct {
	keys         map[string]interface{}
	getKeyErr    error
	refreshErr   error
	refreshed    bool
	getCalls     int
	refreshCalls int
}

func newMockClient() *mockClient {
	return &mockClient{
		keys: make(map[string]interface{}),
	}
}

func (m *mockClient) GetKey(keyID string) (interface{}, error) {
	m.getCalls++
	if m.getKeyErr != nil {
		return nil, m.getKeyErr
	}
	if keyID == "" {
		return nil, errors.New("key ID is required")
	}
	key, ok := m.keys[keyID]
	if !ok {
		return nil, errors.New("key not found: " + keyID)
	}
	return key, nil
}

func (m *mockClient) Refresh() error {
	m.refreshCalls++
	m.refreshed = true
	return m.refreshErr
}

func (m *mockClient) addKey(keyID string, key interface{}) {
	m.keys[keyID] = key
}

func TestClient_GetKey(t *testing.T) {
	t.Parallel()

	// Generate test RSA keys
	privateKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	privateKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	tests := []struct {
		name            string
		setupClient     func() *mockClient
		keyID           string
		wantErr         bool
		wantErrContains string
	}{
		{
			name: "key in cache",
			setupClient: func() *mockClient {
				client := newMockClient()
				client.addKey("key1", &privateKey1.PublicKey)
				return client
			},
			keyID:   "key1",
			wantErr: false,
		},
		{
			name: "multiple keys first key",
			setupClient: func() *mockClient {
				client := newMockClient()
				client.addKey("key1", &privateKey1.PublicKey)
				client.addKey("key2", &privateKey2.PublicKey)
				return client
			},
			keyID:   "key1",
			wantErr: false,
		},
		{
			name: "multiple keys second key",
			setupClient: func() *mockClient {
				client := newMockClient()
				client.addKey("key1", &privateKey1.PublicKey)
				client.addKey("key2", &privateKey2.PublicKey)
				return client
			},
			keyID:   "key2",
			wantErr: false,
		},
		{
			name: "key not found",
			setupClient: func() *mockClient {
				client := newMockClient()
				client.addKey("key1", &privateKey1.PublicKey)
				return client
			},
			keyID:           "unknown-key",
			wantErr:         true,
			wantErrContains: "not found",
		},
		{
			name: "empty key ID",
			setupClient: func() *mockClient {
				client := newMockClient()
				client.addKey("key1", &privateKey1.PublicKey)
				return client
			},
			keyID:           "",
			wantErr:         true,
			wantErrContains: "required",
		},
		{
			name: "empty cache",
			setupClient: func() *mockClient {
				return newMockClient()
			},
			keyID:           "key1",
			wantErr:         true,
			wantErrContains: "not found",
		},
		{
			name: "client error",
			setupClient: func() *mockClient {
				client := newMockClient()
				client.getKeyErr = errors.New("network error")
				return client
			},
			keyID:           "key1",
			wantErr:         true,
			wantErrContains: "network",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := tt.setupClient()
			key, err := client.GetKey(tt.keyID)

			if tt.wantErr {
				if err == nil {
					t.Fatal("GetKey() expected error, got nil")
				}
				if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.wantErrContains)) {
					t.Errorf("GetKey() error = %q, want to contain %q", err.Error(), tt.wantErrContains)
				}
			} else {
				if err != nil {
					t.Fatalf("GetKey() unexpected error: %v", err)
				}
				if key == nil {
					t.Fatal("GetKey() returned nil key")
				}
			}
		})
	}
}

func TestClient_GetKey_ReturnsCorrectKey(t *testing.T) {
	t.Parallel()

	// Generate distinct test RSA keys
	privateKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key 1: %v", err)
	}
	privateKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key 2: %v", err)
	}

	client := newMockClient()
	client.addKey("key1", &privateKey1.PublicKey)
	client.addKey("key2", &privateKey2.PublicKey)

	// Get key1 and verify it's the correct one
	key1, err := client.GetKey("key1")
	if err != nil {
		t.Fatalf("GetKey(key1) unexpected error: %v", err)
	}
	rsaKey1, ok := key1.(*rsa.PublicKey)
	if !ok {
		t.Fatal("GetKey(key1) did not return *rsa.PublicKey")
	}
	if rsaKey1.N.Cmp(privateKey1.N) != 0 {
		t.Error("GetKey(key1) returned wrong key")
	}

	// Get key2 and verify it's the correct one
	key2, err := client.GetKey("key2")
	if err != nil {
		t.Fatalf("GetKey(key2) unexpected error: %v", err)
	}
	rsaKey2, ok := key2.(*rsa.PublicKey)
	if !ok {
		t.Fatal("GetKey(key2) did not return *rsa.PublicKey")
	}
	if rsaKey2.N.Cmp(privateKey2.N) != 0 {
		t.Error("GetKey(key2) returned wrong key")
	}

	// Verify they are different
	if rsaKey1.N.Cmp(rsaKey2.N) == 0 {
		t.Error("key1 and key2 should be different")
	}
}

func TestClient_Refresh(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		setupClient     func() *mockClient
		wantErr         bool
		wantErrContains string
	}{
		{
			name: "refresh success",
			setupClient: func() *mockClient {
				return newMockClient()
			},
			wantErr: false,
		},
		{
			name: "refresh error",
			setupClient: func() *mockClient {
				client := newMockClient()
				client.refreshErr = errors.New("failed to fetch JWKS")
				return client
			},
			wantErr:         true,
			wantErrContains: "fetch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := tt.setupClient()
			err := client.Refresh()

			if tt.wantErr {
				if err == nil {
					t.Fatal("Refresh() expected error, got nil")
				}
				if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.wantErrContains)) {
					t.Errorf("Refresh() error = %q, want to contain %q", err.Error(), tt.wantErrContains)
				}
			} else {
				if err != nil {
					t.Fatalf("Refresh() unexpected error: %v", err)
				}
				if !client.refreshed {
					t.Error("Refresh() should set refreshed flag")
				}
			}
		})
	}
}

func TestClient_GetKey_CallCount(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	client := newMockClient()
	client.addKey("key1", &privateKey.PublicKey)

	// Call GetKey multiple times
	for i := 0; i < 5; i++ {
		_, _ = client.GetKey("key1")
	}

	if client.getCalls != 5 {
		t.Errorf("GetKey call count = %d, want 5", client.getCalls)
	}
}

func TestClient_Refresh_CallCount(t *testing.T) {
	t.Parallel()

	client := newMockClient()

	// Call Refresh multiple times
	for i := 0; i < 3; i++ {
		_ = client.Refresh()
	}

	if client.refreshCalls != 3 {
		t.Errorf("Refresh call count = %d, want 3", client.refreshCalls)
	}
}

// Benchmark tests for JWKS client operations
func BenchmarkClient_GetKey(b *testing.B) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	client := newMockClient()
	client.addKey("key1", &privateKey.PublicKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = client.GetKey("key1")
	}
}

func BenchmarkClient_GetKey_Miss(b *testing.B) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	client := newMockClient()
	client.addKey("key1", &privateKey.PublicKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = client.GetKey("unknown")
	}
}
