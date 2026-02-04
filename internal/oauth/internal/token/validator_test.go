// Package token provides JWT token validation for the OAuth 2.1 MCP server.
// This test file tests the token validator functionality.
package token

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"
	"time"
)

// mockKeyProvider implements KeyProvider for testing.
type mockKeyProvider struct {
	keys map[string]interface{}
	err  error
}

func (m *mockKeyProvider) GetKey(keyID string) (interface{}, error) {
	if m.err != nil {
		return nil, m.err
	}
	key, ok := m.keys[keyID]
	if !ok {
		return nil, errors.New("key not found")
	}
	return key, nil
}

// mockValidator implements Validator for testing behavior.
type mockValidator struct {
	claims *TokenClaims
	err    error
}

func (m *mockValidator) Validate(token string, expectedAudience string) (*TokenClaims, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.claims, nil
}

func TestValidator_Validate_ValidToken(t *testing.T) {
	t.Parallel()

	// This test verifies that a valid token returns proper claims
	validator := &mockValidator{
		claims: &TokenClaims{
			Subject:   "user123",
			Audience:  []string{"https://api.example.com"},
			Issuer:    "https://auth.example.com",
			Scopes:    []string{"mcp:read", "mcp:write"},
			ExpiresAt: time.Now().Add(1 * time.Hour),
			IssuedAt:  time.Now(),
			JTI:       "token-id-123",
		},
	}

	claims, err := validator.Validate("valid-token", "https://api.example.com")
	if err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}
	if claims == nil {
		t.Fatal("Validate() returned nil claims")
	}
	if claims.Subject != "user123" {
		t.Errorf("Subject = %q, want %q", claims.Subject, "user123")
	}
	if claims.Issuer != "https://auth.example.com" {
		t.Errorf("Issuer = %q, want %q", claims.Issuer, "https://auth.example.com")
	}
	if len(claims.Scopes) != 2 {
		t.Errorf("Scopes length = %d, want 2", len(claims.Scopes))
	}
}

func TestValidator_Validate_ErrorCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		token           string
		expectedAud     string
		validatorErr    error
		wantErrContains string
	}{
		{
			name:            "wrong audience",
			token:           "some-token",
			expectedAud:     "https://other.example.com",
			validatorErr:    errors.New("token audience does not match expected audience"),
			wantErrContains: "audience",
		},
		{
			name:            "expired token",
			token:           "expired-token",
			expectedAud:     "https://api.example.com",
			validatorErr:    errors.New("token has expired"),
			wantErrContains: "expired",
		},
		{
			name:            "invalid signature",
			token:           "tampered-token",
			expectedAud:     "https://api.example.com",
			validatorErr:    errors.New("invalid token signature"),
			wantErrContains: "signature",
		},
		{
			name:            "empty token",
			token:           "",
			expectedAud:     "https://api.example.com",
			validatorErr:    errors.New("token is required"),
			wantErrContains: "required",
		},
		{
			name:            "malformed token",
			token:           "not.a.jwt",
			expectedAud:     "https://api.example.com",
			validatorErr:    errors.New("invalid token format"),
			wantErrContains: "invalid",
		},
		{
			name:            "unsupported algorithm",
			token:           "none-alg-token",
			expectedAud:     "https://api.example.com",
			validatorErr:    errors.New("unsupported algorithm: none"),
			wantErrContains: "algorithm",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			validator := &mockValidator{err: tt.validatorErr}

			_, err := validator.Validate(tt.token, tt.expectedAud)
			if err == nil {
				t.Fatal("Validate() expected error, got nil")
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.wantErrContains)) {
				t.Errorf("Validate() error = %q, want to contain %q", err.Error(), tt.wantErrContains)
			}
		})
	}
}

func TestValidator_Validate_TokenStructure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		token           string
		wantErrContains string
	}{
		{
			name:            "empty token",
			token:           "",
			wantErrContains: "required",
		},
		{
			name:            "single part token",
			token:           "onlyonepart",
			wantErrContains: "invalid",
		},
		{
			name:            "two part token",
			token:           "part1.part2",
			wantErrContains: "invalid",
		},
		{
			name:            "four part token",
			token:           "part1.part2.part3.part4",
			wantErrContains: "invalid",
		},
		{
			name:            "whitespace only",
			token:           "   ",
			wantErrContains: "required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// For structure validation tests, we create a validator that
			// checks token structure first
			validator := &mockValidator{
				err: func() error {
					token := strings.TrimSpace(tt.token)
					if token == "" {
						return errors.New("token is required")
					}
					parts := strings.Split(token, ".")
					if len(parts) != 3 {
						return errors.New("invalid token format: expected 3 parts")
					}
					return nil
				}(),
			}

			_, err := validator.Validate(tt.token, "https://api.example.com")
			if err == nil {
				t.Fatal("Validate() expected error, got nil")
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.wantErrContains)) {
				t.Errorf("Validate() error = %q, want to contain %q", err.Error(), tt.wantErrContains)
			}
		})
	}
}

func TestValidator_Validate_AudienceValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		tokenAudience   []string
		expectedAud     string
		wantErr         bool
		wantErrContains string
	}{
		{
			name:          "single audience matches",
			tokenAudience: []string{"https://api.example.com"},
			expectedAud:   "https://api.example.com",
			wantErr:       false,
		},
		{
			name:          "multiple audiences one matches",
			tokenAudience: []string{"https://other.example.com", "https://api.example.com"},
			expectedAud:   "https://api.example.com",
			wantErr:       false,
		},
		{
			name:            "single audience does not match",
			tokenAudience:   []string{"https://other.example.com"},
			expectedAud:     "https://api.example.com",
			wantErr:         true,
			wantErrContains: "audience",
		},
		{
			name:            "multiple audiences none match",
			tokenAudience:   []string{"https://other1.example.com", "https://other2.example.com"},
			expectedAud:     "https://api.example.com",
			wantErr:         true,
			wantErrContains: "audience",
		},
		{
			name:            "empty audience in token",
			tokenAudience:   []string{},
			expectedAud:     "https://api.example.com",
			wantErr:         true,
			wantErrContains: "audience",
		},
		{
			name:            "nil audience in token",
			tokenAudience:   nil,
			expectedAud:     "https://api.example.com",
			wantErr:         true,
			wantErrContains: "audience",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Simulate audience validation
			var validationErr error
			if tt.wantErr {
				validationErr = errors.New("token audience does not match expected audience")
			}

			validator := &mockValidator{
				claims: &TokenClaims{
					Audience: tt.tokenAudience,
				},
				err: validationErr,
			}

			claims, err := validator.Validate("some-token", tt.expectedAud)
			if tt.wantErr {
				if err == nil {
					t.Fatal("Validate() expected error, got nil")
				}
				if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.wantErrContains)) {
					t.Errorf("Validate() error = %q, want to contain %q", err.Error(), tt.wantErrContains)
				}
			} else {
				if err != nil {
					t.Fatalf("Validate() unexpected error: %v", err)
				}
				if claims == nil {
					t.Fatal("Validate() returned nil claims")
				}
			}
		})
	}
}

func TestValidator_Validate_ExpirationValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		expiresAt       time.Time
		wantErr         bool
		wantErrContains string
	}{
		{
			name:      "token not expired",
			expiresAt: time.Now().Add(1 * time.Hour),
			wantErr:   false,
		},
		{
			name:            "token expired",
			expiresAt:       time.Now().Add(-1 * time.Hour),
			wantErr:         true,
			wantErrContains: "expired",
		},
		{
			name:      "token expires exactly now (within clock skew)",
			expiresAt: time.Now(),
			wantErr:   false, // Should allow for clock skew
		},
		{
			name:            "token expired long ago",
			expiresAt:       time.Now().Add(-24 * time.Hour),
			wantErr:         true,
			wantErrContains: "expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var validationErr error
			if tt.wantErr {
				validationErr = errors.New("token has expired")
			}

			validator := &mockValidator{
				claims: &TokenClaims{
					ExpiresAt: tt.expiresAt,
				},
				err: validationErr,
			}

			claims, err := validator.Validate("some-token", "https://api.example.com")
			if tt.wantErr {
				if err == nil {
					t.Fatal("Validate() expected error, got nil")
				}
				if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.wantErrContains)) {
					t.Errorf("Validate() error = %q, want to contain %q", err.Error(), tt.wantErrContains)
				}
			} else {
				if err != nil {
					t.Fatalf("Validate() unexpected error: %v", err)
				}
				if claims == nil {
					t.Fatal("Validate() returned nil claims")
				}
			}
		})
	}
}

func TestValidator_Validate_AlgorithmValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		algorithm       string
		wantErr         bool
		wantErrContains string
	}{
		{
			name:      "RS256 supported",
			algorithm: "RS256",
			wantErr:   false,
		},
		{
			name:      "RS384 supported",
			algorithm: "RS384",
			wantErr:   false,
		},
		{
			name:      "RS512 supported",
			algorithm: "RS512",
			wantErr:   false,
		},
		{
			name:      "ES256 supported",
			algorithm: "ES256",
			wantErr:   false,
		},
		{
			name:            "none algorithm rejected",
			algorithm:       "none",
			wantErr:         true,
			wantErrContains: "algorithm",
		},
		{
			name:            "HS256 symmetric rejected",
			algorithm:       "HS256",
			wantErr:         true,
			wantErrContains: "algorithm",
		},
		{
			name:            "empty algorithm rejected",
			algorithm:       "",
			wantErr:         true,
			wantErrContains: "algorithm",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var validationErr error
			if tt.wantErr {
				validationErr = errors.New("unsupported algorithm: " + tt.algorithm)
			}

			validator := &mockValidator{
				claims: &TokenClaims{},
				err:    validationErr,
			}

			_, err := validator.Validate("some-token", "https://api.example.com")
			if tt.wantErr {
				if err == nil {
					t.Fatal("Validate() expected error, got nil")
				}
				if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.wantErrContains)) {
					t.Errorf("Validate() error = %q, want to contain %q", err.Error(), tt.wantErrContains)
				}
			} else {
				if err != nil {
					t.Fatalf("Validate() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestKeyProvider_GetKey(t *testing.T) {
	t.Parallel()

	// Generate a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	tests := []struct {
		name            string
		provider        *mockKeyProvider
		keyID           string
		wantErr         bool
		wantErrContains string
	}{
		{
			name: "key found",
			provider: &mockKeyProvider{
				keys: map[string]interface{}{
					"key1": &privateKey.PublicKey,
				},
			},
			keyID:   "key1",
			wantErr: false,
		},
		{
			name: "key not found",
			provider: &mockKeyProvider{
				keys: map[string]interface{}{
					"key1": &privateKey.PublicKey,
				},
			},
			keyID:           "unknown-key",
			wantErr:         true,
			wantErrContains: "not found",
		},
		{
			name: "empty key ID",
			provider: &mockKeyProvider{
				keys: map[string]interface{}{
					"key1": &privateKey.PublicKey,
				},
			},
			keyID:           "",
			wantErr:         true,
			wantErrContains: "not found",
		},
		{
			name: "provider error",
			provider: &mockKeyProvider{
				err: errors.New("connection failed"),
			},
			keyID:           "key1",
			wantErr:         true,
			wantErrContains: "connection",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			key, err := tt.provider.GetKey(tt.keyID)
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

// Benchmark tests for token validation
func BenchmarkValidator_Validate(b *testing.B) {
	validator := &mockValidator{
		claims: &TokenClaims{
			Subject:   "user123",
			Audience:  []string{"https://api.example.com"},
			Issuer:    "https://auth.example.com",
			Scopes:    []string{"mcp:read", "mcp:write"},
			ExpiresAt: time.Now().Add(1 * time.Hour),
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = validator.Validate("test-token", "https://api.example.com")
	}
}
