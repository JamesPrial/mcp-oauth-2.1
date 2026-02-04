package token

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// mockJWKSClient implements JWKSClient for testing.
type mockJWKSClient struct {
	mu           sync.Mutex
	keys         map[string]any
	getKeyErr    error
	refreshErr   error
	getCalls     int
	refreshCalls int
}

func newMockJWKSClient() *mockJWKSClient {
	return &mockJWKSClient{
		keys: make(map[string]any),
	}
}

func (m *mockJWKSClient) GetKey(ctx context.Context, keyID string) (any, error) {
	m.mu.Lock()
	m.getCalls++
	getKeyErr := m.getKeyErr
	m.mu.Unlock()

	if getKeyErr != nil {
		return nil, getKeyErr
	}

	m.mu.Lock()
	key, ok := m.keys[keyID]
	m.mu.Unlock()

	if !ok {
		return nil, nil
	}
	return key, nil
}

func (m *mockJWKSClient) RefreshKeys(ctx context.Context) error {
	m.mu.Lock()
	m.refreshCalls++
	refreshErr := m.refreshErr
	m.mu.Unlock()

	return refreshErr
}

func (m *mockJWKSClient) addKey(keyID string, key any) {
	m.mu.Lock()
	m.keys[keyID] = key
	m.mu.Unlock()
}

// createSignedToken creates a properly signed JWT token for testing.
func createSignedToken(t *testing.T, privateKey *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	return tokenString
}

// createSignedTokenWithAlg creates a signed JWT token with custom algorithm.
func createSignedTokenWithAlg(t *testing.T, method jwt.SigningMethod, privateKey any, kid string, claims jwt.MapClaims) string {
	t.Helper()

	token := jwt.NewWithClaims(method, claims)
	token.Header["kid"] = kid

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	return tokenString
}

func TestValidator_ValidateToken_Success(t *testing.T) {
	t.Parallel()

	// Generate test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	jwksClient := newMockJWKSClient()
	jwksClient.addKey("test-key-1", &privateKey.PublicKey)

	validator := NewValidator(jwksClient, "https://api.example.com", 5*time.Minute)

	claims := jwt.MapClaims{
		"sub":   "user123",
		"iss":   "https://auth.example.com",
		"aud":   []string{"https://api.example.com"},
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"jti":   "token-id-123",
		"scope": "mcp:read mcp:write",
	}

	tokenString := createSignedToken(t, privateKey, "test-key-1", claims)

	result, err := validator.ValidateToken(context.Background(), tokenString)
	if err != nil {
		t.Fatalf("ValidateToken() unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("ValidateToken() returned nil claims")
	}

	if result.Subject != "user123" {
		t.Errorf("Subject = %q, want %q", result.Subject, "user123")
	}

	if result.Issuer != "https://auth.example.com" {
		t.Errorf("Issuer = %q, want %q", result.Issuer, "https://auth.example.com")
	}

	if len(result.Scopes) != 2 {
		t.Errorf("Scopes length = %d, want 2", len(result.Scopes))
	}

	if !result.HasScope("mcp:read") {
		t.Error("Token should have mcp:read scope")
	}

	if !result.HasScope("mcp:write") {
		t.Error("Token should have mcp:write scope")
	}
}

func TestValidator_ValidateToken_ExpiredToken(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	jwksClient := newMockJWKSClient()
	jwksClient.addKey("test-key-1", &privateKey.PublicKey)

	validator := NewValidator(jwksClient, "https://api.example.com", 5*time.Second)

	claims := jwt.MapClaims{
		"sub": "user123",
		"iss": "https://auth.example.com",
		"aud": []string{"https://api.example.com"},
		"exp": time.Now().Add(-1 * time.Hour).Unix(), // Expired
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
	}

	tokenString := createSignedToken(t, privateKey, "test-key-1", claims)

	_, err = validator.ValidateToken(context.Background(), tokenString)
	if err == nil {
		t.Fatal("ValidateToken() expected error for expired token, got nil")
	}

	if !strings.Contains(strings.ToLower(err.Error()), "expired") &&
		!strings.Contains(strings.ToLower(err.Error()), "unauthorized") {
		t.Errorf("ValidateToken() error = %q, want error about expiration", err.Error())
	}
}

func TestValidator_ValidateToken_WrongAudience(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	jwksClient := newMockJWKSClient()
	jwksClient.addKey("test-key-1", &privateKey.PublicKey)

	validator := NewValidator(jwksClient, "https://api.example.com", 5*time.Minute)

	claims := jwt.MapClaims{
		"sub": "user123",
		"iss": "https://auth.example.com",
		"aud": []string{"https://other.example.com"}, // Wrong audience
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}

	tokenString := createSignedToken(t, privateKey, "test-key-1", claims)

	_, err = validator.ValidateToken(context.Background(), tokenString)
	if err == nil {
		t.Fatal("ValidateToken() expected error for wrong audience, got nil")
	}

	if !strings.Contains(strings.ToLower(err.Error()), "audience") {
		t.Errorf("ValidateToken() error = %q, want error about audience", err.Error())
	}
}

func TestValidator_ValidateToken_MalformedToken(t *testing.T) {
	t.Parallel()

	jwksClient := newMockJWKSClient()
	validator := NewValidator(jwksClient, "https://api.example.com", 5*time.Minute)

	tests := []struct {
		name            string
		token           string
		wantErrContains string
	}{
		{
			name:            "not a JWT",
			token:           "not-a-jwt-token",
			wantErrContains: "parse",
		},
		{
			name:            "empty token",
			token:           "",
			wantErrContains: "parse",
		},
		{
			name:            "two parts only",
			token:           "header.payload",
			wantErrContains: "parse",
		},
		{
			name:            "invalid base64",
			token:           "invalid!@#.invalid!@#.invalid!@#",
			wantErrContains: "parse",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := validator.ValidateToken(context.Background(), tt.token)
			if err == nil {
				t.Fatal("ValidateToken() expected error, got nil")
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.wantErrContains)) {
				t.Errorf("ValidateToken() error = %q, want to contain %q", err.Error(), tt.wantErrContains)
			}
		})
	}
}

func TestValidator_ValidateToken_UnsupportedAlgorithm(t *testing.T) {
	t.Parallel()

	jwksClient := newMockJWKSClient()
	validator := NewValidator(jwksClient, "https://api.example.com", 5*time.Minute)

	// Create a token with "none" algorithm (unsigned)
	claims := jwt.MapClaims{
		"sub": "user123",
		"iss": "https://auth.example.com",
		"aud": []string{"https://api.example.com"},
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	token.Header["kid"] = "test-key"

	tokenString, _ := token.SignedString(jwt.UnsafeAllowNoneSignatureType)

	_, err := validator.ValidateToken(context.Background(), tokenString)
	if err == nil {
		t.Fatal("ValidateToken() expected error for 'none' algorithm, got nil")
	}

	if !strings.Contains(strings.ToLower(err.Error()), "algorithm") {
		t.Errorf("ValidateToken() error = %q, want error about algorithm", err.Error())
	}
}

func TestValidator_ValidateToken_MissingKID(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	jwksClient := newMockJWKSClient()
	jwksClient.addKey("test-key-1", &privateKey.PublicKey)

	validator := NewValidator(jwksClient, "https://api.example.com", 5*time.Minute)

	claims := jwt.MapClaims{
		"sub": "user123",
		"iss": "https://auth.example.com",
		"aud": []string{"https://api.example.com"},
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	// Don't set kid in header

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	_, err = validator.ValidateToken(context.Background(), tokenString)
	if err == nil {
		t.Fatal("ValidateToken() expected error for missing kid, got nil")
	}

	if !strings.Contains(strings.ToLower(err.Error()), "kid") {
		t.Errorf("ValidateToken() error = %q, want error about missing kid", err.Error())
	}
}

func TestValidator_ValidateToken_KeyNotFound(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	jwksClient := newMockJWKSClient()
	// Don't add the key to the client

	validator := NewValidator(jwksClient, "https://api.example.com", 5*time.Minute)

	claims := jwt.MapClaims{
		"sub": "user123",
		"iss": "https://auth.example.com",
		"aud": []string{"https://api.example.com"},
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	}

	tokenString := createSignedToken(t, privateKey, "unknown-key", claims)

	_, err = validator.ValidateToken(context.Background(), tokenString)
	if err == nil {
		t.Fatal("ValidateToken() expected error for key not found, got nil")
	}

	if !strings.Contains(strings.ToLower(err.Error()), "key") &&
		!strings.Contains(strings.ToLower(err.Error()), "not found") {
		t.Errorf("ValidateToken() error = %q, want error about key not found", err.Error())
	}
}

func TestValidator_ValidateToken_MissingRequiredClaims(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	jwksClient := newMockJWKSClient()
	jwksClient.addKey("test-key-1", &privateKey.PublicKey)

	validator := NewValidator(jwksClient, "https://api.example.com", 5*time.Minute)

	tests := []struct {
		name            string
		claims          jwt.MapClaims
		wantErrContains string
	}{
		{
			name: "missing subject",
			claims: jwt.MapClaims{
				"iss": "https://auth.example.com",
				"aud": []string{"https://api.example.com"},
				"exp": time.Now().Add(1 * time.Hour).Unix(),
			},
			wantErrContains: "sub",
		},
		{
			name: "missing issuer",
			claims: jwt.MapClaims{
				"sub": "user123",
				"aud": []string{"https://api.example.com"},
				"exp": time.Now().Add(1 * time.Hour).Unix(),
			},
			wantErrContains: "iss",
		},
		{
			name: "missing audience",
			claims: jwt.MapClaims{
				"sub": "user123",
				"iss": "https://auth.example.com",
				"exp": time.Now().Add(1 * time.Hour).Unix(),
			},
			wantErrContains: "aud",
		},
		{
			name: "missing expiration",
			claims: jwt.MapClaims{
				"sub": "user123",
				"iss": "https://auth.example.com",
				"aud": []string{"https://api.example.com"},
			},
			wantErrContains: "exp",
		},
		{
			name: "empty subject",
			claims: jwt.MapClaims{
				"sub": "",
				"iss": "https://auth.example.com",
				"aud": []string{"https://api.example.com"},
				"exp": time.Now().Add(1 * time.Hour).Unix(),
			},
			wantErrContains: "sub",
		},
		{
			name: "empty audience array",
			claims: jwt.MapClaims{
				"sub": "user123",
				"iss": "https://auth.example.com",
				"aud": []string{},
				"exp": time.Now().Add(1 * time.Hour).Unix(),
			},
			wantErrContains: "aud",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tokenString := createSignedToken(t, privateKey, "test-key-1", tt.claims)

			_, err := validator.ValidateToken(context.Background(), tokenString)
			if err == nil {
				t.Fatal("ValidateToken() expected error, got nil")
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.wantErrContains)) {
				t.Errorf("ValidateToken() error = %q, want to contain %q", err.Error(), tt.wantErrContains)
			}
		})
	}
}

func TestValidator_ValidateToken_MultipleAudiences(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	jwksClient := newMockJWKSClient()
	jwksClient.addKey("test-key-1", &privateKey.PublicKey)

	validator := NewValidator(jwksClient, "https://api.example.com", 5*time.Minute)

	claims := jwt.MapClaims{
		"sub": "user123",
		"iss": "https://auth.example.com",
		"aud": []string{"https://other.example.com", "https://api.example.com", "https://third.example.com"},
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	}

	tokenString := createSignedToken(t, privateKey, "test-key-1", claims)

	result, err := validator.ValidateToken(context.Background(), tokenString)
	if err != nil {
		t.Fatalf("ValidateToken() unexpected error: %v", err)
	}

	if len(result.Audience) != 3 {
		t.Errorf("Audience length = %d, want 3", len(result.Audience))
	}
}

func TestValidator_ValidateToken_SupportedAlgorithms(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		method  jwt.SigningMethod
		genKey  func() (any, any, error) // Returns (private, public, error)
		wantErr bool
	}{
		{
			name:   "RS256",
			method: jwt.SigningMethodRS256,
			genKey: func() (any, any, error) {
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				return key, &key.PublicKey, err
			},
			wantErr: false,
		},
		{
			name:   "RS384",
			method: jwt.SigningMethodRS384,
			genKey: func() (any, any, error) {
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				return key, &key.PublicKey, err
			},
			wantErr: false,
		},
		{
			name:   "RS512",
			method: jwt.SigningMethodRS512,
			genKey: func() (any, any, error) {
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				return key, &key.PublicKey, err
			},
			wantErr: false,
		},
		{
			name:   "ES256",
			method: jwt.SigningMethodES256,
			genKey: func() (any, any, error) {
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				return key, &key.PublicKey, err
			},
			wantErr: false,
		},
		{
			name:   "ES384",
			method: jwt.SigningMethodES384,
			genKey: func() (any, any, error) {
				key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				return key, &key.PublicKey, err
			},
			wantErr: false,
		},
		{
			name:   "ES512",
			method: jwt.SigningMethodES512,
			genKey: func() (any, any, error) {
				key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
				return key, &key.PublicKey, err
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			privateKey, publicKey, err := tt.genKey()
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}

			jwksClient := newMockJWKSClient()
			jwksClient.addKey("test-key-1", publicKey)

			validator := NewValidator(jwksClient, "https://api.example.com", 5*time.Minute)

			claims := jwt.MapClaims{
				"sub": "user123",
				"iss": "https://auth.example.com",
				"aud": []string{"https://api.example.com"},
				"exp": time.Now().Add(1 * time.Hour).Unix(),
			}

			tokenString := createSignedTokenWithAlg(t, tt.method, privateKey, "test-key-1", claims)

			_, err = validator.ValidateToken(context.Background(), tokenString)
			if tt.wantErr {
				if err == nil {
					t.Fatal("ValidateToken() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Fatalf("ValidateToken() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestValidator_ValidateToken_OptionalClaims(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	jwksClient := newMockJWKSClient()
	jwksClient.addKey("test-key-1", &privateKey.PublicKey)

	validator := NewValidator(jwksClient, "https://api.example.com", 5*time.Minute)

	claims := jwt.MapClaims{
		"sub": "user123",
		"iss": "https://auth.example.com",
		"aud": []string{"https://api.example.com"},
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"iat": time.Now().Unix(),
		"jti": "token-id-123",
	}

	tokenString := createSignedToken(t, privateKey, "test-key-1", claims)

	result, err := validator.ValidateToken(context.Background(), tokenString)
	if err != nil {
		t.Fatalf("ValidateToken() unexpected error: %v", err)
	}

	if result.JTI != "token-id-123" {
		t.Errorf("JTI = %q, want %q", result.JTI, "token-id-123")
	}

	if result.IssuedAt.IsZero() {
		t.Error("IssuedAt should not be zero")
	}
}

func TestValidator_ValidateToken_WithoutOptionalClaims(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	jwksClient := newMockJWKSClient()
	jwksClient.addKey("test-key-1", &privateKey.PublicKey)

	validator := NewValidator(jwksClient, "https://api.example.com", 5*time.Minute)

	claims := jwt.MapClaims{
		"sub": "user123",
		"iss": "https://auth.example.com",
		"aud": []string{"https://api.example.com"},
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	}

	tokenString := createSignedToken(t, privateKey, "test-key-1", claims)

	result, err := validator.ValidateToken(context.Background(), tokenString)
	if err != nil {
		t.Fatalf("ValidateToken() unexpected error: %v", err)
	}

	if result.JTI != "" {
		t.Errorf("JTI = %q, want empty", result.JTI)
	}

	if !result.IssuedAt.IsZero() {
		t.Error("IssuedAt should be zero when not provided")
	}
}

func TestParseScopes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "single scope",
			input:    "mcp:read",
			expected: []string{"mcp:read"},
		},
		{
			name:     "multiple scopes",
			input:    "mcp:read mcp:write",
			expected: []string{"mcp:read", "mcp:write"},
		},
		{
			name:     "scopes with extra spaces",
			input:    "mcp:read  mcp:write   mcp:admin",
			expected: []string{"mcp:read", "mcp:write", "mcp:admin"},
		},
		{
			name:     "empty string",
			input:    "",
			expected: nil,
		},
		{
			name:     "only spaces",
			input:    "   ",
			expected: nil,
		},
		{
			name:     "leading and trailing spaces",
			input:    "  mcp:read mcp:write  ",
			expected: []string{"mcp:read", "mcp:write"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := parseScopes(tt.input)

			if len(result) != len(tt.expected) {
				t.Errorf("parseScopes(%q) length = %d, want %d", tt.input, len(result), len(tt.expected))
				return
			}

			for i, scope := range result {
				if scope != tt.expected[i] {
					t.Errorf("parseScopes(%q)[%d] = %q, want %q", tt.input, i, scope, tt.expected[i])
				}
			}
		})
	}
}

func TestNewValidator(t *testing.T) {
	t.Parallel()

	jwksClient := newMockJWKSClient()
	audience := "https://api.example.com"
	clockSkew := 5 * time.Minute

	validator := NewValidator(jwksClient, audience, clockSkew)

	if validator == nil {
		t.Fatal("NewValidator() returned nil")
	}

	if validator.audience != audience {
		t.Errorf("validator.audience = %q, want %q", validator.audience, audience)
	}

	if validator.clockSkew != clockSkew {
		t.Errorf("validator.clockSkew = %v, want %v", validator.clockSkew, clockSkew)
	}
}

func BenchmarkValidator_ValidateToken(b *testing.B) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwksClient := newMockJWKSClient()
	jwksClient.addKey("test-key-1", &privateKey.PublicKey)

	validator := NewValidator(jwksClient, "https://api.example.com", 5*time.Minute)

	claims := jwt.MapClaims{
		"sub":   "user123",
		"iss":   "https://auth.example.com",
		"aud":   []string{"https://api.example.com"},
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
		"scope": "mcp:read mcp:write",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-key-1"
	tokenString, _ := token.SignedString(privateKey)

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = validator.ValidateToken(ctx, tokenString)
	}
}

func BenchmarkParseScopes(b *testing.B) {
	scopeStr := "mcp:read mcp:write mcp:admin mcp:delete"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = parseScopes(scopeStr)
	}
}
