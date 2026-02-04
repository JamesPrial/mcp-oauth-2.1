package oauth

import (
	"context"
	"testing"
	"time"
)

func TestNewJWKSClient(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		AuthorizationServers: []string{"https://auth.example.com"},
		JWKSCacheTTL:         5 * time.Minute,
	}

	client := NewJWKSClient(cfg)
	if client == nil {
		t.Fatal("NewJWKSClient() returned nil")
	}
}

func TestNewTokenValidator(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		AuthorizationServers: []string{"https://auth.example.com"},
		Audience:             "https://api.example.com",
		JWKSCacheTTL:         5 * time.Minute,
		ClockSkew:            1 * time.Minute,
	}

	jwksClient := NewJWKSClient(cfg)
	validator := NewTokenValidator(cfg, jwksClient)

	if validator == nil {
		t.Fatal("NewTokenValidator() returned nil")
	}
}

func TestNewMetadataService(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		BaseURL:              "https://example.com/mcp",
		AuthorizationServers: []string{"https://auth.example.com"},
		ScopesSupported:      []string{"mcp:read", "mcp:write"},
	}

	service := NewMetadataService(cfg)
	if service == nil {
		t.Fatal("NewMetadataService() returned nil")
	}

	metadata, err := service.GetMetadata(context.Background())
	if err != nil {
		t.Fatalf("GetMetadata() unexpected error: %v", err)
	}

	if metadata.Resource != "https://example.com/mcp" {
		t.Errorf("Resource = %q, want %q", metadata.Resource, "https://example.com/mcp")
	}
}

func TestNewScopeChecker(t *testing.T) {
	t.Parallel()

	checker := NewScopeChecker()
	if checker == nil {
		t.Fatal("NewScopeChecker() returned nil")
	}
}

func TestNewOAuthServices(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		BaseURL:              "https://example.com/mcp",
		AuthorizationServers: []string{"https://auth.example.com"},
		Audience:             "https://api.example.com",
		ScopesSupported:      []string{"mcp:read", "mcp:write"},
		JWKSCacheTTL:         5 * time.Minute,
		ClockSkew:            1 * time.Minute,
	}

	tokenValidator, metadataService, scopeChecker, jwksClient := NewOAuthServices(cfg)

	if tokenValidator == nil {
		t.Error("NewOAuthServices() returned nil tokenValidator")
	}
	if metadataService == nil {
		t.Error("NewOAuthServices() returned nil metadataService")
	}
	if scopeChecker == nil {
		t.Error("NewOAuthServices() returned nil scopeChecker")
	}
	if jwksClient == nil {
		t.Error("NewOAuthServices() returned nil jwksClient")
	}
}

func TestTokenValidatorAdapter(t *testing.T) {
	t.Parallel()

	// This test verifies the adapter doesn't panic with nil claims
	// The actual validation logic is tested in the internal/token package

	cfg := &Config{
		AuthorizationServers: []string{"https://auth.example.com"},
		Audience:             "https://api.example.com",
		JWKSCacheTTL:         5 * time.Minute,
		ClockSkew:            1 * time.Minute,
	}

	jwksClient := NewJWKSClient(cfg)
	validator := NewTokenValidator(cfg, jwksClient)

	// Invalid token should return error
	_, err := validator.ValidateToken(context.Background(), "invalid-token")
	if err == nil {
		t.Error("ValidateToken() expected error for invalid token, got nil")
	}
}

func TestMetadataServiceAdapter(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		BaseURL:              "https://example.com/mcp",
		AuthorizationServers: []string{"https://auth.example.com", "https://auth2.example.com"},
		ScopesSupported:      []string{"mcp:read", "mcp:write"},
	}

	service := NewMetadataService(cfg)

	// Test GetMetadata
	metadata, err := service.GetMetadata(context.Background())
	if err != nil {
		t.Fatalf("GetMetadata() unexpected error: %v", err)
	}

	if metadata.Resource != "https://example.com/mcp" {
		t.Errorf("Resource = %q, want %q", metadata.Resource, "https://example.com/mcp")
	}

	if len(metadata.AuthorizationServers) != 2 {
		t.Errorf("AuthorizationServers length = %d, want 2", len(metadata.AuthorizationServers))
	}

	if len(metadata.ScopesSupported) != 2 {
		t.Errorf("ScopesSupported length = %d, want 2", len(metadata.ScopesSupported))
	}

	// Test GetMetadataURL
	metadataURL := service.GetMetadataURL()
	expectedURL := "https://example.com/mcp/.well-known/oauth-protected-resource"
	if metadataURL != expectedURL {
		t.Errorf("GetMetadataURL() = %q, want %q", metadataURL, expectedURL)
	}
}

func TestScopeCheckerAdapter(t *testing.T) {
	t.Parallel()

	checker := NewScopeChecker()

	claims := &TokenClaims{
		Subject:  "user123",
		Issuer:   "https://auth.example.com",
		Audience: []string{"https://api.example.com"},
		Scopes:   []string{"mcp:read", "mcp:write"},
	}

	// Test RequireScopes with all scopes present
	err := checker.RequireScopes(claims, "mcp:read", "mcp:write")
	if err != nil {
		t.Errorf("RequireScopes() unexpected error: %v", err)
	}

	// Test RequireScopes with missing scope
	err = checker.RequireScopes(claims, "mcp:admin")
	if err == nil {
		t.Error("RequireScopes() expected error for missing scope, got nil")
	}

	// Test RequireAnyScope with one scope present
	err = checker.RequireAnyScope(claims, "mcp:read", "mcp:admin")
	if err != nil {
		t.Errorf("RequireAnyScope() unexpected error: %v", err)
	}

	// Test RequireAnyScope with no scopes present
	err = checker.RequireAnyScope(claims, "mcp:admin", "mcp:delete")
	if err == nil {
		t.Error("RequireAnyScope() expected error for no matching scopes, got nil")
	}
}

func TestScopeCheckerAdapter_NilClaims(t *testing.T) {
	t.Parallel()

	checker := NewScopeChecker()

	// Test with nil claims
	err := checker.RequireScopes(nil, "mcp:read")
	if err == nil {
		t.Error("RequireScopes() expected error for nil claims, got nil")
	}

	err = checker.RequireAnyScope(nil, "mcp:read")
	if err == nil {
		t.Error("RequireAnyScope() expected error for nil claims, got nil")
	}
}

func TestConfig_DefaultValues(t *testing.T) {
	t.Parallel()

	cfg := &Config{}

	// Verify zero values don't cause panics
	jwksClient := NewJWKSClient(cfg)
	if jwksClient == nil {
		t.Error("NewJWKSClient() should handle empty config")
	}

	metadataService := NewMetadataService(cfg)
	if metadataService == nil {
		t.Error("NewMetadataService() should handle empty config")
	}

	scopeChecker := NewScopeChecker()
	if scopeChecker == nil {
		t.Error("NewScopeChecker() should not return nil")
	}
}

func BenchmarkNewOAuthServices(b *testing.B) {
	cfg := &Config{
		BaseURL:              "https://example.com/mcp",
		AuthorizationServers: []string{"https://auth.example.com"},
		Audience:             "https://api.example.com",
		ScopesSupported:      []string{"mcp:read", "mcp:write"},
		JWKSCacheTTL:         5 * time.Minute,
		ClockSkew:            1 * time.Minute,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, _ = NewOAuthServices(cfg)
	}
}
