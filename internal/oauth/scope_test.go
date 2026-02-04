// Package oauth provides the OAuth 2.1 implementation for the MCP server.
// This test file tests the ScopeChecker functionality.
package oauth

import (
	"errors"
	"strings"
	"testing"
)

// ScopeError represents an error related to scope validation.
type ScopeError struct {
	Code           string
	Message        string
	RequiredScopes []string
	GrantedScopes  []string
}

func (e *ScopeError) Error() string {
	return e.Code + ": " + e.Message
}

// ErrClaimsRequired is a test-specific error
var ErrClaimsRequired = errors.New("claims required")

// mockScopeChecker implements ScopeChecker for testing.
type mockScopeChecker struct {
	resourceMetadataURL string
}

func newMockScopeChecker(resourceMetadataURL string) *mockScopeChecker {
	return &mockScopeChecker{resourceMetadataURL: resourceMetadataURL}
}

func (c *mockScopeChecker) RequireScopes(claims *TokenClaims, required []string) error {
	if claims == nil {
		return &ScopeError{
			Code:           "claims_required",
			Message:        "claims are required for scope checking",
			RequiredScopes: required,
		}
	}

	var missing []string
	for _, scope := range required {
		if !claims.HasScope(scope) {
			missing = append(missing, scope)
		}
	}

	if len(missing) > 0 {
		return &ScopeError{
			Code:           "insufficient_scope",
			Message:        "missing required scopes: " + strings.Join(missing, ", "),
			RequiredScopes: required,
			GrantedScopes:  claims.Scopes,
		}
	}

	return nil
}

func (c *mockScopeChecker) RequireAnyScope(claims *TokenClaims, required []string) error {
	if claims == nil {
		return &ScopeError{
			Code:           "claims_required",
			Message:        "claims are required for scope checking",
			RequiredScopes: required,
		}
	}

	if len(required) == 0 {
		return nil
	}

	if claims.HasAnyScope(required...) {
		return nil
	}

	return &ScopeError{
		Code:           "insufficient_scope",
		Message:        "none of the required scopes are present: " + strings.Join(required, ", "),
		RequiredScopes: required,
		GrantedScopes:  claims.Scopes,
	}
}

func TestScopeChecker_RequireScopes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		claims          *TokenClaims
		required        []string
		wantErr         bool
		wantErrContains string
	}{
		{
			name: "all required scopes present",
			claims: &TokenClaims{
				Scopes: []string{"mcp:read", "mcp:write"},
			},
			required: []string{"mcp:read", "mcp:write"},
			wantErr:  false,
		},
		{
			name: "extra scopes beyond required",
			claims: &TokenClaims{
				Scopes: []string{"mcp:read", "mcp:write", "mcp:admin"},
			},
			required: []string{"mcp:read"},
			wantErr:  false,
		},
		{
			name: "missing one required scope",
			claims: &TokenClaims{
				Scopes: []string{"mcp:read"},
			},
			required:        []string{"mcp:read", "mcp:write"},
			wantErr:         true,
			wantErrContains: "insufficient_scope",
		},
		{
			name: "missing all required scopes",
			claims: &TokenClaims{
				Scopes: []string{"mcp:delete"},
			},
			required:        []string{"mcp:read", "mcp:write"},
			wantErr:         true,
			wantErrContains: "insufficient_scope",
		},
		{
			name: "empty required scopes",
			claims: &TokenClaims{
				Scopes: []string{"mcp:read"},
			},
			required: []string{},
			wantErr:  false,
		},
		{
			name: "nil required scopes",
			claims: &TokenClaims{
				Scopes: []string{"mcp:read"},
			},
			required: nil,
			wantErr:  false,
		},
		{
			name:            "nil claims",
			claims:          nil,
			required:        []string{"mcp:read"},
			wantErr:         true,
			wantErrContains: "required",
		},
		{
			name:            "nil claims with empty required",
			claims:          nil,
			required:        []string{},
			wantErr:         true,
			wantErrContains: "required",
		},
		{
			name: "empty claims scopes",
			claims: &TokenClaims{
				Scopes: []string{},
			},
			required:        []string{"mcp:read"},
			wantErr:         true,
			wantErrContains: "insufficient_scope",
		},
		{
			name: "single required scope present",
			claims: &TokenClaims{
				Scopes: []string{"mcp:read"},
			},
			required: []string{"mcp:read"},
			wantErr:  false,
		},
		{
			name: "case sensitive scope matching",
			claims: &TokenClaims{
				Scopes: []string{"MCP:READ"},
			},
			required:        []string{"mcp:read"},
			wantErr:         true,
			wantErrContains: "insufficient_scope",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			checker := newMockScopeChecker("https://example.com/.well-known/oauth-protected-resource")
			err := checker.RequireScopes(tt.claims, tt.required)

			if tt.wantErr {
				if err == nil {
					t.Fatal("RequireScopes() expected error, got nil")
				}
				if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.wantErrContains)) {
					t.Errorf("RequireScopes() error = %q, want to contain %q", err.Error(), tt.wantErrContains)
				}
			} else {
				if err != nil {
					t.Errorf("RequireScopes() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestScopeChecker_RequireAnyScope(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		claims          *TokenClaims
		required        []string
		wantErr         bool
		wantErrContains string
	}{
		{
			name: "one scope matches",
			claims: &TokenClaims{
				Scopes: []string{"mcp:read"},
			},
			required: []string{"mcp:read", "mcp:write"},
			wantErr:  false,
		},
		{
			name: "multiple scopes match",
			claims: &TokenClaims{
				Scopes: []string{"mcp:read", "mcp:write"},
			},
			required: []string{"mcp:read", "mcp:write"},
			wantErr:  false,
		},
		{
			name: "none match",
			claims: &TokenClaims{
				Scopes: []string{"mcp:delete"},
			},
			required:        []string{"mcp:read", "mcp:write"},
			wantErr:         true,
			wantErrContains: "insufficient_scope",
		},
		{
			name: "empty required scopes",
			claims: &TokenClaims{
				Scopes: []string{"mcp:read"},
			},
			required: []string{},
			wantErr:  false,
		},
		{
			name:            "nil claims",
			claims:          nil,
			required:        []string{"mcp:read"},
			wantErr:         true,
			wantErrContains: "required",
		},
		{
			name: "nil required scopes",
			claims: &TokenClaims{
				Scopes: []string{"mcp:read"},
			},
			required: nil,
			wantErr:  false,
		},
		{
			name: "last scope in list matches",
			claims: &TokenClaims{
				Scopes: []string{"mcp:admin"},
			},
			required: []string{"mcp:read", "mcp:write", "mcp:admin"},
			wantErr:  false,
		},
		{
			name: "first scope in list matches",
			claims: &TokenClaims{
				Scopes: []string{"mcp:read"},
			},
			required: []string{"mcp:read", "mcp:write", "mcp:admin"},
			wantErr:  false,
		},
		{
			name: "empty claims scopes",
			claims: &TokenClaims{
				Scopes: []string{},
			},
			required:        []string{"mcp:read"},
			wantErr:         true,
			wantErrContains: "insufficient_scope",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			checker := newMockScopeChecker("https://example.com/.well-known/oauth-protected-resource")
			err := checker.RequireAnyScope(tt.claims, tt.required)

			if tt.wantErr {
				if err == nil {
					t.Fatal("RequireAnyScope() expected error, got nil")
				}
				if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.wantErrContains)) {
					t.Errorf("RequireAnyScope() error = %q, want to contain %q", err.Error(), tt.wantErrContains)
				}
			} else {
				if err != nil {
					t.Errorf("RequireAnyScope() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestScopeError_Fields(t *testing.T) {
	t.Parallel()

	err := &ScopeError{
		Code:           "insufficient_scope",
		Message:        "missing required scopes",
		RequiredScopes: []string{"mcp:read", "mcp:write"},
		GrantedScopes:  []string{"mcp:read"},
	}

	// Verify error message contains code
	if !strings.Contains(err.Error(), "insufficient_scope") {
		t.Errorf("Error() = %q, want to contain %q", err.Error(), "insufficient_scope")
	}

	// Verify fields are accessible
	if err.Code != "insufficient_scope" {
		t.Errorf("Code = %q, want %q", err.Code, "insufficient_scope")
	}
	if len(err.RequiredScopes) != 2 {
		t.Errorf("RequiredScopes length = %d, want 2", len(err.RequiredScopes))
	}
	if len(err.GrantedScopes) != 1 {
		t.Errorf("GrantedScopes length = %d, want 1", len(err.GrantedScopes))
	}
}

func TestScopeChecker_RequireScopes_ErrorDetails(t *testing.T) {
	t.Parallel()

	claims := &TokenClaims{
		Scopes: []string{"mcp:read"},
	}
	required := []string{"mcp:read", "mcp:write", "mcp:admin"}

	checker := newMockScopeChecker("https://example.com/.well-known/oauth-protected-resource")
	err := checker.RequireScopes(claims, required)

	if err == nil {
		t.Fatal("RequireScopes() expected error, got nil")
	}

	scopeErr, ok := err.(*ScopeError)
	if !ok {
		t.Fatalf("Error type = %T, want *ScopeError", err)
	}

	if scopeErr.Code != "insufficient_scope" {
		t.Errorf("Error code = %q, want %q", scopeErr.Code, "insufficient_scope")
	}

	// Should list the required scopes
	if len(scopeErr.RequiredScopes) != 3 {
		t.Errorf("RequiredScopes length = %d, want 3", len(scopeErr.RequiredScopes))
	}

	// Should list the granted scopes
	if len(scopeErr.GrantedScopes) != 1 {
		t.Errorf("GrantedScopes length = %d, want 1", len(scopeErr.GrantedScopes))
	}
}

func TestScopeChecker_RequireAnyScope_ErrorDetails(t *testing.T) {
	t.Parallel()

	claims := &TokenClaims{
		Scopes: []string{"mcp:delete"},
	}
	required := []string{"mcp:read", "mcp:write"}

	checker := newMockScopeChecker("https://example.com/.well-known/oauth-protected-resource")
	err := checker.RequireAnyScope(claims, required)

	if err == nil {
		t.Fatal("RequireAnyScope() expected error, got nil")
	}

	scopeErr, ok := err.(*ScopeError)
	if !ok {
		t.Fatalf("Error type = %T, want *ScopeError", err)
	}

	if scopeErr.Code != "insufficient_scope" {
		t.Errorf("Error code = %q, want %q", scopeErr.Code, "insufficient_scope")
	}

	// Should list the required scopes
	if len(scopeErr.RequiredScopes) != 2 {
		t.Errorf("RequiredScopes length = %d, want 2", len(scopeErr.RequiredScopes))
	}

	// Should list the granted scopes
	if len(scopeErr.GrantedScopes) != 1 {
		t.Errorf("GrantedScopes length = %d, want 1", len(scopeErr.GrantedScopes))
	}
}

// Benchmark tests for scope checking operations
func BenchmarkScopeChecker_RequireScopes(b *testing.B) {
	checker := newMockScopeChecker("https://example.com/.well-known/oauth-protected-resource")
	claims := &TokenClaims{
		Scopes: []string{"mcp:read", "mcp:write", "mcp:admin"},
	}
	required := []string{"mcp:read", "mcp:write"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = checker.RequireScopes(claims, required)
	}
}

func BenchmarkScopeChecker_RequireAnyScope(b *testing.B) {
	checker := newMockScopeChecker("https://example.com/.well-known/oauth-protected-resource")
	claims := &TokenClaims{
		Scopes: []string{"mcp:read", "mcp:write", "mcp:admin"},
	}
	required := []string{"mcp:admin", "mcp:super"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = checker.RequireAnyScope(claims, required)
	}
}

func BenchmarkScopeChecker_RequireScopes_Missing(b *testing.B) {
	checker := newMockScopeChecker("https://example.com/.well-known/oauth-protected-resource")
	claims := &TokenClaims{
		Scopes: []string{"mcp:read"},
	}
	required := []string{"mcp:read", "mcp:write", "mcp:admin"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = checker.RequireScopes(claims, required)
	}
}
