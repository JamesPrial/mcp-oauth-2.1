package token

import (
	"strings"
	"testing"
	"time"
)

func TestScopeChecker_RequireScopes(t *testing.T) {
	t.Parallel()

	checker := NewScopeChecker()

	tests := []struct {
		name            string
		claims          *TokenClaims
		required        []string
		wantErr         bool
		wantErrContains string
	}{
		{
			name: "has all required scopes",
			claims: &TokenClaims{
				Scopes: []string{"mcp:read", "mcp:write", "mcp:admin"},
			},
			required: []string{"mcp:read", "mcp:write"},
			wantErr:  false,
		},
		{
			name: "has exact required scopes",
			claims: &TokenClaims{
				Scopes: []string{"mcp:read", "mcp:write"},
			},
			required: []string{"mcp:read", "mcp:write"},
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
				Scopes: []string{"other:scope"},
			},
			required:        []string{"mcp:read", "mcp:write"},
			wantErr:         true,
			wantErrContains: "insufficient_scope",
		},
		{
			name: "empty token scopes",
			claims: &TokenClaims{
				Scopes: []string{},
			},
			required:        []string{"mcp:read"},
			wantErr:         true,
			wantErrContains: "insufficient_scope",
		},
		{
			name: "nil token scopes",
			claims: &TokenClaims{
				Scopes: nil,
			},
			required:        []string{"mcp:read"},
			wantErr:         true,
			wantErrContains: "insufficient_scope",
		},
		{
			name:            "nil claims",
			claims:          nil,
			required:        []string{"mcp:read"},
			wantErr:         true,
			wantErrContains: "insufficient_scope",
		},
		{
			name: "no scopes required with scopes present",
			claims: &TokenClaims{
				Scopes: []string{"mcp:read"},
			},
			required: []string{},
			wantErr:  false,
		},
		{
			name: "single scope required and present",
			claims: &TokenClaims{
				Scopes: []string{"mcp:read"},
			},
			required: []string{"mcp:read"},
			wantErr:  false,
		},
		{
			name: "multiple scopes all present",
			claims: &TokenClaims{
				Scopes: []string{"mcp:read", "mcp:write", "mcp:delete", "mcp:admin"},
			},
			required: []string{"mcp:read", "mcp:write", "mcp:delete"},
			wantErr:  false,
		},
		{
			name: "case sensitive scope check",
			claims: &TokenClaims{
				Scopes: []string{"mcp:Read"},
			},
			required:        []string{"mcp:read"},
			wantErr:         true,
			wantErrContains: "insufficient_scope",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := checker.RequireScopes(tt.claims, tt.required...)

			if tt.wantErr {
				if err == nil {
					t.Fatal("RequireScopes() expected error, got nil")
				}
				if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.wantErrContains)) {
					t.Errorf("RequireScopes() error = %q, want to contain %q", err.Error(), tt.wantErrContains)
				}
			} else {
				if err != nil {
					t.Fatalf("RequireScopes() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestScopeChecker_RequireAnyScope(t *testing.T) {
	t.Parallel()

	checker := NewScopeChecker()

	tests := []struct {
		name            string
		claims          *TokenClaims
		scopes          []string
		wantErr         bool
		wantErrContains string
	}{
		{
			name: "has one of required scopes",
			claims: &TokenClaims{
				Scopes: []string{"mcp:read"},
			},
			scopes:  []string{"mcp:read", "mcp:write"},
			wantErr: false,
		},
		{
			name: "has multiple of required scopes",
			claims: &TokenClaims{
				Scopes: []string{"mcp:read", "mcp:write"},
			},
			scopes:  []string{"mcp:read", "mcp:write"},
			wantErr: false,
		},
		{
			name: "has all of required scopes",
			claims: &TokenClaims{
				Scopes: []string{"mcp:read", "mcp:write", "mcp:admin"},
			},
			scopes:  []string{"mcp:read", "mcp:write"},
			wantErr: false,
		},
		{
			name: "has none of required scopes",
			claims: &TokenClaims{
				Scopes: []string{"other:scope"},
			},
			scopes:          []string{"mcp:read", "mcp:write"},
			wantErr:         true,
			wantErrContains: "insufficient_scope",
		},
		{
			name: "empty token scopes",
			claims: &TokenClaims{
				Scopes: []string{},
			},
			scopes:          []string{"mcp:read"},
			wantErr:         true,
			wantErrContains: "insufficient_scope",
		},
		{
			name: "nil token scopes",
			claims: &TokenClaims{
				Scopes: nil,
			},
			scopes:          []string{"mcp:read"},
			wantErr:         true,
			wantErrContains: "insufficient_scope",
		},
		{
			name:            "nil claims",
			claims:          nil,
			scopes:          []string{"mcp:read"},
			wantErr:         true,
			wantErrContains: "insufficient_scope",
		},
		{
			name: "no scopes required",
			claims: &TokenClaims{
				Scopes: []string{"mcp:read"},
			},
			scopes:          []string{},
			wantErr:         true,
			wantErrContains: "insufficient_scope",
		},
		{
			name: "single scope required and present",
			claims: &TokenClaims{
				Scopes: []string{"mcp:read"},
			},
			scopes:  []string{"mcp:read"},
			wantErr: false,
		},
		{
			name: "last scope in list matches",
			claims: &TokenClaims{
				Scopes: []string{"mcp:admin"},
			},
			scopes:  []string{"mcp:read", "mcp:write", "mcp:admin"},
			wantErr: false,
		},
		{
			name: "case sensitive scope check",
			claims: &TokenClaims{
				Scopes: []string{"mcp:Read"},
			},
			scopes:          []string{"mcp:read"},
			wantErr:         true,
			wantErrContains: "insufficient_scope",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := checker.RequireAnyScope(tt.claims, tt.scopes...)

			if tt.wantErr {
				if err == nil {
					t.Fatal("RequireAnyScope() expected error, got nil")
				}
				if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.wantErrContains)) {
					t.Errorf("RequireAnyScope() error = %q, want to contain %q", err.Error(), tt.wantErrContains)
				}
			} else {
				if err != nil {
					t.Fatalf("RequireAnyScope() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestTokenClaims_HasScope(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		claims   *TokenClaims
		scope    string
		expected bool
	}{
		{
			name: "scope present",
			claims: &TokenClaims{
				Scopes: []string{"mcp:read", "mcp:write"},
			},
			scope:    "mcp:read",
			expected: true,
		},
		{
			name: "scope not present",
			claims: &TokenClaims{
				Scopes: []string{"mcp:read"},
			},
			scope:    "mcp:write",
			expected: false,
		},
		{
			name: "empty scopes",
			claims: &TokenClaims{
				Scopes: []string{},
			},
			scope:    "mcp:read",
			expected: false,
		},
		{
			name: "nil scopes",
			claims: &TokenClaims{
				Scopes: nil,
			},
			scope:    "mcp:read",
			expected: false,
		},
		{
			name:     "nil claims",
			claims:   nil,
			scope:    "mcp:read",
			expected: false,
		},
		{
			name: "empty scope string",
			claims: &TokenClaims{
				Scopes: []string{"mcp:read"},
			},
			scope:    "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := tt.claims.HasScope(tt.scope)
			if result != tt.expected {
				t.Errorf("HasScope(%q) = %v, want %v", tt.scope, result, tt.expected)
			}
		})
	}
}

func TestTokenClaims_HasAnyScope(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		claims   *TokenClaims
		scopes   []string
		expected bool
	}{
		{
			name: "has one scope",
			claims: &TokenClaims{
				Scopes: []string{"mcp:read"},
			},
			scopes:   []string{"mcp:read", "mcp:write"},
			expected: true,
		},
		{
			name: "has multiple scopes",
			claims: &TokenClaims{
				Scopes: []string{"mcp:read", "mcp:write"},
			},
			scopes:   []string{"mcp:read", "mcp:write"},
			expected: true,
		},
		{
			name: "has no scopes",
			claims: &TokenClaims{
				Scopes: []string{"other:scope"},
			},
			scopes:   []string{"mcp:read", "mcp:write"},
			expected: false,
		},
		{
			name: "empty token scopes",
			claims: &TokenClaims{
				Scopes: []string{},
			},
			scopes:   []string{"mcp:read"},
			expected: false,
		},
		{
			name:     "nil claims",
			claims:   nil,
			scopes:   []string{"mcp:read"},
			expected: false,
		},
		{
			name: "empty required scopes",
			claims: &TokenClaims{
				Scopes: []string{"mcp:read"},
			},
			scopes:   []string{},
			expected: false,
		},
		{
			name: "nil required scopes",
			claims: &TokenClaims{
				Scopes: []string{"mcp:read"},
			},
			scopes:   nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := tt.claims.HasAnyScope(tt.scopes...)
			if result != tt.expected {
				t.Errorf("HasAnyScope(%v) = %v, want %v", tt.scopes, result, tt.expected)
			}
		})
	}
}

func TestTokenClaims_HasAllScopes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		claims   *TokenClaims
		scopes   []string
		expected bool
	}{
		{
			name: "has all scopes",
			claims: &TokenClaims{
				Scopes: []string{"mcp:read", "mcp:write", "mcp:admin"},
			},
			scopes:   []string{"mcp:read", "mcp:write"},
			expected: true,
		},
		{
			name: "has exact scopes",
			claims: &TokenClaims{
				Scopes: []string{"mcp:read", "mcp:write"},
			},
			scopes:   []string{"mcp:read", "mcp:write"},
			expected: true,
		},
		{
			name: "missing one scope",
			claims: &TokenClaims{
				Scopes: []string{"mcp:read"},
			},
			scopes:   []string{"mcp:read", "mcp:write"},
			expected: false,
		},
		{
			name: "missing all scopes",
			claims: &TokenClaims{
				Scopes: []string{"other:scope"},
			},
			scopes:   []string{"mcp:read", "mcp:write"},
			expected: false,
		},
		{
			name: "empty token scopes",
			claims: &TokenClaims{
				Scopes: []string{},
			},
			scopes:   []string{"mcp:read"},
			expected: false,
		},
		{
			name:     "nil claims",
			claims:   nil,
			scopes:   []string{"mcp:read"},
			expected: false,
		},
		{
			name: "empty required scopes",
			claims: &TokenClaims{
				Scopes: []string{"mcp:read"},
			},
			scopes:   []string{},
			expected: true,
		},
		{
			name:     "nil claims with empty required scopes",
			claims:   nil,
			scopes:   []string{},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := tt.claims.HasAllScopes(tt.scopes...)
			if result != tt.expected {
				t.Errorf("HasAllScopes(%v) = %v, want %v", tt.scopes, result, tt.expected)
			}
		})
	}
}

func TestNewScopeChecker(t *testing.T) {
	t.Parallel()

	checker := NewScopeChecker()
	if checker == nil {
		t.Fatal("NewScopeChecker() returned nil")
	}
}

func TestScopeChecker_Integration(t *testing.T) {
	t.Parallel()

	checker := NewScopeChecker()

	// Create a token with typical scopes
	claims := &TokenClaims{
		Subject:   "user123",
		Issuer:    "https://auth.example.com",
		Audience:  []string{"https://api.example.com"},
		Scopes:    []string{"mcp:read", "mcp:write"},
		ExpiresAt: time.Now().Add(1 * time.Hour),
		IssuedAt:  time.Now(),
		JTI:       "token-id-123",
	}

	// Test various scope requirement scenarios
	tests := []struct {
		name    string
		test    func() error
		wantErr bool
	}{
		{
			name: "require read scope - should pass",
			test: func() error {
				return checker.RequireScopes(claims, "mcp:read")
			},
			wantErr: false,
		},
		{
			name: "require read and write - should pass",
			test: func() error {
				return checker.RequireScopes(claims, "mcp:read", "mcp:write")
			},
			wantErr: false,
		},
		{
			name: "require admin - should fail",
			test: func() error {
				return checker.RequireScopes(claims, "mcp:admin")
			},
			wantErr: true,
		},
		{
			name: "require any of read or admin - should pass",
			test: func() error {
				return checker.RequireAnyScope(claims, "mcp:read", "mcp:admin")
			},
			wantErr: false,
		},
		{
			name: "require any of admin or delete - should fail",
			test: func() error {
				return checker.RequireAnyScope(claims, "mcp:admin", "mcp:delete")
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.test()
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func BenchmarkScopeChecker_RequireScopes(b *testing.B) {
	checker := NewScopeChecker()
	claims := &TokenClaims{
		Scopes: []string{"mcp:read", "mcp:write", "mcp:admin"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = checker.RequireScopes(claims, "mcp:read", "mcp:write")
	}
}

func BenchmarkScopeChecker_RequireAnyScope(b *testing.B) {
	checker := NewScopeChecker()
	claims := &TokenClaims{
		Scopes: []string{"mcp:read", "mcp:write", "mcp:admin"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = checker.RequireAnyScope(claims, "mcp:read", "mcp:write")
	}
}
