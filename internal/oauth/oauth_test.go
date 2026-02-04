// Package oauth provides the OAuth 2.1 implementation for the MCP server.
// This test file tests TokenClaims scope-checking functionality.
package oauth

import (
	"testing"
)

func TestTokenClaims_HasScope(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		claims *TokenClaims
		scope  string
		want   bool
	}{
		{
			name: "scope present in claims",
			claims: &TokenClaims{
				Scopes: []string{"read", "write"},
			},
			scope: "read",
			want:  true,
		},
		{
			name: "scope absent from claims",
			claims: &TokenClaims{
				Scopes: []string{"read"},
			},
			scope: "write",
			want:  false,
		},
		{
			name: "empty scopes list",
			claims: &TokenClaims{
				Scopes: []string{},
			},
			scope: "read",
			want:  false,
		},
		{
			name: "nil scopes list",
			claims: &TokenClaims{
				Scopes: nil,
			},
			scope: "read",
			want:  false,
		},
		{
			name:   "nil claims",
			claims: nil,
			scope:  "read",
			want:   false,
		},
		{
			name: "exact match required - partial match fails",
			claims: &TokenClaims{
				Scopes: []string{"mcp:read"},
			},
			scope: "mcp:read:extra",
			want:  false,
		},
		{
			name: "exact match required - prefix match fails",
			claims: &TokenClaims{
				Scopes: []string{"mcp:read:extra"},
			},
			scope: "mcp:read",
			want:  false,
		},
		{
			name: "empty scope string to check",
			claims: &TokenClaims{
				Scopes: []string{"read", ""},
			},
			scope: "",
			want:  true,
		},
		{
			name: "multiple scopes with exact match",
			claims: &TokenClaims{
				Scopes: []string{"mcp:read", "mcp:write", "mcp:admin"},
			},
			scope: "mcp:write",
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := tt.claims.HasScope(tt.scope)
			if got != tt.want {
				t.Errorf("HasScope(%q) = %v, want %v", tt.scope, got, tt.want)
			}
		})
	}
}

func TestTokenClaims_HasAnyScope(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		claims *TokenClaims
		scopes []string
		want   bool
	}{
		{
			name: "one scope matches",
			claims: &TokenClaims{
				Scopes: []string{"read"},
			},
			scopes: []string{"read", "write"},
			want:   true,
		},
		{
			name: "multiple scopes match",
			claims: &TokenClaims{
				Scopes: []string{"read", "write"},
			},
			scopes: []string{"read", "write"},
			want:   true,
		},
		{
			name: "no scopes match",
			claims: &TokenClaims{
				Scopes: []string{"delete"},
			},
			scopes: []string{"read", "write"},
			want:   false,
		},
		{
			name: "empty required scopes",
			claims: &TokenClaims{
				Scopes: []string{"read"},
			},
			scopes: []string{},
			want:   false,
		},
		{
			name: "empty claims scopes",
			claims: &TokenClaims{
				Scopes: []string{},
			},
			scopes: []string{"read", "write"},
			want:   false,
		},
		{
			name:   "nil claims",
			claims: nil,
			scopes: []string{"read"},
			want:   false,
		},
		{
			name: "nil required scopes",
			claims: &TokenClaims{
				Scopes: []string{"read"},
			},
			scopes: nil,
			want:   false,
		},
		{
			name: "first scope matches",
			claims: &TokenClaims{
				Scopes: []string{"admin"},
			},
			scopes: []string{"admin", "superadmin"},
			want:   true,
		},
		{
			name: "last scope matches",
			claims: &TokenClaims{
				Scopes: []string{"superadmin"},
			},
			scopes: []string{"admin", "superadmin"},
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := tt.claims.HasAnyScope(tt.scopes...)
			if got != tt.want {
				t.Errorf("HasAnyScope(%v) = %v, want %v", tt.scopes, got, tt.want)
			}
		})
	}
}

func TestTokenClaims_HasAllScopes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		claims *TokenClaims
		scopes []string
		want   bool
	}{
		{
			name: "all scopes present",
			claims: &TokenClaims{
				Scopes: []string{"read", "write"},
			},
			scopes: []string{"read", "write"},
			want:   true,
		},
		{
			name: "one scope missing",
			claims: &TokenClaims{
				Scopes: []string{"read"},
			},
			scopes: []string{"read", "write"},
			want:   false,
		},
		{
			name: "empty required scopes returns true",
			claims: &TokenClaims{
				Scopes: []string{"read"},
			},
			scopes: []string{},
			want:   true,
		},
		{
			name: "nil required scopes returns true",
			claims: &TokenClaims{
				Scopes: []string{"read"},
			},
			scopes: nil,
			want:   true,
		},
		{
			name: "claims have more scopes than required",
			claims: &TokenClaims{
				Scopes: []string{"read", "write", "admin"},
			},
			scopes: []string{"read", "write"},
			want:   true,
		},
		{
			name: "empty claims scopes",
			claims: &TokenClaims{
				Scopes: []string{},
			},
			scopes: []string{"read"},
			want:   false,
		},
		{
			name:   "nil claims",
			claims: nil,
			scopes: []string{"read"},
			want:   false,
		},
		{
			name: "all missing",
			claims: &TokenClaims{
				Scopes: []string{"delete"},
			},
			scopes: []string{"read", "write"},
			want:   false,
		},
		{
			name: "duplicate required scopes",
			claims: &TokenClaims{
				Scopes: []string{"read"},
			},
			scopes: []string{"read", "read"},
			want:   true,
		},
		{
			name: "order does not matter",
			claims: &TokenClaims{
				Scopes: []string{"write", "read"},
			},
			scopes: []string{"read", "write"},
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := tt.claims.HasAllScopes(tt.scopes...)
			if got != tt.want {
				t.Errorf("HasAllScopes(%v) = %v, want %v", tt.scopes, got, tt.want)
			}
		})
	}
}

// Benchmark tests for scope checking operations
func BenchmarkTokenClaims_HasScope(b *testing.B) {
	claims := &TokenClaims{
		Scopes: []string{"mcp:read", "mcp:write", "mcp:admin", "mcp:delete", "mcp:list"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = claims.HasScope("mcp:admin")
	}
}

func BenchmarkTokenClaims_HasAnyScope(b *testing.B) {
	claims := &TokenClaims{
		Scopes: []string{"mcp:read", "mcp:write", "mcp:admin", "mcp:delete", "mcp:list"},
	}
	required := []string{"mcp:super", "mcp:admin"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = claims.HasAnyScope(required...)
	}
}

func BenchmarkTokenClaims_HasAllScopes(b *testing.B) {
	claims := &TokenClaims{
		Scopes: []string{"mcp:read", "mcp:write", "mcp:admin", "mcp:delete", "mcp:list"},
	}
	required := []string{"mcp:read", "mcp:write", "mcp:admin"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = claims.HasAllScopes(required...)
	}
}
