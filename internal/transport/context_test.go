// Package transport provides HTTP transport layer for the MCP server.
package transport

import (
	"context"
	"testing"
	"time"

	"github.com/jamesprial/mcp-oauth-2.1/internal/oauth"
)

func TestClaimsFromContext(t *testing.T) {
	t.Parallel()

	// Custom key type for testing - demonstrates type-safe context keys
	type testContextKey string

	tests := []struct {
		name       string
		setupCtx   func() context.Context
		wantClaims *oauth.TokenClaims
		wantOK     bool
	}{
		{
			name: "claims present in context",
			setupCtx: func() context.Context {
				claims := &oauth.TokenClaims{
					Subject:   "user123",
					Issuer:    "https://auth.example.com",
					Audience:  []string{"https://api.example.com"},
					Scopes:    []string{"mcp:read", "mcp:write"},
					ExpiresAt: time.Now().Add(time.Hour),
					IssuedAt:  time.Now(),
					JTI:       "token-id-123",
				}
				return ContextWithClaims(context.Background(), claims)
			},
			wantClaims: &oauth.TokenClaims{
				Subject:  "user123",
				Issuer:   "https://auth.example.com",
				Audience: []string{"https://api.example.com"},
				Scopes:   []string{"mcp:read", "mcp:write"},
				JTI:      "token-id-123",
			},
			wantOK: true,
		},
		{
			name: "claims absent from context",
			setupCtx: func() context.Context {
				return context.Background()
			},
			wantClaims: nil,
			wantOK:     false,
		},
		{
			name: "empty context with values",
			setupCtx: func() context.Context {
				// Context with other values but no claims
				return context.WithValue(context.Background(), testContextKey("other-key"), "other-value")
			},
			wantClaims: nil,
			wantOK:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := tt.setupCtx()
			gotClaims, gotOK := ClaimsFromContext(ctx)

			if gotOK != tt.wantOK {
				t.Errorf("ClaimsFromContext() ok = %v, want %v", gotOK, tt.wantOK)
				return
			}

			if tt.wantOK {
				if gotClaims == nil {
					t.Error("ClaimsFromContext() claims = nil, want non-nil")
					return
				}
				// Verify key fields match (not comparing time fields exactly)
				if gotClaims.Subject != tt.wantClaims.Subject {
					t.Errorf("ClaimsFromContext() Subject = %v, want %v", gotClaims.Subject, tt.wantClaims.Subject)
				}
				if gotClaims.Issuer != tt.wantClaims.Issuer {
					t.Errorf("ClaimsFromContext() Issuer = %v, want %v", gotClaims.Issuer, tt.wantClaims.Issuer)
				}
				if gotClaims.JTI != tt.wantClaims.JTI {
					t.Errorf("ClaimsFromContext() JTI = %v, want %v", gotClaims.JTI, tt.wantClaims.JTI)
				}
			} else {
				if gotClaims != nil {
					t.Errorf("ClaimsFromContext() claims = %v, want nil", gotClaims)
				}
			}
		})
	}
}

func TestClaimsFromContext_NilContext(t *testing.T) {
	t.Parallel()

	// This test verifies the function handles nil context gracefully
	// The behavior depends on implementation - it should either:
	// 1. Return (nil, false) without panic
	// 2. Panic (which would be caught by this test failing)
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("ClaimsFromContext() panicked with nil context: %v", r)
		}
	}()

	//nolint:staticcheck // intentionally passing nil context to test nil safety
	claims, ok := ClaimsFromContext(nil)
	if ok {
		t.Error("ClaimsFromContext(nil) ok = true, want false")
	}
	if claims != nil {
		t.Errorf("ClaimsFromContext(nil) claims = %v, want nil", claims)
	}
}

func TestContextWithClaims(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		claims *oauth.TokenClaims
	}{
		{
			name: "add valid claims to context",
			claims: &oauth.TokenClaims{
				Subject:   "user456",
				Issuer:    "https://auth.example.com",
				Audience:  []string{"https://api.example.com"},
				Scopes:    []string{"mcp:read"},
				ExpiresAt: time.Now().Add(time.Hour),
				IssuedAt:  time.Now(),
				JTI:       "token-456",
			},
		},
		{
			name: "add claims with minimal fields",
			claims: &oauth.TokenClaims{
				Subject: "minimal-user",
			},
		},
		{
			name: "add claims with empty scopes",
			claims: &oauth.TokenClaims{
				Subject: "no-scopes-user",
				Scopes:  []string{},
			},
		},
		{
			name: "add claims with multiple audiences",
			claims: &oauth.TokenClaims{
				Subject:  "multi-aud-user",
				Audience: []string{"aud1", "aud2", "aud3"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			newCtx := ContextWithClaims(ctx, tt.claims)

			if newCtx == nil {
				t.Fatal("ContextWithClaims() returned nil context")
			}

			// Verify we can retrieve the claims
			gotClaims, ok := ClaimsFromContext(newCtx)
			if !ok {
				t.Error("ClaimsFromContext() after ContextWithClaims() returned ok = false")
				return
			}

			if gotClaims.Subject != tt.claims.Subject {
				t.Errorf("Retrieved claims Subject = %v, want %v", gotClaims.Subject, tt.claims.Subject)
			}
		})
	}
}

func TestContextWithClaims_NilClaims(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// Test with nil claims - behavior may vary:
	// Option 1: Stores nil, retrieval returns (nil, true)
	// Option 2: Does not store, retrieval returns (nil, false)
	// Both are acceptable; test verifies no panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("ContextWithClaims() panicked with nil claims: %v", r)
		}
	}()

	newCtx := ContextWithClaims(ctx, nil)
	if newCtx == nil {
		t.Error("ContextWithClaims() returned nil context")
	}
}

func TestContextWithClaims_OriginalContextUnmodified(t *testing.T) {
	t.Parallel()

	originalCtx := context.Background()
	claims := &oauth.TokenClaims{Subject: "test-user"}

	newCtx := ContextWithClaims(originalCtx, claims)

	// Original context should not have claims
	_, okOriginal := ClaimsFromContext(originalCtx)
	if okOriginal {
		t.Error("Original context was modified by ContextWithClaims()")
	}

	// New context should have claims
	_, okNew := ClaimsFromContext(newCtx)
	if !okNew {
		t.Error("New context does not have claims after ContextWithClaims()")
	}
}

func TestClaimsRoundTrip(t *testing.T) {
	t.Parallel()

	// Test that claims survive a round-trip through context
	originalClaims := &oauth.TokenClaims{
		Subject:   "roundtrip-user",
		Issuer:    "https://issuer.example.com",
		Audience:  []string{"https://resource.example.com"},
		Scopes:    []string{"scope1", "scope2", "scope3"},
		ExpiresAt: time.Now().Add(2 * time.Hour),
		IssuedAt:  time.Now().Add(-time.Minute),
		JTI:       "unique-jwt-id",
	}

	ctx := ContextWithClaims(context.Background(), originalClaims)
	retrievedClaims, ok := ClaimsFromContext(ctx)

	if !ok {
		t.Fatal("Failed to retrieve claims from context")
	}

	// Verify all fields
	if retrievedClaims.Subject != originalClaims.Subject {
		t.Errorf("Subject mismatch: got %v, want %v", retrievedClaims.Subject, originalClaims.Subject)
	}
	if retrievedClaims.Issuer != originalClaims.Issuer {
		t.Errorf("Issuer mismatch: got %v, want %v", retrievedClaims.Issuer, originalClaims.Issuer)
	}
	if len(retrievedClaims.Audience) != len(originalClaims.Audience) {
		t.Errorf("Audience length mismatch: got %v, want %v", len(retrievedClaims.Audience), len(originalClaims.Audience))
	}
	if len(retrievedClaims.Scopes) != len(originalClaims.Scopes) {
		t.Errorf("Scopes length mismatch: got %v, want %v", len(retrievedClaims.Scopes), len(originalClaims.Scopes))
	}
	if retrievedClaims.JTI != originalClaims.JTI {
		t.Errorf("JTI mismatch: got %v, want %v", retrievedClaims.JTI, originalClaims.JTI)
	}
}
