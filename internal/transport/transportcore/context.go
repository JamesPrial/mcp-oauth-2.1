package transportcore

import (
	"context"

	"github.com/jamesprial/mcp-oauth-2.1/internal/oauth"
)

// contextKey is a custom type for context keys to avoid collisions.
type contextKey string

const (
	// ClaimsContextKey is the context key for OAuth token claims.
	ClaimsContextKey contextKey = "oauth_claims"
)

// ClaimsFromContext extracts OAuth claims from the request context.
// Returns nil and false if the claims are not present in the context.
//
// This is used by handlers that need to access authenticated user information.
func ClaimsFromContext(ctx context.Context) (*oauth.TokenClaims, bool) {
	if ctx == nil {
		return nil, false
	}
	claims, ok := ctx.Value(ClaimsContextKey).(*oauth.TokenClaims)
	return claims, ok
}

// ContextWithClaims adds OAuth claims to the request context.
// Returns a new context containing the claims.
//
// This is used by authentication middleware to store validated claims.
func ContextWithClaims(ctx context.Context, claims *oauth.TokenClaims) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, ClaimsContextKey, claims)
}
