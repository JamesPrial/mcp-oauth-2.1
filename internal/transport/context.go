package transport

import (
	"context"

	"github.com/jamesprial/mcp-oauth-2.1/internal/oauth"
	"github.com/jamesprial/mcp-oauth-2.1/internal/transport/transportcore"
)

// Re-export context key and helpers from transportcore for backward compatibility.
// This allows external packages to import transport without creating cycles.

// ClaimsContextKey is the context key for OAuth token claims.
const ClaimsContextKey = transportcore.ClaimsContextKey

// ClaimsFromContext extracts OAuth claims from the request context.
// Returns nil and false if the claims are not present in the context.
//
// This is used by handlers that need to access authenticated user information.
func ClaimsFromContext(ctx context.Context) (*oauth.TokenClaims, bool) {
	return transportcore.ClaimsFromContext(ctx)
}

// ContextWithClaims adds OAuth claims to the request context.
// Returns a new context containing the claims.
//
// This is used by authentication middleware to store validated claims.
func ContextWithClaims(ctx context.Context, claims *oauth.TokenClaims) context.Context {
	return transportcore.ContextWithClaims(ctx, claims)
}
