// Package oauth provides OAuth 2.1 token validation and protected resource
// metadata services for the MCP server acting as a Resource Server.
package oauth

import (
	"context"
	"time"
)

// TokenValidator validates OAuth 2.1 access tokens.
// Implementations must verify token signatures, expiration, audience,
// and other security-critical claims per OAuth 2.1 Section 5.2.
type TokenValidator interface {
	// ValidateToken validates an access token and returns the parsed claims.
	// It verifies the token signature using JWKS from the issuing authorization server,
	// checks expiration with clock skew tolerance, validates the audience matches
	// this resource server, and ensures the token is valid per OAuth 2.1.
	//
	// Returns ErrUnauthorized from internal/errors if the token is invalid.
	ValidateToken(ctx context.Context, token string) (*TokenClaims, error)
}

// TokenClaims represents validated JWT claims from an access token.
// All fields are populated from the token after successful validation.
type TokenClaims struct {
	// Subject is the subject (sub) claim - typically the user identifier.
	Subject string

	// Issuer is the issuer (iss) claim - the authorization server that issued the token.
	Issuer string

	// Audience is the audience (aud) claim - the intended recipient(s) of the token.
	// For this resource server, must contain this server's canonical URI.
	Audience []string

	// Scopes is the list of OAuth scopes granted by this token.
	// Parsed from the "scope" claim (space-separated string).
	Scopes []string

	// ExpiresAt is the expiration time (exp) claim.
	ExpiresAt time.Time

	// IssuedAt is the issued at (iat) claim.
	IssuedAt time.Time

	// JTI is the JWT ID (jti) claim - a unique identifier for this token.
	JTI string
}

// HasScope returns true if the token has the specified scope.
func (c *TokenClaims) HasScope(scope string) bool {
	if c == nil {
		return false
	}
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// HasAnyScope returns true if the token has any of the specified scopes.
// Returns false if the token has none of the required scopes or if scopes is empty.
func (c *TokenClaims) HasAnyScope(scopes ...string) bool {
	if c == nil || len(scopes) == 0 {
		return false
	}
	for _, required := range scopes {
		if c.HasScope(required) {
			return true
		}
	}
	return false
}

// HasAllScopes returns true if the token has all specified scopes.
// Returns true if scopes is empty (vacuous truth).
func (c *TokenClaims) HasAllScopes(scopes ...string) bool {
	if c == nil {
		return len(scopes) == 0
	}
	for _, required := range scopes {
		if !c.HasScope(required) {
			return false
		}
	}
	return true
}

// MetadataService provides Protected Resource Metadata per RFC 9728.
// This metadata helps clients discover the authorization servers and
// supported scopes for this protected resource.
type MetadataService interface {
	// GetMetadata returns the protected resource metadata document.
	// The metadata includes authorization servers, supported scopes,
	// and other discovery information per RFC 9728.
	GetMetadata(ctx context.Context) (*ProtectedResourceMetadata, error)

	// GetMetadataURL returns the canonical URL where this metadata is served.
	// Typically: {baseURL}/.well-known/oauth-protected-resource
	GetMetadataURL() string
}

// ProtectedResourceMetadata represents the OAuth 2.0 Protected Resource
// Metadata as defined in RFC 9728. This metadata is served at the
// /.well-known/oauth-protected-resource endpoint to aid client discovery.
type ProtectedResourceMetadata struct {
	// Resource is the canonical URI for this protected resource.
	// This value must match the "aud" (audience) claim in access tokens.
	Resource string `json:"resource"`

	// AuthorizationServers is an array of authorization server URLs that can
	// issue tokens for this resource. At least one server must be listed.
	AuthorizationServers []string `json:"authorization_servers"`

	// ScopesSupported is an optional array of OAuth scope values supported
	// by this protected resource. Recommended for client discovery.
	ScopesSupported []string `json:"scopes_supported,omitempty"`

	// BearerMethodsSupported indicates supported methods for presenting
	// bearer tokens. OAuth 2.1 requires "header" (Authorization header only).
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`
}

// JWKSClient fetches and caches JSON Web Key Sets (JWKS) from authorization servers.
// The client maintains an in-memory cache with TTL to minimize network requests
// while ensuring key rotation is respected.
type JWKSClient interface {
	// GetKey retrieves a public key for the given key ID (kid).
	// It first checks the cache, and if not found or expired, fetches
	// the JWKS from the authorization server.
	//
	// Returns the public key (typically *rsa.PublicKey or *ecdsa.PublicKey)
	// suitable for JWT signature verification.
	GetKey(ctx context.Context, keyID string) (any, error)

	// RefreshKeys forces a refresh of the JWKS cache from all configured
	// authorization servers. This is useful after receiving an "invalid_token"
	// error that might be due to key rotation.
	RefreshKeys(ctx context.Context) error
}

// ScopeChecker validates token scopes against required scopes.
// It provides methods for both "all required" and "any required" scope checks,
// returning appropriate OAuth errors per RFC 6750.
type ScopeChecker interface {
	// RequireScopes checks that the token has all of the specified scopes.
	// Returns an "insufficient_scope" error from internal/errors if any
	// required scope is missing.
	RequireScopes(claims *TokenClaims, required ...string) error

	// RequireAnyScope checks that the token has at least one of the specified scopes.
	// Returns an "insufficient_scope" error from internal/errors if none of
	// the scopes are present.
	RequireAnyScope(claims *TokenClaims, scopes ...string) error
}
