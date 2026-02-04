// Package oauth provides shared OAuth 2.1 types and constants for the MCP server.
package oauth

// OAuth 2.1 scope constants for MCP operations.
const (
	// ScopeRead allows reading MCP resources.
	ScopeRead = "mcp:read"

	// ScopeWrite allows modifying MCP resources.
	ScopeWrite = "mcp:write"

	// ScopeAdmin allows administrative operations on MCP resources.
	ScopeAdmin = "mcp:admin"
)

// Token type constants as defined in RFC 6750.
const (
	// BearerToken is the OAuth 2.1 Bearer token type.
	BearerToken = "Bearer"

	// TokenTypeBearer is an alias for BearerToken.
	TokenTypeBearer = "Bearer"
)

// Grant types as defined in OAuth 2.1.
const (
	// GrantTypeAuthorizationCode is the authorization code grant type.
	GrantTypeAuthorizationCode = "authorization_code"

	// GrantTypeRefreshToken is the refresh token grant type.
	GrantTypeRefreshToken = "refresh_token"

	// GrantTypeClientCredentials is the client credentials grant type.
	GrantTypeClientCredentials = "client_credentials"
)

// Response types as defined in OAuth 2.1.
const (
	// ResponseTypeCode is the authorization code response type.
	// OAuth 2.1 only supports the code response type (implicit grant is removed).
	ResponseTypeCode = "code"
)

// PKCE code challenge methods as defined in RFC 7636.
// OAuth 2.1 requires S256 only (plain method is prohibited).
const (
	// CodeChallengeMethodS256 is the SHA-256 code challenge method.
	// This is the only allowed method in OAuth 2.1.
	CodeChallengeMethodS256 = "S256"
)

// HTTP header names.
const (
	// HeaderAuthorization is the Authorization HTTP header name.
	HeaderAuthorization = "Authorization"

	// HeaderWWWAuthenticate is the WWW-Authenticate HTTP header name.
	HeaderWWWAuthenticate = "WWW-Authenticate"

	// HeaderContentType is the Content-Type HTTP header name.
	HeaderContentType = "Content-Type"
)

// Content type constants.
const (
	// ContentTypeJSON is the application/json content type.
	ContentTypeJSON = "application/json"

	// ContentTypeFormURLEncoded is the application/x-www-form-urlencoded content type.
	ContentTypeFormURLEncoded = "application/x-www-form-urlencoded"
)
