package errors

import (
	"fmt"
	"strings"
)

// OAuth 2.1 error codes as defined in RFC 6749 Section 5.2 and related RFCs.
const (
	// ErrorCodeInvalidToken indicates the access token is invalid, expired, or revoked.
	ErrorCodeInvalidToken = "invalid_token"

	// ErrorCodeInsufficientScope indicates the token lacks required scope(s).
	ErrorCodeInsufficientScope = "insufficient_scope"

	// ErrorCodeInvalidRequest indicates the request is malformed or missing required parameters.
	ErrorCodeInvalidRequest = "invalid_request"

	// OAuthErrorInvalidToken is an alias for ErrorCodeInvalidToken.
	OAuthErrorInvalidToken = "invalid_token"

	// OAuthErrorInsufficientScope is an alias for ErrorCodeInsufficientScope.
	OAuthErrorInsufficientScope = "insufficient_scope"

	// OAuthErrorInvalidRequest is an alias for ErrorCodeInvalidRequest.
	OAuthErrorInvalidRequest = "invalid_request"
)

// OAuthError represents an RFC 6749 compliant OAuth error response.
// It is used to format error responses and WWW-Authenticate header values.
type OAuthError struct {
	// ErrorCode is the OAuth error code (e.g., "invalid_token", "insufficient_scope").
	ErrorCode string

	// ErrorDescription is a human-readable description of the error.
	ErrorDescription string

	// ErrorURI is an optional URI for additional error information.
	ErrorURI string

	// Scope is the space-separated list of required scopes for WWW-Authenticate header.
	Scope string

	// ResourceMetadata is the URL to the protected resource metadata endpoint.
	ResourceMetadata string

	// Realm is the protection space for WWW-Authenticate header.
	Realm string
}

// Error implements the error interface.
func (e *OAuthError) Error() string {
	if e.ErrorDescription != "" {
		return fmt.Sprintf("%s: %s", e.ErrorCode, e.ErrorDescription)
	}
	return e.ErrorCode
}

// NewOAuthError creates a new OAuthError with the given error code and description.
func NewOAuthError(errorCode, errorDescription string) *OAuthError {
	return &OAuthError{
		ErrorCode:        errorCode,
		ErrorDescription: errorDescription,
	}
}

// WithScope sets the scope field and returns the error for chaining.
func (e *OAuthError) WithScope(scope string) *OAuthError {
	e.Scope = scope
	return e
}

// WithResourceMetadata sets the resource metadata URL and returns the error for chaining.
func (e *OAuthError) WithResourceMetadata(url string) *OAuthError {
	e.ResourceMetadata = url
	return e
}

// WWWAuthenticate formats the OAuthError as a WWW-Authenticate header value
// per RFC 6750. It returns a properly formatted header with Bearer scheme
// and comma-separated parameters.
//
// Example output:
//
//	Bearer realm="mcp-server", error="invalid_token", error_description="Token expired", scope="mcp:read", resource_metadata="https://example.com/.well-known/oauth-protected-resource"
func (e *OAuthError) WWWAuthenticate() string {
	var parts []string

	// Add realm if present
	if e.Realm != "" {
		parts = append(parts, fmt.Sprintf(`realm="%s"`, escapeQuotes(e.Realm)))
	}

	// Add error code if present
	if e.ErrorCode != "" {
		parts = append(parts, fmt.Sprintf(`error="%s"`, escapeQuotes(e.ErrorCode)))
	}

	// Add error description if present
	if e.ErrorDescription != "" {
		parts = append(parts, fmt.Sprintf(`error_description="%s"`, escapeQuotes(e.ErrorDescription)))
	}

	// Add error URI if present
	if e.ErrorURI != "" {
		parts = append(parts, fmt.Sprintf(`error_uri="%s"`, escapeQuotes(e.ErrorURI)))
	}

	// Add scope if present
	if e.Scope != "" {
		parts = append(parts, fmt.Sprintf(`scope="%s"`, escapeQuotes(e.Scope)))
	}

	// Add resource metadata if present
	if e.ResourceMetadata != "" {
		parts = append(parts, fmt.Sprintf(`resource_metadata="%s"`, escapeQuotes(e.ResourceMetadata)))
	}

	// Join parts with ", " and prepend "Bearer "
	if len(parts) == 0 {
		return "Bearer"
	}
	return "Bearer " + strings.Join(parts, ", ")
}

// WWWAuthenticateHeader formats the OAuthError as a WWW-Authenticate header value
// for use in 401 Unauthorized or 403 Forbidden responses.
//
// Additional parameters can be provided as key-value pairs:
//   - scope: space-separated list of required scopes
//   - resource_metadata: URL to the protected resource metadata endpoint
//
// Example output:
//
//	Bearer error="invalid_token", error_description="Token expired", scope="mcp:read"
func (e *OAuthError) WWWAuthenticateHeader(additionalParams map[string]string) string {
	var parts []string

	// Always start with "Bearer"
	parts = append(parts, "Bearer")

	// Add error code
	parts = append(parts, fmt.Sprintf(`error="%s"`, e.ErrorCode))

	// Add error description if present
	if e.ErrorDescription != "" {
		parts = append(parts, fmt.Sprintf(`error_description="%s"`, escapeQuotes(e.ErrorDescription)))
	}

	// Add error URI if present
	if e.ErrorURI != "" {
		parts = append(parts, fmt.Sprintf(`error_uri="%s"`, e.ErrorURI))
	}

	// Add additional parameters (scope, resource_metadata, etc.)
	for key, value := range additionalParams {
		if value != "" {
			parts = append(parts, fmt.Sprintf(`%s="%s"`, key, escapeQuotes(value)))
		}
	}

	return strings.Join(parts, " ")
}

// escapeQuotes escapes double quotes in strings for use in header values.
func escapeQuotes(s string) string {
	return strings.ReplaceAll(s, `"`, `\"`)
}
