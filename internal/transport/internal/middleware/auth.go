// Package middleware provides HTTP middleware for the transport layer.
package middleware

import (
	"errors"
	"net/http"
	"strings"

	"github.com/jamesprial/mcp-oauth-2.1/internal/oauth"
	"github.com/jamesprial/mcp-oauth-2.1/internal/transport/transportcore"
	pkgoauth "github.com/jamesprial/mcp-oauth-2.1/pkg/oauth"
)

// authMiddleware implements transportcore.AuthMiddleware.
type authMiddleware struct {
	validator     oauth.TokenValidator
	responder     transportcore.ErrorResponder
	metadataURL   string
	defaultScopes []string
}

// NewAuthMiddleware creates OAuth authentication middleware.
// It validates Bearer tokens using the provided TokenValidator and stores
// validated claims in the request context.
func NewAuthMiddleware(
	validator oauth.TokenValidator,
	responder transportcore.ErrorResponder,
	metadataURL string,
	defaultScopes []string,
) transportcore.AuthMiddleware {
	if validator == nil {
		panic("validator cannot be nil")
	}
	if responder == nil {
		panic("responder cannot be nil")
	}

	return &authMiddleware{
		validator:     validator,
		responder:     responder,
		metadataURL:   metadataURL,
		defaultScopes: defaultScopes,
	}
}

// Authenticate validates the Bearer token and adds claims to context.
// It extracts the token from the Authorization header, validates it,
// and stores the claims in the request context for downstream handlers.
//
// Returns 401 Unauthorized with WWW-Authenticate header if validation fails.
func (m *authMiddleware) Authenticate() transportcore.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract token from Authorization header
			token, err := extractBearerToken(r)
			if err != nil {
				// Determine scope for WWW-Authenticate header
				scope := strings.Join(m.defaultScopes, " ")
				m.responder.Unauthorized(w, scope, err)
				return
			}

			// Validate token
			claims, err := m.validator.ValidateToken(r.Context(), token)
			if err != nil {
				// Token validation failed
				scope := strings.Join(m.defaultScopes, " ")
				m.responder.Unauthorized(w, scope, err)
				return
			}

			// Add claims to request context
			ctx := transportcore.ContextWithClaims(r.Context(), claims)
			r = r.WithContext(ctx)

			// Call next handler
			next.ServeHTTP(w, r)
		})
	}
}

// RequireScopes checks that the token has all required scopes.
// This middleware must be used after Authenticate() in the chain.
//
// Returns 403 Forbidden with WWW-Authenticate header if scopes are insufficient.
// Returns 401 Unauthorized if claims are missing from context.
func (m *authMiddleware) RequireScopes(scopes ...string) transportcore.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract claims from context
			claims, ok := transportcore.ClaimsFromContext(r.Context())
			if !ok || claims == nil {
				// Claims missing - authentication did not happen or failed
				// Return 401 to indicate authentication is required
				scope := strings.Join(m.defaultScopes, " ")
				m.responder.Unauthorized(w, scope, errors.New("authentication required"))
				return
			}

			// Check if token has all required scopes
			if !claims.HasAllScopes(scopes...) {
				m.responder.Forbidden(w, scopes, transportcore.ErrInsufficientScope)
				return
			}

			// Call next handler
			next.ServeHTTP(w, r)
		})
	}
}

// extractBearerToken extracts the Bearer token from the Authorization header.
// Returns an error if the header is missing or not in the correct format.
//
// Format: Authorization: Bearer <token>
func extractBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get(pkgoauth.HeaderAuthorization)
	if authHeader == "" {
		return "", transportcore.ErrMissingToken
	}

	// Split header into scheme and token
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 {
		return "", transportcore.ErrInvalidToken
	}

	// Verify scheme is "Bearer" (case-insensitive per RFC 6750)
	if !strings.EqualFold(parts[0], pkgoauth.BearerToken) {
		return "", transportcore.ErrInvalidToken
	}

	// Extract token
	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", transportcore.ErrMissingToken
	}

	return token, nil
}
