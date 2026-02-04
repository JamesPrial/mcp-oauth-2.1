// Package transportcore provides core types, interfaces, and primitives for the transport layer.
// This package exists to break import cycles between the transport package and its internal subpackages.
package transportcore

import (
	"context"
	"net/http"
)

// Middleware is a function that wraps an http.Handler.
// It can modify the request, response, or perform additional logic
// before or after calling the next handler in the chain.
type Middleware func(http.Handler) http.Handler

// Server manages the HTTP server lifecycle.
// Implementations must support graceful shutdown and provide
// access to the bound address after startup.
type Server interface {
	// Start begins serving HTTP requests on the configured address.
	// This is a blocking call that returns when the server stops
	// or encounters an error during startup.
	Start() error

	// Shutdown gracefully shuts down the server without interrupting
	// active connections. It waits for active connections to close
	// or the context to be cancelled/expired.
	Shutdown(ctx context.Context) error

	// Addr returns the address the server is listening on.
	// This is useful when the server is configured to bind to a random port.
	Addr() string
}

// Router handles HTTP request routing and middleware composition.
// It extends http.Handler with pattern-based routing and middleware support.
type Router interface {
	http.Handler

	// Handle registers a handler for the given pattern.
	// The pattern syntax follows http.ServeMux conventions.
	Handle(pattern string, handler http.Handler)

	// HandleFunc registers a handler function for the given pattern.
	HandleFunc(pattern string, handler http.HandlerFunc)

	// Use applies middleware to all subsequent route registrations.
	// Middleware is applied in the order registered.
	Use(middlewares ...Middleware)
}

// AuthMiddleware provides OAuth token validation middleware.
// It validates Bearer tokens and enforces scope requirements
// according to OAuth 2.1 and RFC 6750.
type AuthMiddleware interface {
	// Authenticate validates the Bearer token and adds claims to context.
	// It extracts the token from the Authorization header, validates it
	// using the TokenValidator, and stores the claims in the request context.
	//
	// Returns 401 Unauthorized with WWW-Authenticate header if validation fails.
	Authenticate() Middleware

	// RequireScopes checks that the token has all required scopes.
	// This middleware must be used after Authenticate() in the chain.
	//
	// Returns 403 Forbidden with WWW-Authenticate header if scopes are insufficient.
	RequireScopes(scopes ...string) Middleware
}

// ErrorResponder handles OAuth-compliant error responses.
// It formats HTTP responses according to RFC 6750 (Bearer Token Usage)
// and RFC 9728 (Protected Resource Metadata).
type ErrorResponder interface {
	// Unauthorized sends a 401 Unauthorized response with WWW-Authenticate header.
	// The header includes the resource metadata URL and required scope.
	//
	// Format: WWW-Authenticate: Bearer resource_metadata="<url>", scope="<scope>"
	Unauthorized(w http.ResponseWriter, scope string, err error)

	// Forbidden sends a 403 Forbidden response with WWW-Authenticate header
	// for insufficient scope errors per RFC 6750 Section 3.1.
	//
	// Format: WWW-Authenticate: Bearer error="insufficient_scope", scope="<scopes>", resource_metadata="<url>"
	Forbidden(w http.ResponseWriter, requiredScopes []string, err error)

	// InternalError sends a 500 Internal Server Error response.
	// The response body contains a JSON error message.
	InternalError(w http.ResponseWriter, err error)

	// BadRequest sends a 400 Bad Request response.
	// The response body contains a JSON error message.
	BadRequest(w http.ResponseWriter, err error)
}
