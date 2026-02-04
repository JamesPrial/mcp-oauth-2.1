// Package transport provides HTTP transport layer for the OAuth 2.1 MCP server.
// It ties OAuth validation to MCP protocol handling through HTTP middleware
// and handlers compliant with RFC 9728 (Protected Resource Metadata).
package transport

import (
	"github.com/jamesprial/mcp-oauth-2.1/internal/transport/transportcore"
)

// Re-export types from transportcore for backward compatibility.
// This allows external packages to import transport without creating cycles.

// Middleware is a function that wraps an http.Handler.
// It can modify the request, response, or perform additional logic
// before or after calling the next handler in the chain.
type Middleware = transportcore.Middleware

// Server manages the HTTP server lifecycle.
// Implementations must support graceful shutdown and provide
// access to the bound address after startup.
type Server = transportcore.Server

// Router handles HTTP request routing and middleware composition.
// It extends http.Handler with pattern-based routing and middleware support.
type Router = transportcore.Router

// AuthMiddleware provides OAuth token validation middleware.
// It validates Bearer tokens and enforces scope requirements
// according to OAuth 2.1 and RFC 6750.
type AuthMiddleware = transportcore.AuthMiddleware

// ErrorResponder handles OAuth-compliant error responses.
// It formats HTTP responses according to RFC 6750 (Bearer Token Usage)
// and RFC 9728 (Protected Resource Metadata).
type ErrorResponder = transportcore.ErrorResponder
