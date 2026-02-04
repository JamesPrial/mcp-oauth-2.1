package transport

import (
	"github.com/jamesprial/mcp-oauth-2.1/internal/transport/transportcore"
)

// Re-export errors from transportcore for backward compatibility.
// This allows external packages to import transport without creating cycles.
var (
	// ErrMissingToken indicates the Authorization header is missing or empty.
	ErrMissingToken = transportcore.ErrMissingToken

	// ErrInvalidToken indicates the token format is invalid (not a Bearer token).
	ErrInvalidToken = transportcore.ErrInvalidToken

	// ErrInsufficientScope indicates the token lacks required scope(s).
	ErrInsufficientScope = transportcore.ErrInsufficientScope

	// ErrMethodNotAllowed indicates the HTTP method is not allowed for the endpoint.
	ErrMethodNotAllowed = transportcore.ErrMethodNotAllowed

	// ErrServerClosed indicates the server has been closed and cannot accept requests.
	ErrServerClosed = transportcore.ErrServerClosed
)
