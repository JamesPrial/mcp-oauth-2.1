package transportcore

import (
	"errors"
)

// Sentinel errors for transport operations.
// These are used for error identification and testing.
// For creating domain errors with context, wrap these with DomainError from internal/errors.
var (
	// ErrMissingToken indicates the Authorization header is missing or empty.
	ErrMissingToken = errors.New("missing authorization token")

	// ErrInvalidToken indicates the token format is invalid (not a Bearer token).
	ErrInvalidToken = errors.New("invalid authorization token")

	// ErrInsufficientScope indicates the token lacks required scope(s).
	ErrInsufficientScope = errors.New("insufficient scope")

	// ErrMethodNotAllowed indicates the HTTP method is not allowed for the endpoint.
	ErrMethodNotAllowed = errors.New("method not allowed")

	// ErrServerClosed indicates the server has been closed and cannot accept requests.
	ErrServerClosed = errors.New("server closed")
)
