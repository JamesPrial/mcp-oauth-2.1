// Package errors provides domain-specific error handling infrastructure
// for the OAuth 2.1 MCP server.
package errors

import (
	"errors"
	"fmt"
)

// Sentinel errors for common error conditions.
var (
	// ErrNotFound indicates a requested resource was not found.
	ErrNotFound = errors.New("not found")

	// ErrUnauthorized indicates authentication is required or failed.
	ErrUnauthorized = errors.New("unauthorized")

	// ErrForbidden indicates the authenticated user lacks permission.
	ErrForbidden = errors.New("forbidden")

	// ErrBadRequest indicates invalid request parameters or format.
	ErrBadRequest = errors.New("bad request")

	// ErrInternal indicates an internal server error.
	ErrInternal = errors.New("internal error")
)

// DomainError represents a domain-specific error with context.
// It wraps an underlying error and provides additional metadata
// about the domain, operation, and contextual information.
type DomainError struct {
	// Domain identifies the subsystem where the error occurred (e.g., "oauth", "mcp").
	Domain string

	// Op identifies the operation that failed (e.g., "ValidateToken", "HandleRequest").
	Op string

	// Kind is the sentinel error that categorizes this error.
	Kind error

	// Err is the underlying wrapped error, if any.
	Err error

	// Context provides additional key-value pairs for debugging.
	Context map[string]interface{}
}

// New creates a new DomainError.
//
// Parameters:
//   - domain: the subsystem identifier (e.g., "oauth", "mcp")
//   - op: the operation that failed
//   - kind: sentinel error indicating the error category
//   - err: underlying error to wrap (may be nil)
func New(domain, op string, kind, err error) *DomainError {
	return &DomainError{
		Domain:  domain,
		Op:      op,
		Kind:    kind,
		Err:     err,
		Context: make(map[string]interface{}),
	}
}

// Error implements the error interface.
func (e *DomainError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s.%s: %v: %v", e.Domain, e.Op, e.Kind, e.Err)
	}
	return fmt.Sprintf("%s.%s: %v", e.Domain, e.Op, e.Kind)
}

// Unwrap returns the underlying wrapped error.
// This allows errors.Is and errors.As to work correctly.
func (e *DomainError) Unwrap() error {
	return e.Err
}

// Is reports whether this error matches the target error.
// It checks both the Kind field and the wrapped error chain.
func (e *DomainError) Is(target error) bool {
	if e.Kind != nil && errors.Is(e.Kind, target) {
		return true
	}
	if e.Err != nil && errors.Is(e.Err, target) {
		return true
	}
	return false
}

// WithContext adds a key-value pair to the error's context and returns the error.
// This allows for method chaining when adding context to errors.
func (e *DomainError) WithContext(key string, value interface{}) *DomainError {
	if e.Context == nil {
		e.Context = make(map[string]interface{})
	}
	e.Context[key] = value
	return e
}
