package mcp

import (
	"errors"
)

// Sentinel errors for MCP operations.
// These are used for error identification and testing.
// For creating domain errors with context, wrap these with DomainError from internal/errors.
var (
	// ErrInvalidRequest indicates the JSON-RPC request is invalid or malformed.
	ErrInvalidRequest = errors.New("invalid request")

	// ErrMethodNotFound indicates the requested JSON-RPC method does not exist.
	ErrMethodNotFound = errors.New("method not found")

	// ErrInvalidParams indicates the method parameters are invalid.
	ErrInvalidParams = errors.New("invalid params")

	// ErrToolNotFound indicates the requested tool does not exist.
	ErrToolNotFound = errors.New("tool not found")

	// ErrToolAlreadyRegistered indicates a tool with the same name is already registered.
	ErrToolAlreadyRegistered = errors.New("tool already registered")

	// ErrToolExecutionFailed indicates the tool execution encountered an error.
	ErrToolExecutionFailed = errors.New("tool execution failed")

	// ErrResourceNotFound indicates the requested resource does not exist.
	ErrResourceNotFound = errors.New("resource not found")

	// ErrResourceAlreadyRegistered indicates a resource with the same URI is already registered.
	ErrResourceAlreadyRegistered = errors.New("resource already registered")

	// ErrResourceReadFailed indicates reading the resource content failed.
	ErrResourceReadFailed = errors.New("resource read failed")

	// ErrParseError indicates the JSON-RPC request could not be parsed.
	ErrParseError = errors.New("parse error")

	// ErrInternalError indicates an internal server error occurred.
	ErrInternalError = errors.New("internal error")
)
