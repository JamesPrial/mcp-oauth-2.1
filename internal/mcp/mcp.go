// Package mcp provides Model Context Protocol (MCP) server implementation
// with JSON-RPC 2.0 protocol handling, tool registry, and resource management.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
)

// Handler processes MCP protocol requests.
// Implementations must handle JSON-RPC 2.0 requests and route them
// to appropriate method handlers (initialize, tools/list, tools/call, etc.).
type Handler interface {
	// HandleRequest processes an MCP JSON-RPC request and returns a response.
	// The context can be used for cancellation and deadline propagation.
	//
	// Returns appropriate JSON-RPC errors for malformed requests, missing methods,
	// or execution failures per JSON-RPC 2.0 specification.
	HandleRequest(ctx context.Context, req *Request) (*Response, error)
}

// Request represents an MCP JSON-RPC 2.0 request.
type Request struct {
	// JSONRPC is the JSON-RPC version, must be "2.0".
	JSONRPC string `json:"jsonrpc"`

	// ID is the request identifier, can be string, number, or null.
	// Omitted for notification requests.
	ID any `json:"id,omitempty"`

	// Method is the MCP method name to invoke.
	Method string `json:"method"`

	// Params contains method-specific parameters as raw JSON.
	Params json.RawMessage `json:"params,omitempty"`
}

// Response represents an MCP JSON-RPC 2.0 response.
type Response struct {
	// JSONRPC is the JSON-RPC version, always "2.0".
	JSONRPC string `json:"jsonrpc"`

	// ID matches the request ID, or null for error responses without a valid ID.
	ID any `json:"id,omitempty"`

	// Result contains the successful response data.
	// Must not be present if Error is set.
	Result any `json:"result,omitempty"`

	// Error contains error information if the request failed.
	// Must not be present if Result is set.
	Error *Error `json:"error,omitempty"`
}

// Error represents a JSON-RPC 2.0 error object.
type Error struct {
	// Code is the error code indicating the error type.
	Code int `json:"code"`

	// Message is a short description of the error.
	Message string `json:"message"`

	// Data contains additional information about the error (optional).
	Data any `json:"data,omitempty"`

	// Cause is the underlying error (not serialized to JSON).
	Cause error `json:"-"`
}

// Protocol constants
const (
	// ProtocolVersion is the MCP protocol version this implementation supports.
	ProtocolVersion = "2024-11-05"

	// JSONRPCVersion is the JSON-RPC version used by MCP.
	JSONRPCVersion = "2.0"
)

// Standard JSON-RPC 2.0 error codes
const (
	// CodeParseError indicates invalid JSON was received by the server.
	CodeParseError = -32700

	// CodeInvalidRequest indicates the JSON sent is not a valid Request object.
	CodeInvalidRequest = -32600

	// CodeMethodNotFound indicates the method does not exist or is not available.
	CodeMethodNotFound = -32601

	// CodeInvalidParams indicates invalid method parameters.
	CodeInvalidParams = -32602

	// CodeInternalError indicates an internal JSON-RPC error.
	CodeInternalError = -32603
)

// MCP-specific error codes
const (
	// CodeResourceNotFound indicates the requested resource was not found.
	CodeResourceNotFound = -32002

	// CodeToolNotFound indicates the requested tool was not found.
	CodeToolNotFound = -32003
)

// ToolRegistry manages MCP tools.
// Implementations must be thread-safe as tools may be registered and
// executed concurrently.
type ToolRegistry interface {
	// RegisterTool registers a tool with the given name.
	// Returns an error if a tool with the same name is already registered.
	RegisterTool(name string, tool Tool) error

	// GetTool retrieves a tool by name.
	// Returns an error if the tool is not found.
	GetTool(name string) (Tool, error)

	// ListTools returns definitions for all registered tools.
	// The returned slice should not be modified by the caller.
	ListTools() []ToolDefinition
}

// Tool represents an executable MCP tool.
// Tools are invoked by clients to perform specific operations.
type Tool interface {
	// Execute runs the tool with the provided arguments.
	// The context can be used for cancellation and deadline propagation.
	// Arguments are provided as a map of parameter names to values.
	//
	// Returns the tool result or an error if execution fails.
	Execute(ctx context.Context, args map[string]any) (any, error)

	// Definition returns the tool's metadata including name, description,
	// and input schema for client discovery.
	Definition() ToolDefinition
}

// ToolDefinition describes a tool's interface for client discovery.
type ToolDefinition struct {
	// Name is the unique identifier for this tool.
	Name string `json:"name"`

	// Description explains what the tool does.
	Description string `json:"description"`

	// InputSchema is a JSON Schema describing the tool's expected parameters.
	// Should follow JSON Schema Draft 7 or later.
	InputSchema map[string]any `json:"inputSchema"`
}

// ResourceRegistry manages MCP resources.
// Implementations must be thread-safe as resources may be registered
// and accessed concurrently.
type ResourceRegistry interface {
	// RegisterResource registers a resource provider for the given URI.
	// Returns an error if a resource with the same URI is already registered.
	RegisterResource(uri string, provider ResourceProvider) error

	// GetResource retrieves a resource by URI and reads its content.
	// The context can be used for cancellation and deadline propagation.
	//
	// Returns an error if the resource is not found or cannot be read.
	GetResource(ctx context.Context, uri string) (*Resource, error)

	// ListResources returns definitions for all registered resources.
	// The returned slice should not be modified by the caller.
	ListResources() []ResourceDefinition
}

// ResourceProvider provides access to a specific resource.
// Resources are read-only data sources that clients can access.
type ResourceProvider interface {
	// Read retrieves the current content of the resource.
	// The context can be used for cancellation and deadline propagation.
	//
	// Returns the resource content or an error if reading fails.
	Read(ctx context.Context) (*Resource, error)

	// Definition returns the resource's metadata for client discovery.
	Definition() ResourceDefinition
}

// Resource represents MCP resource content.
type Resource struct {
	// URI is the unique identifier for this resource.
	URI string `json:"uri"`

	// MimeType indicates the content type (e.g., "text/plain", "application/json").
	MimeType string `json:"mimeType,omitempty"`

	// Text contains the resource content as a string.
	// For binary content, use base64 encoding.
	Text string `json:"text,omitempty"`
}

// ResourceDefinition describes a resource for client discovery.
type ResourceDefinition struct {
	// URI is the unique identifier for this resource.
	URI string `json:"uri"`

	// Name is a human-readable name for the resource.
	Name string `json:"name"`

	// Description explains what the resource provides (optional).
	Description string `json:"description,omitempty"`

	// MimeType indicates the content type (optional).
	MimeType string `json:"mimeType,omitempty"`
}

// NewError creates a new Error with the given code, message, and optional data.
func NewError(code int, message string, data any) *Error {
	return &Error{Code: code, Message: message, Data: data}
}

// Error implements the error interface for Error.
func (e *Error) Error() string {
	if e.Data != nil {
		return fmt.Sprintf("JSON-RPC error %d: %s (data: %v)", e.Code, e.Message, e.Data)
	}
	return fmt.Sprintf("JSON-RPC error %d: %s", e.Code, e.Message)
}

// Unwrap returns the underlying cause of the error.
func (e *Error) Unwrap() error {
	return e.Cause
}

// Validate checks if the request is valid according to JSON-RPC 2.0 specification.
func (r *Request) Validate() error {
	if r.JSONRPC != JSONRPCVersion {
		return ErrInvalidRequest
	}
	if r.Method == "" {
		return ErrInvalidRequest
	}
	return nil
}

// IsError returns true if the response contains an error.
func (r *Response) IsError() bool {
	return r.Error != nil
}
