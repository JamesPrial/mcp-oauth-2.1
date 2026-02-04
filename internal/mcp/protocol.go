package mcp

// InitializeParams contains parameters for the initialize method.
type InitializeParams struct {
	// ProtocolVersion is the MCP protocol version the client supports.
	ProtocolVersion string `json:"protocolVersion"`

	// ClientInfo contains metadata about the client.
	ClientInfo ClientInfo `json:"clientInfo"`

	// Capabilities describes what the client supports.
	Capabilities ClientCapabilities `json:"capabilities,omitempty"`
}

// ClientInfo contains metadata about the MCP client.
type ClientInfo struct {
	// Name is the client name.
	Name string `json:"name"`

	// Version is the client version.
	Version string `json:"version"`
}

// ClientCapabilities describes what the client supports.
type ClientCapabilities struct {
	// Roots indicates if the client supports workspace roots.
	Roots *RootsCapability `json:"roots,omitempty"`

	// Sampling indicates if the client supports sampling.
	Sampling *SamplingCapability `json:"sampling,omitempty"`
}

// RootsCapability indicates roots support.
type RootsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// SamplingCapability indicates sampling support.
type SamplingCapability struct{}

// InitializeResult is the result of the initialize method.
type InitializeResult struct {
	// ProtocolVersion is the MCP protocol version the server supports.
	ProtocolVersion string `json:"protocolVersion"`

	// ServerInfo contains metadata about the server.
	ServerInfo ServerInfoResponse `json:"serverInfo"`

	// Capabilities describes what the server supports.
	Capabilities Capabilities `json:"capabilities"`
}

// ServerInfoResponse contains metadata about the MCP server.
type ServerInfoResponse struct {
	// Name is the server name.
	Name string `json:"name"`

	// Version is the server version.
	Version string `json:"version"`
}

// Capabilities describes what the MCP server supports.
type Capabilities struct {
	// Tools indicates the server supports tools.
	Tools *ToolsCapability `json:"tools,omitempty"`

	// Resources indicates the server supports resources.
	Resources *ResourcesCapability `json:"resources,omitempty"`

	// Prompts indicates the server supports prompts.
	Prompts *PromptsCapability `json:"prompts,omitempty"`

	// Logging indicates the server supports logging.
	Logging *LoggingCapability `json:"logging,omitempty"`
}

// ToolsCapability indicates tools support.
type ToolsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// ResourcesCapability indicates resources support.
type ResourcesCapability struct {
	Subscribe   bool `json:"subscribe,omitempty"`
	ListChanged bool `json:"listChanged,omitempty"`
}

// PromptsCapability indicates prompts support.
type PromptsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// LoggingCapability indicates logging support.
type LoggingCapability struct{}

// ToolsListResult is the result of the tools/list method.
type ToolsListResult struct {
	// Tools is the list of available tools.
	Tools []ToolDefinition `json:"tools"`
}

// ToolsCallParams contains parameters for the tools/call method.
type ToolsCallParams struct {
	// Name is the tool name to call.
	Name string `json:"name"`

	// Arguments contains the tool-specific arguments.
	Arguments map[string]any `json:"arguments,omitempty"`
}

// ToolsCallResult is the result of the tools/call method.
type ToolsCallResult struct {
	// Content contains the tool execution results.
	Content []Content `json:"content"`

	// IsError indicates if the tool execution failed.
	IsError bool `json:"isError,omitempty"`
}

// Content represents a piece of content in a tool result.
type Content struct {
	// Type is the content type (e.g., "text", "image", "resource").
	Type string `json:"type"`

	// Text contains text content (for type "text").
	Text string `json:"text,omitempty"`

	// Data contains base64-encoded binary data (for type "image", "blob").
	Data string `json:"data,omitempty"`

	// MimeType indicates the MIME type (for binary content).
	MimeType string `json:"mimeType,omitempty"`

	// URI references a resource (for type "resource").
	URI string `json:"uri,omitempty"`
}

// ResourcesListResult is the result of the resources/list method.
type ResourcesListResult struct {
	// Resources is the list of available resources.
	Resources []ResourceDefinition `json:"resources"`
}

// ResourcesReadParams contains parameters for the resources/read method.
type ResourcesReadParams struct {
	// URI is the resource URI to read.
	URI string `json:"uri"`
}

// ResourcesReadResult is the result of the resources/read method.
type ResourcesReadResult struct {
	// Contents contains the resource content.
	Contents []ResourceContent `json:"contents"`
}

// ResourceContent represents the content of a resource.
type ResourceContent struct {
	// URI is the resource URI.
	URI string `json:"uri"`

	// MimeType indicates the content type.
	MimeType string `json:"mimeType,omitempty"`

	// Text contains the resource content as text.
	Text string `json:"text,omitempty"`

	// Blob contains base64-encoded binary content.
	Blob string `json:"blob,omitempty"`
}
