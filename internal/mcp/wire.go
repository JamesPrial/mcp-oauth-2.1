package mcp

// Config holds configuration for MCP services.
type Config struct {
	// ServerName is the name of the MCP server.
	ServerName string

	// ServerVersion is the version of the MCP server.
	ServerVersion string
}

// NewHandler creates a new MCP protocol handler.
// The handler routes JSON-RPC requests to the appropriate registries.
func NewHandler(cfg *Config, toolRegistry ToolRegistry, resourceRegistry ResourceRegistry) Handler {
	if cfg == nil {
		panic("config cannot be nil")
	}
	if toolRegistry == nil {
		panic("toolRegistry cannot be nil")
	}
	if resourceRegistry == nil {
		panic("resourceRegistry cannot be nil")
	}

	info := serverInfo{
		Name:    cfg.ServerName,
		Version: cfg.ServerVersion,
	}

	return newHandler(toolRegistry, resourceRegistry, info)
}

// NewMCPServices creates all MCP services from the configuration.
// This is a convenience function for dependency injection.
func NewMCPServices(cfg *Config) (Handler, ToolRegistry, ResourceRegistry) {
	toolRegistry := NewToolRegistry()
	resourceRegistry := NewResourceRegistry()
	handler := NewHandler(cfg, toolRegistry, resourceRegistry)

	return handler, toolRegistry, resourceRegistry
}
