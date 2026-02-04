package mcp

import (
	"fmt"
	"sync"

	internalerrors "github.com/jamesprial/mcp-oauth-2.1/internal/errors"
)

// toolRegistry implements ToolRegistry with thread-safe access.
type toolRegistry struct {
	mu    sync.RWMutex
	tools map[string]Tool
}

// NewToolRegistry creates a new thread-safe tool registry.
func NewToolRegistry() ToolRegistry {
	return &toolRegistry{
		tools: make(map[string]Tool),
	}
}

// RegisterTool registers a tool with the given name.
// Returns an error if a tool with the same name is already registered
// or if the tool or name is invalid.
func (r *toolRegistry) RegisterTool(name string, tool Tool) error {
	if name == "" {
		return internalerrors.New("mcp", "RegisterTool", internalerrors.ErrBadRequest, fmt.Errorf("tool name cannot be empty"))
	}
	if tool == nil {
		return internalerrors.New("mcp", "RegisterTool", internalerrors.ErrBadRequest, fmt.Errorf("tool cannot be nil"))
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.tools[name]; exists {
		return internalerrors.New("mcp", "RegisterTool", internalerrors.ErrBadRequest, ErrToolAlreadyRegistered).
			WithContext("tool_name", name)
	}

	r.tools[name] = tool
	return nil
}

// GetTool retrieves a tool by name.
// Returns ErrToolNotFound if the tool does not exist.
func (r *toolRegistry) GetTool(name string) (Tool, error) {
	if name == "" {
		return nil, internalerrors.New("mcp", "GetTool", internalerrors.ErrBadRequest, fmt.Errorf("tool name cannot be empty"))
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	tool, exists := r.tools[name]
	if !exists {
		return nil, internalerrors.New("mcp", "GetTool", internalerrors.ErrNotFound, ErrToolNotFound).
			WithContext("tool_name", name)
	}

	return tool, nil
}

// ListTools returns definitions for all registered tools.
// The returned slice is a snapshot and safe for concurrent access.
func (r *toolRegistry) ListTools() []ToolDefinition {
	r.mu.RLock()
	defer r.mu.RUnlock()

	definitions := make([]ToolDefinition, 0, len(r.tools))
	for _, tool := range r.tools {
		definitions = append(definitions, tool.Definition())
	}

	return definitions
}
