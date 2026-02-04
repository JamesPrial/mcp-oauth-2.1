// Package mcp provides MCP protocol handler implementation.
package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	internalerrors "github.com/jamesprial/mcp-oauth-2.1/internal/errors"
)

// handler implements the Handler interface.
// It routes JSON-RPC requests to appropriate method handlers.
type handler struct {
	toolRegistry     ToolRegistry
	resourceRegistry ResourceRegistry
	serverInfo       serverInfo
	initialized      bool
}

// serverInfo contains metadata about the MCP server.
type serverInfo struct {
	Name    string
	Version string
}

// newHandler creates a new MCP protocol handler.
// The handler processes JSON-RPC 2.0 requests and routes them to the
// appropriate tool or resource registries.
func newHandler(toolRegistry ToolRegistry, resourceRegistry ResourceRegistry, info serverInfo) Handler {
	if toolRegistry == nil {
		panic("toolRegistry cannot be nil")
	}
	if resourceRegistry == nil {
		panic("resourceRegistry cannot be nil")
	}
	return &handler{
		toolRegistry:     toolRegistry,
		resourceRegistry: resourceRegistry,
		serverInfo:       info,
		initialized:      false,
	}
}

// HandleRequest processes an MCP JSON-RPC request.
func (h *handler) HandleRequest(ctx context.Context, req *Request) (*Response, error) {
	if req == nil {
		return h.errorResponse(nil, CodeInvalidRequest, "request cannot be nil", nil), nil
	}

	// Validate JSON-RPC version
	if req.JSONRPC != JSONRPCVersion {
		return h.errorResponse(req.ID, CodeInvalidRequest, "invalid jsonrpc version", nil), nil
	}

	// Validate method is present
	if req.Method == "" {
		return h.errorResponse(req.ID, CodeInvalidRequest, "method is required", nil), nil
	}

	// Route to appropriate handler
	switch req.Method {
	case "initialize":
		return h.handleInitialize(ctx, req)
	case "tools/list":
		return h.handleToolsList(ctx, req)
	case "tools/call":
		return h.handleToolsCall(ctx, req)
	case "resources/list":
		return h.handleResourcesList(ctx, req)
	case "resources/read":
		return h.handleResourcesRead(ctx, req)
	default:
		return h.errorResponse(req.ID, CodeMethodNotFound, fmt.Sprintf("method not found: %s", req.Method), nil), nil
	}
}

// handleInitialize handles the initialize method.
func (h *handler) handleInitialize(ctx context.Context, req *Request) (*Response, error) {
	var params InitializeParams
	if req.Params != nil {
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return h.errorResponse(req.ID, CodeInvalidParams, "invalid initialize params", err.Error()), nil
		}
	}

	h.initialized = true

	result := InitializeResult{
		ProtocolVersion: ProtocolVersion,
		ServerInfo: ServerInfoResponse{
			Name:    h.serverInfo.Name,
			Version: h.serverInfo.Version,
		},
		Capabilities: Capabilities{
			Tools:     &ToolsCapability{},
			Resources: &ResourcesCapability{},
		},
	}

	return &Response{
		JSONRPC: JSONRPCVersion,
		ID:      req.ID,
		Result:  result,
	}, nil
}

// handleToolsList handles the tools/list method.
func (h *handler) handleToolsList(ctx context.Context, req *Request) (*Response, error) {
	tools := h.toolRegistry.ListTools()

	result := ToolsListResult{
		Tools: tools,
	}

	return &Response{
		JSONRPC: JSONRPCVersion,
		ID:      req.ID,
		Result:  result,
	}, nil
}

// handleToolsCall handles the tools/call method.
func (h *handler) handleToolsCall(ctx context.Context, req *Request) (*Response, error) {
	if req.Params == nil {
		return h.errorResponse(req.ID, CodeInvalidParams, "params required", nil), nil
	}

	var params ToolsCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return h.errorResponse(req.ID, CodeInvalidParams, "invalid tools/call params", err.Error()), nil
	}

	if params.Name == "" {
		return h.errorResponse(req.ID, CodeInvalidParams, "tool name is required", nil), nil
	}

	tool, err := h.toolRegistry.GetTool(params.Name)
	if err != nil {
		if errors.Is(err, ErrToolNotFound) {
			return h.errorResponse(req.ID, CodeToolNotFound, fmt.Sprintf("tool not found: %s", params.Name), nil), nil
		}
		domainErr := internalerrors.New("mcp", "HandleRequest", internalerrors.ErrInternal, err)
		return h.errorResponse(req.ID, CodeInternalError, "failed to get tool", domainErr.Error()), nil
	}

	// Execute the tool
	toolResult, err := tool.Execute(ctx, params.Arguments)
	if err != nil {
		domainErr := internalerrors.New("mcp", "HandleRequest", internalerrors.ErrInternal, err)
		return h.errorResponse(req.ID, CodeInternalError, "tool execution failed", domainErr.Error()), nil
	}

	result := ToolsCallResult{
		Content: []Content{
			{
				Type: "text",
				Text: fmt.Sprintf("%v", toolResult),
			},
		},
	}

	return &Response{
		JSONRPC: JSONRPCVersion,
		ID:      req.ID,
		Result:  result,
	}, nil
}

// handleResourcesList handles the resources/list method.
func (h *handler) handleResourcesList(ctx context.Context, req *Request) (*Response, error) {
	resources := h.resourceRegistry.ListResources()

	result := ResourcesListResult{
		Resources: resources,
	}

	return &Response{
		JSONRPC: JSONRPCVersion,
		ID:      req.ID,
		Result:  result,
	}, nil
}

// handleResourcesRead handles the resources/read method.
func (h *handler) handleResourcesRead(ctx context.Context, req *Request) (*Response, error) {
	if req.Params == nil {
		return h.errorResponse(req.ID, CodeInvalidParams, "params required", nil), nil
	}

	var params ResourcesReadParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return h.errorResponse(req.ID, CodeInvalidParams, "invalid resources/read params", err.Error()), nil
	}

	if params.URI == "" {
		return h.errorResponse(req.ID, CodeInvalidParams, "resource uri is required", nil), nil
	}

	resource, err := h.resourceRegistry.GetResource(ctx, params.URI)
	if err != nil {
		if errors.Is(err, ErrResourceNotFound) {
			return h.errorResponse(req.ID, CodeResourceNotFound, fmt.Sprintf("resource not found: %s", params.URI), nil), nil
		}
		domainErr := internalerrors.New("mcp", "HandleRequest", internalerrors.ErrInternal, err)
		return h.errorResponse(req.ID, CodeInternalError, "failed to read resource", domainErr.Error()), nil
	}

	result := ResourcesReadResult{
		Contents: []ResourceContent{
			{
				URI:      resource.URI,
				MimeType: resource.MimeType,
				Text:     resource.Text,
			},
		},
	}

	return &Response{
		JSONRPC: JSONRPCVersion,
		ID:      req.ID,
		Result:  result,
	}, nil
}

// errorResponse creates a JSON-RPC error response.
func (h *handler) errorResponse(id any, code int, message string, data any) *Response {
	return &Response{
		JSONRPC: JSONRPCVersion,
		ID:      id,
		Error: &Error{
			Code:    code,
			Message: message,
			Data:    data,
		},
	}
}
