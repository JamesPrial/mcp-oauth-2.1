package handlers

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"

	"github.com/jamesprial/mcp-oauth-2.1/internal/mcp"
	"github.com/jamesprial/mcp-oauth-2.1/internal/transport/transportcore"
	pkgoauth "github.com/jamesprial/mcp-oauth-2.1/pkg/oauth"
)

// mcpHandler handles MCP protocol requests over HTTP.
type mcpHandler struct {
	handler   mcp.Handler
	responder transportcore.ErrorResponder
}

// NewMCPHandler creates a handler for MCP JSON-RPC requests.
// It parses JSON-RPC requests, delegates to the MCP handler, and returns JSON-RPC responses.
func NewMCPHandler(handler mcp.Handler, responder transportcore.ErrorResponder) http.Handler {
	if handler == nil {
		panic("handler cannot be nil")
	}
	if responder == nil {
		panic("responder cannot be nil")
	}

	return &mcpHandler{
		handler:   handler,
		responder: responder,
	}
}

// ServeHTTP handles POST requests for MCP protocol.
// Only POST method is allowed for JSON-RPC requests.
func (h *mcpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Only allow POST method
	if r.Method != http.MethodPost {
		// Method not allowed - return 405
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Check Content-Type header
	contentType := r.Header.Get(pkgoauth.HeaderContentType)
	if contentType != pkgoauth.ContentTypeJSON && contentType != "" {
		slog.Warn("unexpected content type", "content_type", contentType)
	}

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		slog.Error("failed to read request body", "error", err)
		h.responder.BadRequest(w, err)
		return
	}
	defer func() {
		if closeErr := r.Body.Close(); closeErr != nil {
			slog.Warn("failed to close request body", "error", closeErr)
		}
	}()

	// Parse JSON-RPC request
	var req mcp.Request
	if err := json.Unmarshal(body, &req); err != nil {
		slog.Error("failed to parse JSON-RPC request", "error", err)
		// Return JSON-RPC parse error
		h.sendJSONRPCError(w, nil, mcp.CodeParseError, "Parse error", err)
		return
	}

	// Validate request
	if err := req.Validate(); err != nil {
		slog.Error("invalid JSON-RPC request", "error", err)
		h.sendJSONRPCError(w, req.ID, mcp.CodeInvalidRequest, "Invalid request", err)
		return
	}

	// Handle request
	resp, err := h.handler.HandleRequest(r.Context(), &req)
	if err != nil {
		slog.Error("MCP handler error", "error", err, "method", req.Method)
		// If the handler returned an error, send it as JSON-RPC error
		h.sendJSONRPCError(w, req.ID, mcp.CodeInternalError, "Internal error", err)
		return
	}

	// Send JSON-RPC response
	h.sendJSONRPCResponse(w, resp)
}

// sendJSONRPCResponse sends a JSON-RPC response to the client.
func (h *mcpHandler) sendJSONRPCResponse(w http.ResponseWriter, resp *mcp.Response) {
	w.Header().Set(pkgoauth.HeaderContentType, pkgoauth.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("failed to encode JSON-RPC response", "error", err)
		// Can't send error response here since headers are already written
	}
}

// sendJSONRPCError sends a JSON-RPC error response to the client.
func (h *mcpHandler) sendJSONRPCError(w http.ResponseWriter, id any, code int, message string, cause error) {
	resp := &mcp.Response{
		JSONRPC: mcp.JSONRPCVersion,
		ID:      id,
		Error: &mcp.Error{
			Code:    code,
			Message: message,
			Cause:   cause,
		},
	}

	w.Header().Set(pkgoauth.HeaderContentType, pkgoauth.ContentTypeJSON)
	w.WriteHeader(http.StatusOK) // JSON-RPC errors still return 200 OK

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("failed to encode JSON-RPC error response", "error", err)
	}
}
