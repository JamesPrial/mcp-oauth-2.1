// Package handlers provides HTTP handlers for the MCP server.
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jamesprial/mcp-oauth-2.1/internal/mcp"
	"github.com/jamesprial/mcp-oauth-2.1/internal/transport/internal/mocks"
)

// mockMCPHandler implements mcp.Handler for testing.
type mockMCPHandler struct {
	handleFunc func(ctx context.Context, req *mcp.Request) (*mcp.Response, error)
}

func (m *mockMCPHandler) HandleRequest(ctx context.Context, req *mcp.Request) (*mcp.Response, error) {
	if m.handleFunc != nil {
		return m.handleFunc(ctx, req)
	}
	return nil, errors.New("not implemented")
}

func TestMCPHandler_ValidRequest(t *testing.T) {
	t.Parallel()

	expectedResult := map[string]any{"success": true}

	handler := &mockMCPHandler{
		handleFunc: func(ctx context.Context, req *mcp.Request) (*mcp.Response, error) {
			return &mcp.Response{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result:  expectedResult,
			}, nil
		},
	}

	responder := &mocks.ErrorResponder{MetadataURL: "https://example.com/.well-known/oauth-protected-resource"}
	mcpHandler := NewMCPHandler(handler, responder)

	reqBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpHandler.ServeHTTP(w, req)

	resp := w.Result()
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("MCPHandler valid request status = %v, want 200", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Errorf("MCPHandler Content-Type = %v, want application/json", contentType)
	}

	var jsonRPCResp mcp.Response
	if err := json.NewDecoder(resp.Body).Decode(&jsonRPCResp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if jsonRPCResp.JSONRPC != "2.0" {
		t.Errorf("JSONRPC version = %v, want 2.0", jsonRPCResp.JSONRPC)
	}

	if jsonRPCResp.Error != nil {
		t.Errorf("Unexpected error in response: %v", jsonRPCResp.Error)
	}
}

func TestMCPHandler_GET(t *testing.T) {
	t.Parallel()

	handler := &mockMCPHandler{}
	responder := &mocks.ErrorResponder{MetadataURL: "https://example.com/.well-known/oauth-protected-resource"}
	mcpHandler := NewMCPHandler(handler, responder)

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	w := httptest.NewRecorder()

	mcpHandler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("MCPHandler GET status = %v, want 405", w.Code)
	}
}

func TestMCPHandler_OtherMethods(t *testing.T) {
	t.Parallel()

	methods := []string{
		http.MethodPut,
		http.MethodDelete,
		http.MethodPatch,
	}

	handler := &mockMCPHandler{}
	responder := &mocks.ErrorResponder{MetadataURL: "https://example.com/.well-known/oauth-protected-resource"}
	mcpHandler := NewMCPHandler(handler, responder)

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(method, "/mcp", nil)
			w := httptest.NewRecorder()

			mcpHandler.ServeHTTP(w, req)

			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("MCPHandler %s status = %v, want 405", method, w.Code)
			}
		})
	}
}

func TestMCPHandler_InvalidJSON(t *testing.T) {
	t.Parallel()

	handler := &mockMCPHandler{}
	responder := &mocks.ErrorResponder{MetadataURL: "https://example.com/.well-known/oauth-protected-resource"}
	mcpHandler := NewMCPHandler(handler, responder)

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("not valid json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpHandler.ServeHTTP(w, req)

	// JSON-RPC protocol returns 200 with error in response body
	if w.Code != http.StatusOK {
		t.Errorf("MCPHandler invalid JSON status = %v, want 200", w.Code)
	}

	// Should have JSON-RPC error response with parse error code
	var resp mcp.Response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode error response: %v", err)
	}
	if resp.Error == nil {
		t.Error("Expected error in JSON-RPC response")
	}
	if resp.Error != nil && resp.Error.Code != mcp.CodeParseError {
		t.Errorf("Error code = %v, want %v (parse error)", resp.Error.Code, mcp.CodeParseError)
	}
}

func TestMCPHandler_EmptyBody(t *testing.T) {
	t.Parallel()

	handler := &mockMCPHandler{}
	responder := &mocks.ErrorResponder{MetadataURL: "https://example.com/.well-known/oauth-protected-resource"}
	mcpHandler := NewMCPHandler(handler, responder)

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpHandler.ServeHTTP(w, req)

	// Empty body results in parse error, which is returned as JSON-RPC error (200)
	if w.Code != http.StatusOK {
		t.Errorf("MCPHandler empty body status = %v, want 200", w.Code)
	}

	// Should have JSON-RPC error response
	var resp mcp.Response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode error response: %v", err)
	}
	if resp.Error == nil {
		t.Error("Expected error in JSON-RPC response for empty body")
	}
}

func TestMCPHandler_HandlerError(t *testing.T) {
	t.Parallel()

	handler := &mockMCPHandler{
		handleFunc: func(ctx context.Context, req *mcp.Request) (*mcp.Response, error) {
			return nil, errors.New("internal handler error")
		},
	}

	responder := &mocks.ErrorResponder{MetadataURL: "https://example.com/.well-known/oauth-protected-resource"}
	mcpHandler := NewMCPHandler(handler, responder)

	reqBody := `{"jsonrpc":"2.0","id":1,"method":"test"}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpHandler.ServeHTTP(w, req)

	// Handler error should result in a JSON-RPC error response or 500
	// The behavior depends on implementation - either:
	// 1. 200 with JSON-RPC error in body
	// 2. 500 with error body
	if w.Code != http.StatusOK && w.Code != http.StatusInternalServerError {
		t.Errorf("MCPHandler error status = %v, want 200 or 500", w.Code)
	}
}

func TestMCPHandler_JSONRPCError(t *testing.T) {
	t.Parallel()

	handler := &mockMCPHandler{
		handleFunc: func(ctx context.Context, req *mcp.Request) (*mcp.Response, error) {
			return &mcp.Response{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error: &mcp.Error{
					Code:    mcp.CodeMethodNotFound,
					Message: "method not found",
				},
			}, nil
		},
	}

	responder := &mocks.ErrorResponder{MetadataURL: "https://example.com/.well-known/oauth-protected-resource"}
	mcpHandler := NewMCPHandler(handler, responder)

	reqBody := `{"jsonrpc":"2.0","id":1,"method":"unknown"}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpHandler.ServeHTTP(w, req)

	// JSON-RPC errors should return 200 with error in body
	if w.Code != http.StatusOK {
		t.Errorf("MCPHandler JSON-RPC error status = %v, want 200", w.Code)
	}

	var jsonRPCResp mcp.Response
	if err := json.NewDecoder(w.Body).Decode(&jsonRPCResp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if jsonRPCResp.Error == nil {
		t.Error("Expected error in JSON-RPC response")
	}

	if jsonRPCResp.Error.Code != mcp.CodeMethodNotFound {
		t.Errorf("Error code = %v, want %v", jsonRPCResp.Error.Code, mcp.CodeMethodNotFound)
	}
}

func TestMCPHandler_ContextPassed(t *testing.T) {
	t.Parallel()

	var receivedCtx context.Context

	handler := &mockMCPHandler{
		handleFunc: func(ctx context.Context, req *mcp.Request) (*mcp.Response, error) {
			receivedCtx = ctx
			return &mcp.Response{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result:  map[string]any{},
			}, nil
		},
	}

	responder := &mocks.ErrorResponder{MetadataURL: "https://example.com/.well-known/oauth-protected-resource"}
	mcpHandler := NewMCPHandler(handler, responder)

	reqBody := `{"jsonrpc":"2.0","id":1,"method":"test"}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpHandler.ServeHTTP(w, req)

	if receivedCtx == nil {
		t.Error("Context was not passed to handler")
	}
}

func TestMCPHandler_RequestParsing(t *testing.T) {
	t.Parallel()

	var receivedReq *mcp.Request

	handler := &mockMCPHandler{
		handleFunc: func(ctx context.Context, req *mcp.Request) (*mcp.Response, error) {
			receivedReq = req
			return &mcp.Response{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result:  map[string]any{},
			}, nil
		},
	}

	responder := &mocks.ErrorResponder{MetadataURL: "https://example.com/.well-known/oauth-protected-resource"}
	mcpHandler := NewMCPHandler(handler, responder)

	reqBody := `{"jsonrpc":"2.0","id":"test-id-123","method":"tools/list","params":{"cursor":"abc"}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpHandler.ServeHTTP(w, req)

	if receivedReq == nil {
		t.Fatal("Request was not passed to handler")
	}

	if receivedReq.JSONRPC != "2.0" {
		t.Errorf("JSONRPC = %v, want 2.0", receivedReq.JSONRPC)
	}

	if receivedReq.Method != "tools/list" {
		t.Errorf("Method = %v, want tools/list", receivedReq.Method)
	}

	if receivedReq.ID != "test-id-123" {
		t.Errorf("ID = %v, want test-id-123", receivedReq.ID)
	}
}

func TestMCPHandler_NumericID(t *testing.T) {
	t.Parallel()

	handler := &mockMCPHandler{
		handleFunc: func(ctx context.Context, req *mcp.Request) (*mcp.Response, error) {
			return &mcp.Response{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result:  map[string]any{},
			}, nil
		},
	}

	responder := &mocks.ErrorResponder{MetadataURL: "https://example.com/.well-known/oauth-protected-resource"}
	mcpHandler := NewMCPHandler(handler, responder)

	reqBody := `{"jsonrpc":"2.0","id":42,"method":"test"}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("MCPHandler numeric ID status = %v, want 200", w.Code)
	}

	var jsonRPCResp mcp.Response
	if err := json.NewDecoder(w.Body).Decode(&jsonRPCResp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// ID should be preserved (as float64 from JSON unmarshaling)
	if jsonRPCResp.ID == nil {
		t.Error("Response ID should not be nil")
	}
}

func TestMCPHandler_NullID(t *testing.T) {
	t.Parallel()

	handler := &mockMCPHandler{
		handleFunc: func(ctx context.Context, req *mcp.Request) (*mcp.Response, error) {
			return &mcp.Response{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result:  map[string]any{},
			}, nil
		},
	}

	responder := &mocks.ErrorResponder{MetadataURL: "https://example.com/.well-known/oauth-protected-resource"}
	mcpHandler := NewMCPHandler(handler, responder)

	reqBody := `{"jsonrpc":"2.0","id":null,"method":"test"}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpHandler.ServeHTTP(w, req)

	// Null ID is valid in JSON-RPC 2.0
	if w.Code != http.StatusOK && w.Code != http.StatusBadRequest {
		t.Errorf("MCPHandler null ID status = %v", w.Code)
	}
}

func TestMCPHandler_LargeRequest(t *testing.T) {
	t.Parallel()

	handler := &mockMCPHandler{
		handleFunc: func(ctx context.Context, req *mcp.Request) (*mcp.Response, error) {
			return &mcp.Response{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result:  map[string]any{"received": true},
			}, nil
		},
	}

	responder := &mocks.ErrorResponder{MetadataURL: "https://example.com/.well-known/oauth-protected-resource"}
	mcpHandler := NewMCPHandler(handler, responder)

	// Create a large params object
	largeParams := make(map[string]string)
	for i := 0; i < 100; i++ {
		largeParams[string(rune('a'+i%26))+string(rune('0'+i%10))] = strings.Repeat("x", 1000)
	}
	paramsJSON, _ := json.Marshal(largeParams)

	reqBody := bytes.Buffer{}
	reqBody.WriteString(`{"jsonrpc":"2.0","id":1,"method":"test","params":`)
	reqBody.Write(paramsJSON)
	reqBody.WriteString(`}`)

	req := httptest.NewRequest(http.MethodPost, "/mcp", &reqBody)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpHandler.ServeHTTP(w, req)

	// Large request should be handled or rejected with appropriate status
	if w.Code != http.StatusOK && w.Code != http.StatusRequestEntityTooLarge && w.Code != http.StatusBadRequest {
		t.Errorf("MCPHandler large request status = %v", w.Code)
	}
}
