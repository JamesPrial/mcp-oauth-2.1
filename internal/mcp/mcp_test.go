// Package mcp provides MCP (Model Context Protocol) types, constants, and core functionality.
// This test file tests Request, Response, Error types and MCP-specific error codes.
package mcp

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func TestRequest_JSONRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		request Request
	}{
		{
			name: "initialize request",
			request: Request{
				JSONRPC: "2.0",
				ID:      1,
				Method:  "initialize",
				Params:  json.RawMessage(`{"protocolVersion":"2024-11-05","capabilities":{}}`),
			},
		},
		{
			name: "tools/list request",
			request: Request{
				JSONRPC: "2.0",
				ID:      2,
				Method:  "tools/list",
				Params:  nil,
			},
		},
		{
			name: "tools/call request",
			request: Request{
				JSONRPC: "2.0",
				ID:      3,
				Method:  "tools/call",
				Params:  json.RawMessage(`{"name":"echo","arguments":{"message":"hello"}}`),
			},
		},
		{
			name: "resources/list request",
			request: Request{
				JSONRPC: "2.0",
				ID:      4,
				Method:  "resources/list",
				Params:  nil,
			},
		},
		{
			name: "resources/read request",
			request: Request{
				JSONRPC: "2.0",
				ID:      5,
				Method:  "resources/read",
				Params:  json.RawMessage(`{"uri":"file:///data/config.json"}`),
			},
		},
		{
			name: "string ID",
			request: Request{
				JSONRPC: "2.0",
				ID:      "request-abc-123",
				Method:  "initialize",
				Params:  nil,
			},
		},
		{
			name: "notification (no ID)",
			request: Request{
				JSONRPC: "2.0",
				Method:  "notifications/cancelled",
				Params:  json.RawMessage(`{"requestId":5}`),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Marshal to JSON
			data, err := json.Marshal(tt.request)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}

			// Unmarshal back
			var got Request
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("json.Unmarshal() error = %v", err)
			}

			// Verify JSONRPC version
			if got.JSONRPC != tt.request.JSONRPC {
				t.Errorf("JSONRPC = %q, want %q", got.JSONRPC, tt.request.JSONRPC)
			}

			// Verify Method
			if got.Method != tt.request.Method {
				t.Errorf("Method = %q, want %q", got.Method, tt.request.Method)
			}

			// Verify Params (if non-nil)
			if tt.request.Params != nil {
				if got.Params == nil {
					t.Error("Params is nil, want non-nil")
				} else if string(got.Params) != string(tt.request.Params) {
					t.Errorf("Params = %s, want %s", got.Params, tt.request.Params)
				}
			}
		})
	}
}

func TestResponse_JSONRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		response Response
	}{
		{
			name: "success response with result",
			response: Response{
				JSONRPC: "2.0",
				ID:      1,
				Result:  json.RawMessage(`{"protocolVersion":"2024-11-05","capabilities":{"tools":{}}}`),
			},
		},
		{
			name: "success response with empty result",
			response: Response{
				JSONRPC: "2.0",
				ID:      2,
				Result:  json.RawMessage(`{}`),
			},
		},
		{
			name: "error response",
			response: Response{
				JSONRPC: "2.0",
				ID:      3,
				Error: &Error{
					Code:    -32601,
					Message: "Method not found",
				},
			},
		},
		{
			name: "error response with data",
			response: Response{
				JSONRPC: "2.0",
				ID:      4,
				Error: &Error{
					Code:    -32602,
					Message: "Invalid params",
					Data:    json.RawMessage(`{"field":"name","reason":"required"}`),
				},
			},
		},
		{
			name: "string ID response",
			response: Response{
				JSONRPC: "2.0",
				ID:      "request-abc-123",
				Result:  json.RawMessage(`{"tools":[]}`),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Marshal to JSON
			data, err := json.Marshal(tt.response)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}

			// Unmarshal back
			var got Response
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("json.Unmarshal() error = %v", err)
			}

			// Verify JSONRPC version
			if got.JSONRPC != tt.response.JSONRPC {
				t.Errorf("JSONRPC = %q, want %q", got.JSONRPC, tt.response.JSONRPC)
			}

			// Verify Result (if non-nil)
			// After JSON unmarshal, Result (type any) will be a map[string]interface{} or other Go type,
			// not json.RawMessage. Compare values by marshaling both to JSON.
			if tt.response.Result != nil || got.Result != nil {
				gotJSON, err := json.Marshal(got.Result)
				if err != nil {
					t.Fatalf("failed to marshal got.Result: %v", err)
				}
				wantJSON, err := json.Marshal(tt.response.Result)
				if err != nil {
					t.Fatalf("failed to marshal tt.response.Result: %v", err)
				}

				// Normalize by unmarshaling into maps for structural comparison
				var gotMap, wantMap any
				if err := json.Unmarshal(gotJSON, &gotMap); err != nil {
					t.Fatalf("failed to unmarshal gotJSON: %v", err)
				}
				if err := json.Unmarshal(wantJSON, &wantMap); err != nil {
					t.Fatalf("failed to unmarshal wantJSON: %v", err)
				}

				if !reflect.DeepEqual(gotMap, wantMap) {
					t.Errorf("Result = %s, want %s", gotJSON, wantJSON)
				}
			}

			// Verify Error (if non-nil)
			if tt.response.Error != nil {
				if got.Error == nil {
					t.Fatal("Error is nil, want non-nil")
				}
				if got.Error.Code != tt.response.Error.Code {
					t.Errorf("Error.Code = %d, want %d", got.Error.Code, tt.response.Error.Code)
				}
				if got.Error.Message != tt.response.Error.Message {
					t.Errorf("Error.Message = %q, want %q", got.Error.Message, tt.response.Error.Message)
				}
			}
		})
	}
}

func TestError_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      Error
		contains string
	}{
		{
			name: "method not found",
			err: Error{
				Code:    CodeMethodNotFound,
				Message: "Method not found",
			},
			contains: "Method not found",
		},
		{
			name: "invalid params",
			err: Error{
				Code:    CodeInvalidParams,
				Message: "Invalid params",
			},
			contains: "Invalid params",
		},
		{
			name: "internal error",
			err: Error{
				Code:    CodeInternalError,
				Message: "Internal error",
			},
			contains: "Internal error",
		},
		{
			name: "parse error",
			err: Error{
				Code:    CodeParseError,
				Message: "Parse error",
			},
			contains: "Parse error",
		},
		{
			name: "invalid request",
			err: Error{
				Code:    CodeInvalidRequest,
				Message: "Invalid request",
			},
			contains: "Invalid request",
		},
		{
			name: "resource not found",
			err: Error{
				Code:    CodeResourceNotFound,
				Message: "Resource not found",
			},
			contains: "Resource not found",
		},
		{
			name: "tool not found",
			err: Error{
				Code:    CodeToolNotFound,
				Message: "Tool not found",
			},
			contains: "Tool not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := tt.err.Error()
			if !containsString(got, tt.contains) {
				t.Errorf("Error() = %q, want to contain %q", got, tt.contains)
			}
		})
	}
}

func TestError_ErrorWithCode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		err     Error
		wantSub string
	}{
		{
			name: "includes code in message",
			err: Error{
				Code:    -32601,
				Message: "Method not found",
			},
			wantSub: "-32601",
		},
		{
			name: "includes custom code",
			err: Error{
				Code:    -32002,
				Message: "Resource not found",
			},
			wantSub: "-32002",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := tt.err.Error()
			// Error message should contain the code
			if !containsString(got, tt.wantSub) {
				t.Errorf("Error() = %q, want to contain %q", got, tt.wantSub)
			}
		})
	}
}

func TestErrorCodes_Constants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		code       int
		wantCode   int
		isStandard bool
	}{
		{
			name:       "parse error",
			code:       CodeParseError,
			wantCode:   -32700,
			isStandard: true,
		},
		{
			name:       "invalid request",
			code:       CodeInvalidRequest,
			wantCode:   -32600,
			isStandard: true,
		},
		{
			name:       "method not found",
			code:       CodeMethodNotFound,
			wantCode:   -32601,
			isStandard: true,
		},
		{
			name:       "invalid params",
			code:       CodeInvalidParams,
			wantCode:   -32602,
			isStandard: true,
		},
		{
			name:       "internal error",
			code:       CodeInternalError,
			wantCode:   -32603,
			isStandard: true,
		},
		{
			name:       "resource not found",
			code:       CodeResourceNotFound,
			wantCode:   -32002,
			isStandard: false,
		},
		{
			name:       "tool not found",
			code:       CodeToolNotFound,
			wantCode:   -32003,
			isStandard: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if tt.code != tt.wantCode {
				t.Errorf("code = %d, want %d", tt.code, tt.wantCode)
			}

			// Standard JSON-RPC errors should be in the -32xxx range
			if tt.isStandard {
				if tt.code > -32600 || tt.code < -32700 {
					// Only parse error is -32700
					if tt.code != -32700 {
						t.Errorf("standard code %d not in expected range", tt.code)
					}
				}
			}
		})
	}
}

func TestNewError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		code        int
		message     string
		data        interface{}
		wantCode    int
		wantMessage string
		wantData    bool
	}{
		{
			name:        "simple error",
			code:        CodeMethodNotFound,
			message:     "Method not found",
			data:        nil,
			wantCode:    CodeMethodNotFound,
			wantMessage: "Method not found",
			wantData:    false,
		},
		{
			name:        "error with data",
			code:        CodeInvalidParams,
			message:     "Invalid params",
			data:        map[string]string{"field": "name"},
			wantCode:    CodeInvalidParams,
			wantMessage: "Invalid params",
			wantData:    true,
		},
		{
			name:        "custom error code",
			code:        CodeResourceNotFound,
			message:     "Resource not found: file:///data",
			data:        nil,
			wantCode:    CodeResourceNotFound,
			wantMessage: "Resource not found: file:///data",
			wantData:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := NewError(tt.code, tt.message, tt.data)
			if got == nil {
				t.Fatal("NewError() returned nil")
			}
			if got.Code != tt.wantCode {
				t.Errorf("Code = %d, want %d", got.Code, tt.wantCode)
			}
			if got.Message != tt.wantMessage {
				t.Errorf("Message = %q, want %q", got.Message, tt.wantMessage)
			}
			if tt.wantData && got.Data == nil {
				t.Error("Data is nil, want non-nil")
			}
			if !tt.wantData && got.Data != nil {
				t.Errorf("Data = %v, want nil", got.Data)
			}
		})
	}
}

func TestMCPVersion_Constants(t *testing.T) {
	t.Parallel()

	// MCP protocol version should be defined
	if ProtocolVersion == "" {
		t.Error("ProtocolVersion should not be empty")
	}

	// JSONRPC version should be 2.0
	if JSONRPCVersion != "2.0" {
		t.Errorf("JSONRPCVersion = %q, want %q", JSONRPCVersion, "2.0")
	}
}

func TestRequest_Validation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		request Request
		wantErr bool
	}{
		{
			name: "valid request",
			request: Request{
				JSONRPC: "2.0",
				ID:      1,
				Method:  "initialize",
			},
			wantErr: false,
		},
		{
			name: "missing jsonrpc",
			request: Request{
				ID:     1,
				Method: "initialize",
			},
			wantErr: true,
		},
		{
			name: "wrong jsonrpc version",
			request: Request{
				JSONRPC: "1.0",
				ID:      1,
				Method:  "initialize",
			},
			wantErr: true,
		},
		{
			name: "missing method",
			request: Request{
				JSONRPC: "2.0",
				ID:      1,
			},
			wantErr: true,
		},
		{
			name: "empty method",
			request: Request{
				JSONRPC: "2.0",
				ID:      1,
				Method:  "",
			},
			wantErr: true,
		},
		{
			name: "notification without ID is valid",
			request: Request{
				JSONRPC: "2.0",
				Method:  "notifications/cancelled",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.request.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestResponse_IsError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		response Response
		want     bool
	}{
		{
			name: "success response",
			response: Response{
				JSONRPC: "2.0",
				ID:      1,
				Result:  json.RawMessage(`{}`),
			},
			want: false,
		},
		{
			name: "error response",
			response: Response{
				JSONRPC: "2.0",
				ID:      1,
				Error: &Error{
					Code:    CodeMethodNotFound,
					Message: "Method not found",
				},
			},
			want: true,
		},
		{
			name: "response with both result and error uses error",
			response: Response{
				JSONRPC: "2.0",
				ID:      1,
				Result:  json.RawMessage(`{}`),
				Error: &Error{
					Code:    CodeInternalError,
					Message: "Internal error",
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := tt.response.IsError()
			if got != tt.want {
				t.Errorf("IsError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMCPError_Unwrap(t *testing.T) {
	t.Parallel()

	innerErr := errors.New("connection refused")
	mcpErr := &Error{
		Code:    CodeInternalError,
		Message: "Internal error",
		Cause:   innerErr,
	}

	// Test that Unwrap returns the inner error
	unwrapped := mcpErr.Unwrap()
	if unwrapped != innerErr {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, innerErr)
	}

	// Test that errors.Is works correctly
	if !errors.Is(mcpErr, innerErr) {
		t.Error("errors.Is() should return true for wrapped error")
	}
}

func TestMCPError_NilUnwrap(t *testing.T) {
	t.Parallel()

	mcpErr := &Error{
		Code:    CodeMethodNotFound,
		Message: "Method not found",
	}

	// Test that Unwrap returns nil when no cause
	unwrapped := mcpErr.Unwrap()
	if unwrapped != nil {
		t.Errorf("Unwrap() = %v, want nil", unwrapped)
	}
}

// Helper function
func containsString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Benchmark tests
func BenchmarkRequest_Marshal(b *testing.B) {
	request := Request{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"echo","arguments":{"message":"hello world"}}`),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = json.Marshal(request)
	}
}

func BenchmarkRequest_Unmarshal(b *testing.B) {
	data := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"message":"hello world"}}}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var req Request
		_ = json.Unmarshal(data, &req)
	}
}

func BenchmarkResponse_Marshal(b *testing.B) {
	response := Response{
		JSONRPC: "2.0",
		ID:      1,
		Result:  json.RawMessage(`{"content":[{"type":"text","text":"Hello, World!"}]}`),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = json.Marshal(response)
	}
}
