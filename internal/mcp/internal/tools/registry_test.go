// Package tools provides tool registration and management for the MCP server.
// This test file tests the tool registry functionality.
package tools

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
)

// Tool interface for testing
type Tool interface {
	Name() string
	Description() string
	InputSchema() interface{}
	Execute(ctx context.Context, args json.RawMessage) (interface{}, error)
}

// mockTool implements Tool for testing
type mockTool struct {
	name        string
	description string
	inputSchema interface{}
	executeFunc func(ctx context.Context, args json.RawMessage) (interface{}, error)
}

func (m *mockTool) Name() string             { return m.name }
func (m *mockTool) Description() string      { return m.description }
func (m *mockTool) InputSchema() interface{} { return m.inputSchema }

func (m *mockTool) Execute(ctx context.Context, args json.RawMessage) (interface{}, error) {
	if m.executeFunc != nil {
		return m.executeFunc(ctx, args)
	}
	return map[string]string{"result": "ok"}, nil
}

// Registry is a test implementation of the tool registry
type Registry struct {
	tools map[string]Tool
	mu    sync.RWMutex
}

// NewRegistry creates a new tool registry
func NewRegistry() *Registry {
	return &Registry{
		tools: make(map[string]Tool),
	}
}

// RegisterTool registers a tool with the registry
func (r *Registry) RegisterTool(name string, tool Tool) error {
	if name == "" {
		return errors.New("tool name cannot be empty")
	}
	if tool == nil {
		return errors.New("tool cannot be nil")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.tools[name]; exists {
		return errors.New("tool already registered: " + name)
	}

	r.tools[name] = tool
	return nil
}

// GetTool retrieves a tool by name
func (r *Registry) GetTool(name string) (Tool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	tool, ok := r.tools[name]
	if !ok {
		return nil, errors.New("tool not found: " + name)
	}
	return tool, nil
}

// ListTools returns all registered tools
func (r *Registry) ListTools() []Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	tools := make([]Tool, 0, len(r.tools))
	for _, t := range r.tools {
		tools = append(tools, t)
	}
	return tools
}

func TestRegistry_RegisterTool_New(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		toolName string
		tool     Tool
		wantErr  bool
	}{
		{
			name:     "register valid tool",
			toolName: "mytool",
			tool: &mockTool{
				name:        "mytool",
				description: "A test tool",
			},
			wantErr: false,
		},
		{
			name:     "register tool with complex name",
			toolName: "my-complex_tool.v1",
			tool: &mockTool{
				name:        "my-complex_tool.v1",
				description: "A tool with complex name",
			},
			wantErr: false,
		},
		{
			name:     "register tool with schema",
			toolName: "tool-with-schema",
			tool: &mockTool{
				name:        "tool-with-schema",
				description: "Tool with input schema",
				inputSchema: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"message": map[string]string{"type": "string"},
					},
				},
			},
			wantErr: false,
		},
		{
			name:     "register tool with execute function",
			toolName: "executable",
			tool: &mockTool{
				name:        "executable",
				description: "Executable tool",
				executeFunc: func(ctx context.Context, args json.RawMessage) (interface{}, error) {
					return map[string]string{"status": "executed"}, nil
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			registry := NewRegistry()
			err := registry.RegisterTool(tt.toolName, tt.tool)

			if (err != nil) != tt.wantErr {
				t.Errorf("RegisterTool() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr {
				// Verify tool was registered
				got, getErr := registry.GetTool(tt.toolName)
				if getErr != nil {
					t.Errorf("GetTool() after register failed: %v", getErr)
				}
				if got == nil {
					t.Error("GetTool() returned nil after successful register")
				}
			}
		})
	}
}

func TestRegistry_RegisterTool_Duplicate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		firstName  string
		secondName string
		wantErr    bool
	}{
		{
			name:       "duplicate name returns error",
			firstName:  "mytool",
			secondName: "mytool",
			wantErr:    true,
		},
		{
			name:       "different names succeed",
			firstName:  "tool1",
			secondName: "tool2",
			wantErr:    false,
		},
		{
			name:       "case sensitive names",
			firstName:  "MyTool",
			secondName: "mytool",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			registry := NewRegistry()

			// Register first tool
			err1 := registry.RegisterTool(tt.firstName, &mockTool{name: tt.firstName})
			if err1 != nil {
				t.Fatalf("First RegisterTool() failed: %v", err1)
			}

			// Try to register second tool
			err2 := registry.RegisterTool(tt.secondName, &mockTool{name: tt.secondName})
			if (err2 != nil) != tt.wantErr {
				t.Errorf("Second RegisterTool() error = %v, wantErr %v", err2, tt.wantErr)
			}
		})
	}
}

func TestRegistry_RegisterTool_EmptyName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		toolName string
		wantErr  bool
	}{
		{
			name:     "empty name returns error",
			toolName: "",
			wantErr:  true,
		},
		{
			name:     "valid name succeeds",
			toolName: "valid",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			registry := NewRegistry()
			err := registry.RegisterTool(tt.toolName, &mockTool{name: tt.toolName})

			if (err != nil) != tt.wantErr {
				t.Errorf("RegisterTool() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRegistry_RegisterTool_NilTool(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		toolName string
		tool     Tool
		wantErr  bool
	}{
		{
			name:     "nil tool returns error",
			toolName: "name",
			tool:     nil,
			wantErr:  true,
		},
		{
			name:     "valid tool succeeds",
			toolName: "name",
			tool:     &mockTool{name: "name"},
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			registry := NewRegistry()
			err := registry.RegisterTool(tt.toolName, tt.tool)

			if (err != nil) != tt.wantErr {
				t.Errorf("RegisterTool() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRegistry_GetTool_Exists(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		registerName string
		lookupName   string
		wantErr      bool
	}{
		{
			name:         "get existing tool",
			registerName: "mytool",
			lookupName:   "mytool",
			wantErr:      false,
		},
		{
			name:         "get with complex name",
			registerName: "my-tool_v1.0",
			lookupName:   "my-tool_v1.0",
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			registry := NewRegistry()
			_ = registry.RegisterTool(tt.registerName, &mockTool{
				name:        tt.registerName,
				description: "Test tool",
			})

			got, err := registry.GetTool(tt.lookupName)

			if (err != nil) != tt.wantErr {
				t.Errorf("GetTool() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr && got == nil {
				t.Error("GetTool() returned nil, want tool")
			}

			if !tt.wantErr && got != nil && got.Name() != tt.registerName {
				t.Errorf("GetTool() name = %q, want %q", got.Name(), tt.registerName)
			}
		})
	}
}

func TestRegistry_GetTool_NotFound(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		lookupName string
		wantErr    bool
	}{
		{
			name:       "get unknown tool returns error",
			lookupName: "unknown",
			wantErr:    true,
		},
		{
			name:       "get empty name returns error",
			lookupName: "",
			wantErr:    true,
		},
		{
			name:       "get with wrong case returns error",
			lookupName: "MYTOOL",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			registry := NewRegistry()
			// Register a tool with a different name
			_ = registry.RegisterTool("mytool", &mockTool{name: "mytool"})

			got, err := registry.GetTool(tt.lookupName)

			if (err != nil) != tt.wantErr {
				t.Errorf("GetTool() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr && got != nil {
				t.Error("GetTool() returned tool, want nil for error case")
			}
		})
	}
}

func TestRegistry_ListTools_Empty(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	tools := registry.ListTools()

	if tools == nil {
		t.Error("ListTools() returned nil, want empty slice")
	}

	if len(tools) != 0 {
		t.Errorf("ListTools() returned %d tools, want 0", len(tools))
	}
}

func TestRegistry_ListTools_Multiple(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		toolNames []string
		wantCount int
	}{
		{
			name:      "list single tool",
			toolNames: []string{"tool1"},
			wantCount: 1,
		},
		{
			name:      "list two tools",
			toolNames: []string{"tool1", "tool2"},
			wantCount: 2,
		},
		{
			name:      "list three tools",
			toolNames: []string{"tool1", "tool2", "tool3"},
			wantCount: 3,
		},
		{
			name:      "list many tools",
			toolNames: []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"},
			wantCount: 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			registry := NewRegistry()
			for _, name := range tt.toolNames {
				_ = registry.RegisterTool(name, &mockTool{name: name})
			}

			tools := registry.ListTools()

			if len(tools) != tt.wantCount {
				t.Errorf("ListTools() returned %d tools, want %d", len(tools), tt.wantCount)
			}

			// Verify all registered tools are present
			toolMap := make(map[string]bool)
			for _, tool := range tools {
				toolMap[tool.Name()] = true
			}

			for _, name := range tt.toolNames {
				if !toolMap[name] {
					t.Errorf("ListTools() missing tool %q", name)
				}
			}
		})
	}
}

func TestRegistry_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	var wg sync.WaitGroup
	errChan := make(chan error, 200)

	// Concurrent registration
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			name := "tool" + string(rune('A'+idx%26)) + string(rune('0'+idx/26))
			err := registry.RegisterTool(name, &mockTool{name: name})
			// Only report unexpected errors (duplicates are expected due to name collision)
			if err != nil && idx < 26 {
				errChan <- err
			}
		}(i)
	}

	// Concurrent reads
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			name := "tool" + string(rune('A'+idx%26)) + string(rune('0'+idx/26))
			_, _ = registry.GetTool(name)
			_ = registry.ListTools()
		}(i)
	}

	wg.Wait()
	close(errChan)

	var errCount int
	for range errChan {
		errCount++
	}

	if errCount > 0 {
		t.Errorf("Got %d unexpected errors during concurrent access", errCount)
	}
}

func TestRegistry_ConcurrentRegisterAndGet(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()

	// Pre-register some tools
	for i := 0; i < 10; i++ {
		name := "preset" + string(rune('0'+i))
		_ = registry.RegisterTool(name, &mockTool{name: name})
	}

	var wg sync.WaitGroup
	successfulGets := make(chan string, 1000)

	// Concurrent gets of pre-registered tools
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			name := "preset" + string(rune('0'+idx%10))
			tool, err := registry.GetTool(name)
			if err == nil && tool != nil {
				successfulGets <- name
			}
		}(i)
	}

	wg.Wait()
	close(successfulGets)

	getCount := 0
	for range successfulGets {
		getCount++
	}

	if getCount != 100 {
		t.Errorf("Got %d successful gets, want 100", getCount)
	}
}

func TestRegistry_ListToolsDoesNotModify(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	_ = registry.RegisterTool("tool1", &mockTool{name: "tool1"})
	_ = registry.RegisterTool("tool2", &mockTool{name: "tool2"})

	// Get the list
	tools1 := registry.ListTools()
	originalLen := len(tools1)

	// Modify the returned slice (should not affect registry)
	if len(tools1) > 0 {
		tools1[0] = nil
	}

	// Get the list again
	tools2 := registry.ListTools()

	if len(tools2) != originalLen {
		t.Errorf("ListTools() length changed after modification: got %d, want %d", len(tools2), originalLen)
	}

	// Verify tools are still accessible
	for _, tool := range tools2 {
		if tool == nil {
			t.Error("ListTools() returned nil tool after external modification")
		}
	}
}

func TestRegistry_ToolExecution(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()

	executed := false
	_ = registry.RegisterTool("executor", &mockTool{
		name: "executor",
		executeFunc: func(ctx context.Context, args json.RawMessage) (interface{}, error) {
			executed = true
			return map[string]string{"status": "done"}, nil
		},
	})

	tool, err := registry.GetTool("executor")
	if err != nil {
		t.Fatalf("GetTool() failed: %v", err)
	}

	result, err := tool.Execute(context.Background(), nil)
	if err != nil {
		t.Fatalf("Execute() failed: %v", err)
	}

	if !executed {
		t.Error("Execute() did not call the execute function")
	}

	if result == nil {
		t.Error("Execute() returned nil result")
	}
}

func TestRegistry_ToolExecutionError(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()

	expectedErr := errors.New("execution failed")
	_ = registry.RegisterTool("failing", &mockTool{
		name: "failing",
		executeFunc: func(ctx context.Context, args json.RawMessage) (interface{}, error) {
			return nil, expectedErr
		},
	})

	tool, err := registry.GetTool("failing")
	if err != nil {
		t.Fatalf("GetTool() failed: %v", err)
	}

	_, execErr := tool.Execute(context.Background(), nil)
	if execErr == nil {
		t.Error("Execute() expected error, got nil")
	}

	if !errors.Is(execErr, expectedErr) {
		t.Errorf("Execute() error = %v, want %v", execErr, expectedErr)
	}
}

func TestRegistry_ToolWithArguments(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()

	_ = registry.RegisterTool("echo", &mockTool{
		name: "echo",
		executeFunc: func(ctx context.Context, args json.RawMessage) (interface{}, error) {
			var input struct {
				Message string `json:"message"`
			}
			if err := json.Unmarshal(args, &input); err != nil {
				return nil, err
			}
			return map[string]string{"echo": input.Message}, nil
		},
	})

	tool, _ := registry.GetTool("echo")
	result, err := tool.Execute(context.Background(), json.RawMessage(`{"message":"hello"}`))
	if err != nil {
		t.Fatalf("Execute() failed: %v", err)
	}

	resultMap, ok := result.(map[string]string)
	if !ok {
		t.Fatalf("Execute() result type = %T, want map[string]string", result)
	}

	if resultMap["echo"] != "hello" {
		t.Errorf("Execute() result[echo] = %q, want %q", resultMap["echo"], "hello")
	}
}

// Benchmark tests
func BenchmarkRegistry_RegisterTool(b *testing.B) {
	for i := 0; i < b.N; i++ {
		registry := NewRegistry()
		_ = registry.RegisterTool("tool", &mockTool{name: "tool"})
	}
}

func BenchmarkRegistry_GetTool(b *testing.B) {
	registry := NewRegistry()
	_ = registry.RegisterTool("tool", &mockTool{name: "tool"})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = registry.GetTool("tool")
	}
}

func BenchmarkRegistry_ListTools_10(b *testing.B) {
	registry := NewRegistry()
	for i := 0; i < 10; i++ {
		name := "tool" + string(rune('A'+i))
		_ = registry.RegisterTool(name, &mockTool{name: name})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = registry.ListTools()
	}
}

func BenchmarkRegistry_ListTools_100(b *testing.B) {
	registry := NewRegistry()
	for i := 0; i < 100; i++ {
		name := "tool" + string(rune('A'+i%26)) + string(rune('0'+i/26))
		_ = registry.RegisterTool(name, &mockTool{name: name})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = registry.ListTools()
	}
}

func BenchmarkRegistry_ConcurrentGet(b *testing.B) {
	registry := NewRegistry()
	for i := 0; i < 10; i++ {
		name := "tool" + string(rune('A'+i))
		_ = registry.RegisterTool(name, &mockTool{name: name})
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			name := "tool" + string(rune('A'+i%10))
			_, _ = registry.GetTool(name)
			i++
		}
	})
}
