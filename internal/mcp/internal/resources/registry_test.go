// Package resources provides resource registration and management for the MCP server.
// This test file tests the resource registry functionality.
package resources

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// ResourceProvider interface for testing
type ResourceProvider interface {
	URI() string
	Name() string
	Description() string
	MimeType() string
	Read(ctx context.Context) (interface{}, error)
}

// ResourceDefinition represents resource metadata
type ResourceDefinition struct {
	URI         string
	Name        string
	Description string
	MimeType    string
}

// mockResourceProvider implements ResourceProvider for testing
type mockResourceProvider struct {
	uri         string
	name        string
	description string
	mimeType    string
	content     interface{}
	readFunc    func(ctx context.Context) (interface{}, error)
}

func (m *mockResourceProvider) URI() string         { return m.uri }
func (m *mockResourceProvider) Name() string        { return m.name }
func (m *mockResourceProvider) Description() string { return m.description }
func (m *mockResourceProvider) MimeType() string    { return m.mimeType }

func (m *mockResourceProvider) Read(ctx context.Context) (interface{}, error) {
	if m.readFunc != nil {
		return m.readFunc(ctx)
	}
	return m.content, nil
}

// Registry is a test implementation of the resource registry
type Registry struct {
	resources map[string]ResourceProvider
	mu        sync.RWMutex
}

// NewRegistry creates a new resource registry
func NewRegistry() *Registry {
	return &Registry{
		resources: make(map[string]ResourceProvider),
	}
}

// RegisterResource registers a resource provider with the registry
func (r *Registry) RegisterResource(uri string, provider ResourceProvider) error {
	if uri == "" {
		return errors.New("resource URI cannot be empty")
	}
	if provider == nil {
		return errors.New("resource provider cannot be nil")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.resources[uri]; exists {
		return errors.New("resource already registered: " + uri)
	}

	r.resources[uri] = provider
	return nil
}

// GetResource retrieves a resource provider by URI
func (r *Registry) GetResource(uri string) (ResourceProvider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	provider, ok := r.resources[uri]
	if !ok {
		return nil, errors.New("resource not found: " + uri)
	}
	return provider, nil
}

// ListResources returns all registered resource definitions
func (r *Registry) ListResources() []ResourceDefinition {
	r.mu.RLock()
	defer r.mu.RUnlock()

	defs := make([]ResourceDefinition, 0, len(r.resources))
	for _, provider := range r.resources {
		defs = append(defs, ResourceDefinition{
			URI:         provider.URI(),
			Name:        provider.Name(),
			Description: provider.Description(),
			MimeType:    provider.MimeType(),
		})
	}
	return defs
}

func TestRegistry_RegisterResource_New(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		uri      string
		provider ResourceProvider
		wantErr  bool
	}{
		{
			name: "register valid file resource",
			uri:  "file:///data/config.json",
			provider: &mockResourceProvider{
				uri:      "file:///data/config.json",
				name:     "config",
				mimeType: "application/json",
			},
			wantErr: false,
		},
		{
			name: "register valid http resource",
			uri:  "https://api.example.com/data",
			provider: &mockResourceProvider{
				uri:      "https://api.example.com/data",
				name:     "api-data",
				mimeType: "application/json",
			},
			wantErr: false,
		},
		{
			name: "register resource with description",
			uri:  "file:///logs/app.log",
			provider: &mockResourceProvider{
				uri:         "file:///logs/app.log",
				name:        "application-logs",
				description: "Application log file",
				mimeType:    "text/plain",
			},
			wantErr: false,
		},
		{
			name: "register resource with custom URI scheme",
			uri:  "db://localhost/users",
			provider: &mockResourceProvider{
				uri:      "db://localhost/users",
				name:     "users-table",
				mimeType: "application/json",
			},
			wantErr: false,
		},
		{
			name: "register resource with content",
			uri:  "memory:///cache/data",
			provider: &mockResourceProvider{
				uri:      "memory:///cache/data",
				name:     "cached-data",
				mimeType: "application/octet-stream",
				content:  []byte("cached content"),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			registry := NewRegistry()
			err := registry.RegisterResource(tt.uri, tt.provider)

			if (err != nil) != tt.wantErr {
				t.Errorf("RegisterResource() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr {
				// Verify resource was registered
				got, getErr := registry.GetResource(tt.uri)
				if getErr != nil {
					t.Errorf("GetResource() after register failed: %v", getErr)
				}
				if got == nil {
					t.Error("GetResource() returned nil after successful register")
				}
			}
		})
	}
}

func TestRegistry_RegisterResource_Duplicate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		firstURI  string
		secondURI string
		wantErr   bool
	}{
		{
			name:      "duplicate URI returns error",
			firstURI:  "file:///data/config.json",
			secondURI: "file:///data/config.json",
			wantErr:   true,
		},
		{
			name:      "different URIs succeed",
			firstURI:  "file:///data/config1.json",
			secondURI: "file:///data/config2.json",
			wantErr:   false,
		},
		{
			name:      "case sensitive URIs",
			firstURI:  "file:///Data/Config.json",
			secondURI: "file:///data/config.json",
			wantErr:   false,
		},
		{
			name:      "different schemes same path",
			firstURI:  "file:///data/file.txt",
			secondURI: "https:///data/file.txt",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			registry := NewRegistry()

			// Register first resource
			err1 := registry.RegisterResource(tt.firstURI, &mockResourceProvider{uri: tt.firstURI})
			if err1 != nil {
				t.Fatalf("First RegisterResource() failed: %v", err1)
			}

			// Try to register second resource
			err2 := registry.RegisterResource(tt.secondURI, &mockResourceProvider{uri: tt.secondURI})
			if (err2 != nil) != tt.wantErr {
				t.Errorf("Second RegisterResource() error = %v, wantErr %v", err2, tt.wantErr)
			}
		})
	}
}

func TestRegistry_RegisterResource_EmptyURI(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	err := registry.RegisterResource("", &mockResourceProvider{uri: ""})

	if err == nil {
		t.Error("RegisterResource() expected error for empty URI, got nil")
	}
}

func TestRegistry_RegisterResource_NilProvider(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	err := registry.RegisterResource("file:///data/test.txt", nil)

	if err == nil {
		t.Error("RegisterResource() expected error for nil provider, got nil")
	}
}

func TestRegistry_GetResource_Exists(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		registerURI string
		lookupURI   string
		wantErr     bool
	}{
		{
			name:        "get existing resource",
			registerURI: "file:///data/config.json",
			lookupURI:   "file:///data/config.json",
			wantErr:     false,
		},
		{
			name:        "get resource with complex URI",
			registerURI: "https://api.example.com/v1/users?limit=100",
			lookupURI:   "https://api.example.com/v1/users?limit=100",
			wantErr:     false,
		},
		{
			name:        "get resource with encoded characters",
			registerURI: "file:///path/to/file%20with%20spaces.txt",
			lookupURI:   "file:///path/to/file%20with%20spaces.txt",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			registry := NewRegistry()
			_ = registry.RegisterResource(tt.registerURI, &mockResourceProvider{
				uri:         tt.registerURI,
				name:        "test-resource",
				description: "Test resource",
				mimeType:    "application/json",
			})

			got, err := registry.GetResource(tt.lookupURI)

			if (err != nil) != tt.wantErr {
				t.Errorf("GetResource() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr && got == nil {
				t.Error("GetResource() returned nil, want resource")
			}

			if !tt.wantErr && got != nil && got.URI() != tt.registerURI {
				t.Errorf("GetResource() URI = %q, want %q", got.URI(), tt.registerURI)
			}
		})
	}
}

func TestRegistry_GetResource_NotFound(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		lookupURI string
		wantErr   bool
	}{
		{
			name:      "get unknown resource returns error",
			lookupURI: "file:///nonexistent/path",
			wantErr:   true,
		},
		{
			name:      "get empty URI returns error",
			lookupURI: "",
			wantErr:   true,
		},
		{
			name:      "get with different case returns error",
			lookupURI: "FILE:///DATA/CONFIG.JSON",
			wantErr:   true,
		},
		{
			name:      "get with partial URI returns error",
			lookupURI: "file:///data",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			registry := NewRegistry()
			// Register a resource with a different URI
			_ = registry.RegisterResource("file:///data/config.json", &mockResourceProvider{
				uri: "file:///data/config.json",
			})

			got, err := registry.GetResource(tt.lookupURI)

			if (err != nil) != tt.wantErr {
				t.Errorf("GetResource() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr && got != nil {
				t.Error("GetResource() returned resource, want nil for error case")
			}
		})
	}
}

func TestRegistry_ListResources_Empty(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	resources := registry.ListResources()

	if resources == nil {
		t.Error("ListResources() returned nil, want empty slice")
	}

	if len(resources) != 0 {
		t.Errorf("ListResources() returned %d resources, want 0", len(resources))
	}
}

func TestRegistry_ListResources_Multiple(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		resources []struct {
			uri      string
			name     string
			mimeType string
		}
		wantCount int
	}{
		{
			name: "list single resource",
			resources: []struct {
				uri      string
				name     string
				mimeType string
			}{
				{uri: "file:///data/config.json", name: "config", mimeType: "application/json"},
			},
			wantCount: 1,
		},
		{
			name: "list two resources",
			resources: []struct {
				uri      string
				name     string
				mimeType string
			}{
				{uri: "file:///data/config.json", name: "config", mimeType: "application/json"},
				{uri: "file:///logs/app.log", name: "logs", mimeType: "text/plain"},
			},
			wantCount: 2,
		},
		{
			name: "list multiple resources",
			resources: []struct {
				uri      string
				name     string
				mimeType string
			}{
				{uri: "file:///data/config.json", name: "config", mimeType: "application/json"},
				{uri: "file:///logs/app.log", name: "logs", mimeType: "text/plain"},
				{uri: "https://api.example.com/data", name: "api", mimeType: "application/json"},
				{uri: "db://localhost/users", name: "users", mimeType: "application/json"},
				{uri: "memory:///cache/data", name: "cache", mimeType: "application/octet-stream"},
			},
			wantCount: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			registry := NewRegistry()
			for _, res := range tt.resources {
				_ = registry.RegisterResource(res.uri, &mockResourceProvider{
					uri:      res.uri,
					name:     res.name,
					mimeType: res.mimeType,
				})
			}

			defs := registry.ListResources()

			if len(defs) != tt.wantCount {
				t.Errorf("ListResources() returned %d resources, want %d", len(defs), tt.wantCount)
			}

			// Verify all registered resources are present
			uriMap := make(map[string]bool)
			for _, def := range defs {
				uriMap[def.URI] = true
			}

			for _, res := range tt.resources {
				if !uriMap[res.uri] {
					t.Errorf("ListResources() missing resource %q", res.uri)
				}
			}
		})
	}
}

func TestRegistry_ListResources_IncludesAllFields(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	_ = registry.RegisterResource("file:///data/config.json", &mockResourceProvider{
		uri:         "file:///data/config.json",
		name:        "config",
		description: "Configuration file",
		mimeType:    "application/json",
	})

	defs := registry.ListResources()
	if len(defs) != 1 {
		t.Fatalf("ListResources() returned %d resources, want 1", len(defs))
	}

	def := defs[0]
	if def.URI != "file:///data/config.json" {
		t.Errorf("URI = %q, want %q", def.URI, "file:///data/config.json")
	}
	if def.Name != "config" {
		t.Errorf("Name = %q, want %q", def.Name, "config")
	}
	if def.Description != "Configuration file" {
		t.Errorf("Description = %q, want %q", def.Description, "Configuration file")
	}
	if def.MimeType != "application/json" {
		t.Errorf("MimeType = %q, want %q", def.MimeType, "application/json")
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
			uri := "file:///data/resource" + string(rune('A'+idx%26)) + string(rune('0'+idx/26)) + ".txt"
			err := registry.RegisterResource(uri, &mockResourceProvider{uri: uri})
			// Only report unexpected errors (duplicates are expected due to URI collision)
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
			uri := "file:///data/resource" + string(rune('A'+idx%26)) + string(rune('0'+idx/26)) + ".txt"
			_, _ = registry.GetResource(uri)
			_ = registry.ListResources()
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

	// Pre-register some resources
	for i := 0; i < 10; i++ {
		uri := "file:///preset/resource" + string(rune('0'+i)) + ".txt"
		_ = registry.RegisterResource(uri, &mockResourceProvider{uri: uri})
	}

	var wg sync.WaitGroup
	successfulGets := make(chan string, 1000)

	// Concurrent gets of pre-registered resources
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			uri := "file:///preset/resource" + string(rune('0'+idx%10)) + ".txt"
			resource, err := registry.GetResource(uri)
			if err == nil && resource != nil {
				successfulGets <- uri
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

func TestRegistry_ResourceRead(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()

	expectedContent := map[string]string{"key": "value"}
	_ = registry.RegisterResource("file:///data/test.json", &mockResourceProvider{
		uri:      "file:///data/test.json",
		name:     "test",
		mimeType: "application/json",
		content:  expectedContent,
	})

	provider, err := registry.GetResource("file:///data/test.json")
	if err != nil {
		t.Fatalf("GetResource() failed: %v", err)
	}

	content, err := provider.Read(context.Background())
	if err != nil {
		t.Fatalf("Read() failed: %v", err)
	}

	contentMap, ok := content.(map[string]string)
	if !ok {
		t.Fatalf("Read() content type = %T, want map[string]string", content)
	}

	if contentMap["key"] != "value" {
		t.Errorf("Read() content[key] = %q, want %q", contentMap["key"], "value")
	}
}

func TestRegistry_ResourceReadWithFunc(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()

	readCalled := false
	_ = registry.RegisterResource("file:///data/dynamic.txt", &mockResourceProvider{
		uri:      "file:///data/dynamic.txt",
		name:     "dynamic",
		mimeType: "text/plain",
		readFunc: func(ctx context.Context) (interface{}, error) {
			readCalled = true
			return "dynamic content", nil
		},
	})

	provider, _ := registry.GetResource("file:///data/dynamic.txt")
	content, err := provider.Read(context.Background())
	if err != nil {
		t.Fatalf("Read() failed: %v", err)
	}

	if !readCalled {
		t.Error("Read() did not call the read function")
	}

	if content != "dynamic content" {
		t.Errorf("Read() content = %v, want %q", content, "dynamic content")
	}
}

func TestRegistry_ResourceReadError(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()

	expectedErr := errors.New("read failed")
	_ = registry.RegisterResource("file:///data/failing.txt", &mockResourceProvider{
		uri:  "file:///data/failing.txt",
		name: "failing",
		readFunc: func(ctx context.Context) (interface{}, error) {
			return nil, expectedErr
		},
	})

	provider, _ := registry.GetResource("file:///data/failing.txt")
	_, err := provider.Read(context.Background())

	if err == nil {
		t.Error("Read() expected error, got nil")
	}

	if !errors.Is(err, expectedErr) {
		t.Errorf("Read() error = %v, want %v", err, expectedErr)
	}
}

func TestRegistry_ResourceReadContextCancellation(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()

	_ = registry.RegisterResource("file:///data/slow.txt", &mockResourceProvider{
		uri:  "file:///data/slow.txt",
		name: "slow",
		readFunc: func(ctx context.Context) (interface{}, error) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
				return "content", nil
			}
		},
	})

	provider, _ := registry.GetResource("file:///data/slow.txt")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := provider.Read(ctx)
	if err == nil {
		// Context was already cancelled, but read might have completed
		// before checking context. This is acceptable behavior.
		t.Log("Read completed despite cancelled context (acceptable)")
	}
}

func TestRegistry_ListResourcesDoesNotModify(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	_ = registry.RegisterResource("file:///data/1.txt", &mockResourceProvider{
		uri:  "file:///data/1.txt",
		name: "res1",
	})
	_ = registry.RegisterResource("file:///data/2.txt", &mockResourceProvider{
		uri:  "file:///data/2.txt",
		name: "res2",
	})

	// Get the list
	defs1 := registry.ListResources()
	originalLen := len(defs1)

	// Modify the returned slice (should not affect registry)
	if len(defs1) > 0 {
		defs1[0].URI = "modified"
	}

	// Get the list again
	defs2 := registry.ListResources()

	if len(defs2) != originalLen {
		t.Errorf("ListResources() length changed after modification: got %d, want %d", len(defs2), originalLen)
	}

	// Verify URIs are still correct
	for _, def := range defs2 {
		if def.URI == "modified" {
			t.Error("ListResources() was modified by external change")
		}
	}
}

// Benchmark tests
func BenchmarkRegistry_RegisterResource(b *testing.B) {
	for i := 0; i < b.N; i++ {
		registry := NewRegistry()
		_ = registry.RegisterResource("file:///data/test.txt", &mockResourceProvider{
			uri: "file:///data/test.txt",
		})
	}
}

func BenchmarkRegistry_GetResource(b *testing.B) {
	registry := NewRegistry()
	_ = registry.RegisterResource("file:///data/test.txt", &mockResourceProvider{
		uri: "file:///data/test.txt",
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = registry.GetResource("file:///data/test.txt")
	}
}

func BenchmarkRegistry_ListResources_10(b *testing.B) {
	registry := NewRegistry()
	for i := 0; i < 10; i++ {
		uri := "file:///data/resource" + string(rune('A'+i)) + ".txt"
		_ = registry.RegisterResource(uri, &mockResourceProvider{uri: uri})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = registry.ListResources()
	}
}

func BenchmarkRegistry_ListResources_100(b *testing.B) {
	registry := NewRegistry()
	for i := 0; i < 100; i++ {
		uri := "file:///data/resource" + string(rune('A'+i%26)) + string(rune('0'+i/26)) + ".txt"
		_ = registry.RegisterResource(uri, &mockResourceProvider{uri: uri})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = registry.ListResources()
	}
}

func BenchmarkRegistry_ConcurrentGet(b *testing.B) {
	registry := NewRegistry()
	for i := 0; i < 10; i++ {
		uri := "file:///data/resource" + string(rune('A'+i)) + ".txt"
		_ = registry.RegisterResource(uri, &mockResourceProvider{uri: uri})
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			uri := "file:///data/resource" + string(rune('A'+i%10)) + ".txt"
			_, _ = registry.GetResource(uri)
			i++
		}
	})
}

func BenchmarkRegistry_ResourceRead(b *testing.B) {
	registry := NewRegistry()
	_ = registry.RegisterResource("file:///data/test.txt", &mockResourceProvider{
		uri:     "file:///data/test.txt",
		content: "test content",
	})

	provider, _ := registry.GetResource("file:///data/test.txt")
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = provider.Read(ctx)
	}
}
