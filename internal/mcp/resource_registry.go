package mcp

import (
	"context"
	"fmt"
	"sync"

	internalerrors "github.com/jamesprial/mcp-oauth-2.1/internal/errors"
)

// resourceRegistry implements ResourceRegistry with thread-safe access.
type resourceRegistry struct {
	mu        sync.RWMutex
	providers map[string]ResourceProvider
}

// NewResourceRegistry creates a new thread-safe resource registry.
func NewResourceRegistry() ResourceRegistry {
	return &resourceRegistry{
		providers: make(map[string]ResourceProvider),
	}
}

// RegisterResource registers a resource provider for the given URI.
// Returns an error if a resource with the same URI is already registered
// or if the URI or provider is invalid.
func (r *resourceRegistry) RegisterResource(uri string, provider ResourceProvider) error {
	if uri == "" {
		return internalerrors.New("mcp", "RegisterResource", internalerrors.ErrBadRequest, fmt.Errorf("resource uri cannot be empty"))
	}
	if provider == nil {
		return internalerrors.New("mcp", "RegisterResource", internalerrors.ErrBadRequest, fmt.Errorf("resource provider cannot be nil"))
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.providers[uri]; exists {
		return internalerrors.New("mcp", "RegisterResource", internalerrors.ErrBadRequest, ErrResourceAlreadyRegistered).
			WithContext("resource_uri", uri)
	}

	r.providers[uri] = provider
	return nil
}

// GetResource retrieves a resource by URI and reads its content.
// Returns ErrResourceNotFound if the resource does not exist.
func (r *resourceRegistry) GetResource(ctx context.Context, uri string) (*Resource, error) {
	if uri == "" {
		return nil, internalerrors.New("mcp", "GetResource", internalerrors.ErrBadRequest, fmt.Errorf("resource uri cannot be empty"))
	}

	r.mu.RLock()
	provider, exists := r.providers[uri]
	r.mu.RUnlock()

	if !exists {
		return nil, internalerrors.New("mcp", "GetResource", internalerrors.ErrNotFound, ErrResourceNotFound).
			WithContext("resource_uri", uri)
	}

	// Read the resource content (outside the lock to allow concurrent reads)
	resource, err := provider.Read(ctx)
	if err != nil {
		return nil, internalerrors.New("mcp", "GetResource", internalerrors.ErrInternal, fmt.Errorf("failed to read resource: %w", err)).
			WithContext("resource_uri", uri)
	}

	return resource, nil
}

// ListResources returns definitions for all registered resources.
// The returned slice is a snapshot and safe for concurrent access.
func (r *resourceRegistry) ListResources() []ResourceDefinition {
	r.mu.RLock()
	defer r.mu.RUnlock()

	definitions := make([]ResourceDefinition, 0, len(r.providers))
	for _, provider := range r.providers {
		definitions = append(definitions, provider.Definition())
	}

	return definitions
}
