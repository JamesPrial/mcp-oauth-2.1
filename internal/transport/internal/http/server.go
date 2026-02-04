// Package http provides HTTP server implementation for the transport layer.
package http

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/jamesprial/mcp-oauth-2.1/internal/config"
	"github.com/jamesprial/mcp-oauth-2.1/internal/transport/transportcore"
)

// server implements transportcore.Server using net/http.Server.
type server struct {
	httpServer *http.Server
	mu         sync.RWMutex
	listener   net.Listener
}

// NewServer creates a new HTTP server with the provided configuration and router.
// The server is configured with timeouts and the router as its handler.
func NewServer(cfg *config.Config, router transportcore.Router) transportcore.Server {
	if cfg == nil {
		panic("config cannot be nil")
	}
	if router == nil {
		panic("router cannot be nil")
	}

	httpServer := &http.Server{
		Addr:         cfg.Addr,
		Handler:      router,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}

	return &server{
		httpServer: httpServer,
	}
}

// Start begins serving HTTP requests on the configured address.
// This is a blocking call that returns when the server stops or encounters an error.
func (s *server) Start() error {
	listener, err := net.Listen("tcp", s.httpServer.Addr)
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}

	s.mu.Lock()
	s.listener = listener
	s.mu.Unlock()

	if err := s.httpServer.Serve(listener); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}

	return nil
}

// Shutdown gracefully shuts down the server without interrupting active connections.
// It waits for active connections to close or the context to be cancelled/expired.
func (s *server) Shutdown(ctx context.Context) error {
	if s.httpServer == nil {
		return transportcore.ErrServerClosed
	}

	// Set a reasonable deadline if the context doesn't have one
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
	}

	if err := s.httpServer.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown failed: %w", err)
	}

	return nil
}

// Addr returns the address the server is listening on.
// This is useful when the server is configured to bind to a random port (":0").
func (s *server) Addr() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.listener == nil {
		return s.httpServer.Addr
	}
	return s.listener.Addr().String()
}
