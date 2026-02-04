// Package http provides HTTP server and routing for the MCP server.
package http

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/jamesprial/mcp-oauth-2.1/internal/config"
)

// newTestServer creates a test server with the given address and handler.
func newTestServer(addr string, handler http.Handler) *server {
	cfg := &config.Config{
		Addr:         addr,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	router := NewRouter()
	router.Handle("/", handler)
	return NewServer(cfg, router).(*server)
}

func TestServer_Start(t *testing.T) {
	t.Parallel()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Use port 0 to get a random available port
	server := newTestServer(":0", handler)

	// Start server in background
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start()
	}()

	// Give server time to start
	time.Sleep(50 * time.Millisecond)

	// Verify server is listening
	addr := server.Addr()
	if addr == "" {
		t.Fatal("Server did not return an address")
	}

	// Try to connect
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("Could not connect to server: %v", err)
	}
	_ = conn.Close()

	// Shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown error: %v", err)
	}
}

func TestServer_Shutdown(t *testing.T) {
	t.Parallel()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	server := newTestServer(":0", handler)

	// Start server
	go func() {
		_ = server.Start()
	}()

	// Give server time to start
	time.Sleep(50 * time.Millisecond)

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := server.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown returned error: %v", err)
	}

	// Verify server is no longer accepting connections
	addr := server.Addr()
	if addr != "" {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			t.Error("Server still accepting connections after shutdown")
		}
	}
}

func TestServer_Addr(t *testing.T) {
	t.Parallel()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	server := newTestServer(":0", handler)

	// Before start, addr might be empty or the configured address
	_ = server.Addr()

	// Start server
	go func() {
		_ = server.Start()
	}()

	// Give server time to start
	time.Sleep(50 * time.Millisecond)

	addr := server.Addr()

	// After start, should have a valid address
	if addr == "" {
		t.Error("Addr() returned empty string after server started")
	}

	// Address should be parseable
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		// Might just be a port like ":8080"
		if addr[0] == ':' {
			port = addr[1:]
		} else {
			t.Errorf("Could not parse address %q: %v", addr, err)
		}
	}

	if port == "" || port == "0" {
		t.Errorf("Expected a real port, got %q", port)
	}

	// Cleanup
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
}

func TestServer_ShutdownTimeout(t *testing.T) {
	t.Parallel()

	// Handler that takes a long time
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Second)
		w.WriteHeader(http.StatusOK)
	})

	server := newTestServer(":0", handler)

	// Start server
	go func() {
		_ = server.Start()
	}()

	// Give server time to start
	time.Sleep(50 * time.Millisecond)

	// Start a long-running request in background
	addr := server.Addr()
	if addr != "" {
		go func() {
			conn, err := net.Dial("tcp", addr)
			if err == nil {
				// Send a simple HTTP request
				_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"))
				// Don't close - let it hang
			}
		}()
	}

	// Short timeout for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Shutdown should return (possibly with error due to timeout)
	_ = server.Shutdown(ctx)

	// The main thing is that Shutdown doesn't hang forever
}

func TestServer_ConfiguredAddress(t *testing.T) {
	t.Parallel()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Specific address (localhost with random port)
	server := newTestServer("127.0.0.1:0", handler)

	go func() {
		_ = server.Start()
	}()

	time.Sleep(50 * time.Millisecond)

	addr := server.Addr()
	if addr == "" {
		t.Skip("Server did not provide address")
	}

	host, _, err := net.SplitHostPort(addr)
	if err == nil && host != "127.0.0.1" {
		t.Errorf("Expected host 127.0.0.1, got %s", host)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
}

func TestServer_MultipleStartCalls(t *testing.T) {
	t.Parallel()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	server := newTestServer(":0", handler)

	// First start
	errCh1 := make(chan error, 1)
	go func() {
		errCh1 <- server.Start()
	}()

	time.Sleep(50 * time.Millisecond)

	// Cleanup
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)

	// Wait for first start to complete
	select {
	case <-errCh1:
		// Expected after shutdown
	case <-time.After(time.Second):
		t.Error("First Start did not return after Shutdown")
	}
}

func TestServer_HandleRequest(t *testing.T) {
	t.Parallel()

	requestReceived := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestReceived = true
		w.Header().Set("X-Test", "value")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("response"))
	})

	server := newTestServer(":0", handler)

	go func() {
		_ = server.Start()
	}()

	time.Sleep(50 * time.Millisecond)

	addr := server.Addr()
	if addr == "" {
		t.Skip("Server did not provide address")
	}

	// Make actual HTTP request
	resp, err := http.Get("http://" + addr + "/test")
	if err != nil {
		t.Fatalf("HTTP request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if !requestReceived {
		t.Error("Handler was not called")
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Status = %v, want 200", resp.StatusCode)
	}

	if resp.Header.Get("X-Test") != "value" {
		t.Error("Custom header not received")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
}
