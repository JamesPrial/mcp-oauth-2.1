// Package main provides the entry point for the OAuth 2.1 MCP server.
// It wires together all components using dependency injection and manages
// the server lifecycle with graceful shutdown.
package main

import (
	"context"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jamesprial/mcp-oauth-2.1/internal/config"
	"github.com/jamesprial/mcp-oauth-2.1/internal/mcp"
	"github.com/jamesprial/mcp-oauth-2.1/internal/oauth"
	"github.com/jamesprial/mcp-oauth-2.1/internal/transport"
)

func main() {
	// Set up structured logging
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	// Load configuration from environment
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	slog.Info("server configuration loaded",
		"addr", cfg.Addr,
		"base_url", cfg.BaseURL,
		"auth_servers", cfg.AuthorizationServers,
	)

	// Wire OAuth components
	oauthCfg := &oauth.Config{
		BaseURL:              cfg.BaseURL,
		AuthorizationServers: cfg.AuthorizationServers,
		Audience:             cfg.Audience,
		ScopesSupported:      cfg.ScopesSupported,
		JWKSCacheTTL:         cfg.JWKSCacheTTL,
		ClockSkew:            cfg.ClockSkew,
	}

	tokenValidator, metadataService, scopeChecker, jwksClient := oauth.NewOAuthServices(oauthCfg)
	_ = scopeChecker // Currently unused but available for future scope checking
	_ = jwksClient   // Currently unused but available for manual key refresh

	slog.Info("oauth services initialized",
		"jwks_cache_ttl", cfg.JWKSCacheTTL,
		"clock_skew", cfg.ClockSkew,
	)

	// Wire MCP components
	mcpCfg := &mcp.Config{
		ServerName:    "mcp-oauth-2.1",
		ServerVersion: "1.0.0",
	}

	mcpHandler, toolRegistry, resourceRegistry := mcp.NewMCPServices(mcpCfg)
	_ = toolRegistry     // Available for registering custom tools
	_ = resourceRegistry // Available for registering custom resources

	slog.Info("mcp services initialized",
		"server_name", mcpCfg.ServerName,
		"server_version", mcpCfg.ServerVersion,
	)

	// Wire transport layer
	transportCfg := &transport.Config{
		ServerConfig:    cfg,
		OAuthValidator:  tokenValidator,
		MetadataService: metadataService,
		MCPHandler:      mcpHandler,
	}

	server, router, err := transport.NewTransportServices(transportCfg)
	if err != nil {
		log.Fatalf("failed to create transport services: %v", err)
	}
	_ = router // Router is used internally by server

	slog.Info("transport services initialized",
		"metadata_url", metadataService.GetMetadataURL(),
	)

	// Create context for graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Start server in background goroutine
	serverErrCh := make(chan error, 1)
	go func() {
		slog.Info("starting server", "addr", cfg.Addr)
		if err := server.Start(); err != nil {
			serverErrCh <- err
		}
	}()

	// Wait for shutdown signal or server error
	select {
	case <-ctx.Done():
		slog.Info("shutdown signal received, stopping server gracefully...")
	case err := <-serverErrCh:
		slog.Error("server error", "error", err)
		stop()
	}

	// Graceful shutdown with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Error("shutdown error", "error", err)
		os.Exit(1)
	}

	slog.Info("server stopped successfully")
}
