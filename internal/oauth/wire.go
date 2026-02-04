package oauth

import (
	"context"
	"fmt"
	"time"

	"github.com/jamesprial/mcp-oauth-2.1/internal/oauth/internal/jwks"
	"github.com/jamesprial/mcp-oauth-2.1/internal/oauth/internal/metadata"
	"github.com/jamesprial/mcp-oauth-2.1/internal/oauth/internal/token"
)

// tokenValidatorAdapter adapts token.Validator to oauth.TokenValidator interface.
type tokenValidatorAdapter struct {
	validator *token.Validator
}

func (a *tokenValidatorAdapter) ValidateToken(ctx context.Context, tokenString string) (*TokenClaims, error) {
	claims, err := a.validator.ValidateToken(ctx, tokenString)
	if err != nil {
		return nil, err
	}
	// Convert token.TokenClaims to oauth.TokenClaims
	return &TokenClaims{
		Subject:   claims.Subject,
		Issuer:    claims.Issuer,
		Audience:  claims.Audience,
		Scopes:    claims.Scopes,
		ExpiresAt: claims.ExpiresAt,
		IssuedAt:  claims.IssuedAt,
		JTI:       claims.JTI,
	}, nil
}

// metadataServiceAdapter adapts metadata.Service to oauth.MetadataService interface.
type metadataServiceAdapter struct {
	service *metadata.Service
}

func (a *metadataServiceAdapter) GetMetadata(ctx context.Context) (*ProtectedResourceMetadata, error) {
	meta, err := a.service.GetMetadata(ctx)
	if err != nil {
		return nil, err
	}
	// Convert metadata.ProtectedResourceMetadata to oauth.ProtectedResourceMetadata
	return &ProtectedResourceMetadata{
		Resource:               meta.Resource,
		AuthorizationServers:   meta.AuthorizationServers,
		ScopesSupported:        meta.ScopesSupported,
		BearerMethodsSupported: meta.BearerMethodsSupported,
	}, nil
}

func (a *metadataServiceAdapter) GetMetadataURL() string {
	return a.service.GetMetadataURL()
}

// scopeCheckerAdapter adapts token.ScopeChecker to oauth.ScopeChecker interface.
type scopeCheckerAdapter struct {
	checker *token.ScopeChecker
}

func (a *scopeCheckerAdapter) RequireScopes(claims *TokenClaims, required ...string) error {
	if claims == nil {
		return fmt.Errorf("claims cannot be nil")
	}
	// Convert oauth.TokenClaims to token.TokenClaims
	tokenClaims := &token.TokenClaims{
		Subject:   claims.Subject,
		Issuer:    claims.Issuer,
		Audience:  claims.Audience,
		Scopes:    claims.Scopes,
		ExpiresAt: claims.ExpiresAt,
		IssuedAt:  claims.IssuedAt,
		JTI:       claims.JTI,
	}
	return a.checker.RequireScopes(tokenClaims, required...)
}

func (a *scopeCheckerAdapter) RequireAnyScope(claims *TokenClaims, scopes ...string) error {
	if claims == nil {
		return fmt.Errorf("claims cannot be nil")
	}
	// Convert oauth.TokenClaims to token.TokenClaims
	tokenClaims := &token.TokenClaims{
		Subject:   claims.Subject,
		Issuer:    claims.Issuer,
		Audience:  claims.Audience,
		Scopes:    claims.Scopes,
		ExpiresAt: claims.ExpiresAt,
		IssuedAt:  claims.IssuedAt,
		JTI:       claims.JTI,
	}
	return a.checker.RequireAnyScope(tokenClaims, scopes...)
}

// Config holds the configuration needed to construct OAuth services.
type Config struct {
	// BaseURL is the canonical base URL for this protected resource.
	BaseURL string

	// AuthorizationServers is a list of trusted authorization server URLs.
	AuthorizationServers []string

	// Audience is the expected audience (aud) claim in access tokens.
	Audience string

	// ScopesSupported is a list of OAuth scopes this server supports.
	ScopesSupported []string

	// JWKSCacheTTL is how long to cache JWKS keys.
	JWKSCacheTTL time.Duration

	// ClockSkew is the allowed clock skew for token expiration validation.
	ClockSkew time.Duration
}

// NewJWKSClient creates a new JWKS client with the provided configuration.
// The client will fetch JWKS from the configured authorization servers
// and cache keys for the specified TTL.
func NewJWKSClient(cfg *Config) JWKSClient {
	return jwks.NewClient(cfg.AuthorizationServers, cfg.JWKSCacheTTL)
}

// NewTokenValidator creates a new token validator with the provided configuration.
// The validator uses the JWKS client to verify token signatures and validates
// the audience, expiration, and other claims per OAuth 2.1.
func NewTokenValidator(cfg *Config, jwksClient JWKSClient) TokenValidator {
	validator := token.NewValidator(jwksClient, cfg.Audience, cfg.ClockSkew)
	return &tokenValidatorAdapter{validator: validator}
}

// NewMetadataService creates a new protected resource metadata service.
// The service provides RFC 9728 compliant metadata at the well-known endpoint.
func NewMetadataService(cfg *Config) MetadataService {
	service := metadata.NewService(
		cfg.BaseURL,
		cfg.AuthorizationServers,
		cfg.ScopesSupported,
	)
	return &metadataServiceAdapter{service: service}
}

// NewScopeChecker creates a new scope checker.
// The checker validates token scopes against required scopes for operations.
func NewScopeChecker() ScopeChecker {
	checker := token.NewScopeChecker()
	return &scopeCheckerAdapter{checker: checker}
}

// NewOAuthServices creates all OAuth services from the configuration.
// This is a convenience function for dependency injection.
func NewOAuthServices(cfg *Config) (TokenValidator, MetadataService, ScopeChecker, JWKSClient) {
	jwksClient := NewJWKSClient(cfg)
	tokenValidator := NewTokenValidator(cfg, jwksClient)
	metadataService := NewMetadataService(cfg)
	scopeChecker := NewScopeChecker()

	return tokenValidator, metadataService, scopeChecker, jwksClient
}
