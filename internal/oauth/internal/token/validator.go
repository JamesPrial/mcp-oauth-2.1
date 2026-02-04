package token

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jamesprial/mcp-oauth-2.1/internal/oauth/oautherr"
)

// JWKSClient defines the interface for fetching signing keys.
// This avoids importing the parent oauth package.
type JWKSClient interface {
	GetKey(ctx context.Context, keyID string) (any, error)
	RefreshKeys(ctx context.Context) error
}

// TokenClaims represents validated JWT claims from an access token.
type TokenClaims struct {
	Subject   string
	Issuer    string
	Audience  []string
	Scopes    []string
	ExpiresAt time.Time
	IssuedAt  time.Time
	JTI       string
}

// HasScope returns true if the token has the specified scope.
func (c *TokenClaims) HasScope(scope string) bool {
	if c == nil {
		return false
	}
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// HasAnyScope returns true if the token has any of the specified scopes.
func (c *TokenClaims) HasAnyScope(scopes ...string) bool {
	if c == nil || len(scopes) == 0 {
		return false
	}
	for _, required := range scopes {
		if c.HasScope(required) {
			return true
		}
	}
	return false
}

// HasAllScopes returns true if the token has all specified scopes.
func (c *TokenClaims) HasAllScopes(scopes ...string) bool {
	if c == nil {
		return len(scopes) == 0
	}
	for _, required := range scopes {
		if !c.HasScope(required) {
			return false
		}
	}
	return true
}

// Whitelisted signing algorithms per OAuth 2.1 security best practices.
// Algorithm confusion attacks are prevented by explicitly validating the algorithm.
var allowedAlgorithms = map[string]bool{
	"RS256": true,
	"RS384": true,
	"RS512": true,
	"ES256": true,
	"ES384": true,
	"ES512": true,
}

// Validator validates OAuth 2.1 access tokens using JWT validation.
type Validator struct {
	jwksClient JWKSClient
	audience   string
	clockSkew  time.Duration
}

// NewValidator creates a new token validator.
func NewValidator(jwksClient JWKSClient, audience string, clockSkew time.Duration) *Validator {
	return &Validator{
		jwksClient: jwksClient,
		audience:   audience,
		clockSkew:  clockSkew,
	}
}

// ValidateToken validates an access token and returns the parsed claims.
func (v *Validator) ValidateToken(ctx context.Context, tokenString string) (*TokenClaims, error) {
	// Parse token without verification first to get the header
	parser := jwt.NewParser(
		jwt.WithoutClaimsValidation(),
	)

	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, oautherr.NewInvalidTokenError("ValidateToken", fmt.Errorf("failed to parse token: %w", err))
	}

	// Validate algorithm is whitelisted
	alg, ok := token.Header["alg"].(string)
	if !ok || alg == "" {
		return nil, oautherr.NewUnsupportedAlgorithmError("ValidateToken", "none")
	}
	if !allowedAlgorithms[alg] {
		return nil, oautherr.NewUnsupportedAlgorithmError("ValidateToken", alg)
	}

	// Get key ID from header
	kid, ok := token.Header["kid"].(string)
	if !ok || kid == "" {
		return nil, oautherr.NewInvalidTokenError("ValidateToken", fmt.Errorf("missing kid in token header"))
	}

	// Fetch the public key
	key, err := v.jwksClient.GetKey(ctx, kid)
	if err != nil {
		return nil, err
	}
	if key == nil {
		return nil, oautherr.NewKeyNotFoundError("ValidateToken", kid)
	}

	// Parse and validate the token with the public key
	validatedToken, err := jwt.Parse(tokenString, func(t *jwt.Token) (any, error) {
		// Verify the algorithm matches what we expect
		if t.Method.Alg() != alg {
			return nil, oautherr.NewUnsupportedAlgorithmError("ValidateToken", t.Method.Alg())
		}
		return key, nil
	}, jwt.WithLeeway(v.clockSkew))

	if err != nil {
		if err == jwt.ErrTokenExpired {
			return nil, oautherr.NewTokenExpiredError("ValidateToken", err)
		}
		return nil, oautherr.NewInvalidSignatureError("ValidateToken", err)
	}

	if !validatedToken.Valid {
		return nil, oautherr.NewInvalidTokenError("ValidateToken", fmt.Errorf("token is invalid"))
	}

	// Extract claims
	mapClaims, ok := validatedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, oautherr.NewInvalidTokenError("ValidateToken", fmt.Errorf("invalid claims type"))
	}

	claims, err := v.extractClaims(mapClaims)
	if err != nil {
		return nil, err
	}

	// Validate audience
	if !v.validateAudience(claims.Audience) {
		return nil, oautherr.NewInvalidAudienceError("ValidateToken", v.audience, claims.Audience)
	}

	return claims, nil
}

// extractClaims extracts TokenClaims from JWT MapClaims.
func (v *Validator) extractClaims(mapClaims jwt.MapClaims) (*TokenClaims, error) {
	claims := &TokenClaims{}

	// Extract subject (required)
	sub, err := mapClaims.GetSubject()
	if err != nil {
		return nil, oautherr.NewMissingClaimError("extractClaims", "sub")
	}
	if sub == "" {
		return nil, oautherr.NewMissingClaimError("extractClaims", "sub")
	}
	claims.Subject = sub

	// Extract issuer (required)
	iss, err := mapClaims.GetIssuer()
	if err != nil {
		return nil, oautherr.NewMissingClaimError("extractClaims", "iss")
	}
	if iss == "" {
		return nil, oautherr.NewMissingClaimError("extractClaims", "iss")
	}
	claims.Issuer = iss

	// Extract audience (required)
	aud, err := mapClaims.GetAudience()
	if err != nil {
		return nil, oautherr.NewMissingClaimError("extractClaims", "aud")
	}
	if len(aud) == 0 {
		return nil, oautherr.NewMissingClaimError("extractClaims", "aud")
	}
	claims.Audience = aud

	// Extract expiration time (required)
	exp, err := mapClaims.GetExpirationTime()
	if err != nil {
		return nil, oautherr.NewMissingClaimError("extractClaims", "exp")
	}
	if exp == nil {
		return nil, oautherr.NewMissingClaimError("extractClaims", "exp")
	}
	claims.ExpiresAt = exp.Time

	// Extract issued at (optional)
	iat, err := mapClaims.GetIssuedAt()
	if err == nil && iat != nil {
		claims.IssuedAt = iat.Time
	}

	// Extract JTI (optional)
	if jti, ok := mapClaims["jti"].(string); ok {
		claims.JTI = jti
	}

	// Extract scopes (optional but important for OAuth)
	if scopeStr, ok := mapClaims["scope"].(string); ok {
		claims.Scopes = parseScopes(scopeStr)
	}

	return claims, nil
}

// validateAudience checks if the expected audience is present in the token's audience claim.
func (v *Validator) validateAudience(audiences []string) bool {
	for _, aud := range audiences {
		if aud == v.audience {
			return true
		}
	}
	return false
}

// parseScopes parses a space-separated scope string into a slice.
func parseScopes(scopeStr string) []string {
	if scopeStr == "" {
		return nil
	}

	parts := strings.Split(scopeStr, " ")
	var scopes []string
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			scopes = append(scopes, trimmed)
		}
	}
	return scopes
}
