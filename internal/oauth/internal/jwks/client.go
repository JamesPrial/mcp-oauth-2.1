package jwks

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/jamesprial/mcp-oauth-2.1/internal/oauth/oautherr"
)

// AuthorizationServerMetadata represents the minimal AS metadata needed for JWKS discovery.
type AuthorizationServerMetadata struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a single JSON Web Key.
type JWK struct {
	KeyType   string `json:"kty"`
	Use       string `json:"use,omitempty"`
	KeyID     string `json:"kid"`
	Algorithm string `json:"alg,omitempty"`
	// RSA public key parameters
	N string `json:"n,omitempty"` // modulus
	E string `json:"e,omitempty"` // exponent
	// EC public key parameters
	Curve string `json:"crv,omitempty"` // curve name
	X     string `json:"x,omitempty"`   // x coordinate
	Y     string `json:"y,omitempty"`   // y coordinate
}

// Client fetches and caches JWKS from authorization servers.
type Client struct {
	httpClient   *http.Client
	cache        *Cache
	serverURLs   []string
	cacheTTL     time.Duration
	mu           sync.RWMutex
	jwksURICache map[string]string // maps issuer to JWKS URI
}

// NewClient creates a new JWKS client.
func NewClient(serverURLs []string, cacheTTL time.Duration) *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		cache:        NewCache(cacheTTL),
		serverURLs:   serverURLs,
		cacheTTL:     cacheTTL,
		jwksURICache: make(map[string]string),
	}
}

// GetKey retrieves a public key for the given key ID.
// It first checks the cache, then fetches from authorization servers if needed.
func (c *Client) GetKey(ctx context.Context, keyID string) (any, error) {
	if keyID == "" {
		return nil, oautherr.NewKeyNotFoundError("GetKey", "key ID is required")
	}

	// Check cache first
	if key := c.cache.Get(keyID); key != nil {
		return key, nil
	}

	// Track the last error for better error messages
	var lastErr error

	// Fetch JWKS from all configured servers
	for _, serverURL := range c.serverURLs {
		key, err := c.fetchAndCacheKey(ctx, serverURL, keyID)
		if err != nil {
			// Preserve the error and continue to next server
			lastErr = err
			continue
		}
		if key != nil {
			return key, nil
		}
	}

	// Return the last error if available, otherwise generic key not found
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, oautherr.NewKeyNotFoundError("GetKey", keyID)
}

// RefreshKeys forces a refresh of the JWKS cache from all configured authorization servers.
func (c *Client) RefreshKeys(ctx context.Context) error {
	c.cache.Clear()
	c.mu.Lock()
	c.jwksURICache = make(map[string]string)
	c.mu.Unlock()

	var lastErr error
	for _, serverURL := range c.serverURLs {
		if err := c.refreshFromServer(ctx, serverURL); err != nil {
			lastErr = err
			// Continue to try other servers
			continue
		}
	}

	if lastErr != nil {
		return lastErr
	}
	return nil
}

// fetchAndCacheKey fetches JWKS from a server and caches the specified key.
func (c *Client) fetchAndCacheKey(ctx context.Context, serverURL, keyID string) (any, error) {
	jwksURI, err := c.getJWKSURI(ctx, serverURL)
	if err != nil {
		return nil, err
	}

	jwks, err := c.fetchJWKS(ctx, jwksURI)
	if err != nil {
		return nil, err
	}

	// Cache all keys from the JWKS
	for _, jwk := range jwks.Keys {
		if jwk.KeyID == "" {
			continue
		}
		key, err := c.jwkToPublicKey(&jwk)
		if err != nil {
			// Skip invalid keys
			continue
		}
		c.cache.Set(jwk.KeyID, key)

		// Return immediately if this is the key we're looking for
		if jwk.KeyID == keyID {
			return key, nil
		}
	}

	return nil, nil
}

// refreshFromServer refreshes all keys from a specific server.
func (c *Client) refreshFromServer(ctx context.Context, serverURL string) error {
	jwksURI, err := c.getJWKSURI(ctx, serverURL)
	if err != nil {
		return err
	}

	jwks, err := c.fetchJWKS(ctx, jwksURI)
	if err != nil {
		return err
	}

	// Cache all keys
	for _, jwk := range jwks.Keys {
		if jwk.KeyID == "" {
			continue
		}
		key, err := c.jwkToPublicKey(&jwk)
		if err != nil {
			continue
		}
		c.cache.Set(jwk.KeyID, key)
	}

	return nil
}

// getJWKSURI retrieves the JWKS URI from authorization server metadata.
func (c *Client) getJWKSURI(ctx context.Context, serverURL string) (string, error) {
	// Check cache first
	c.mu.RLock()
	cached, ok := c.jwksURICache[serverURL]
	c.mu.RUnlock()
	if ok {
		return cached, nil
	}

	// Fetch metadata
	metadataURL := serverURL + "/.well-known/oauth-authorization-server"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return "", oautherr.NewInvalidMetadataError("getJWKSURI", serverURL, err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", oautherr.NewJWKSFetchError("getJWKSURI", serverURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", oautherr.NewJWKSFetchError("getJWKSURI", serverURL,
			fmt.Errorf("metadata endpoint returned status %d", resp.StatusCode))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", oautherr.NewJWKSFetchError("getJWKSURI", serverURL, err)
	}

	var metadata AuthorizationServerMetadata
	if err := json.Unmarshal(body, &metadata); err != nil {
		return "", oautherr.NewInvalidMetadataError("getJWKSURI", serverURL, err)
	}

	if metadata.JWKSURI == "" {
		return "", oautherr.NewInvalidMetadataError("getJWKSURI", serverURL,
			fmt.Errorf("authorization server metadata missing jwks_uri field"))
	}

	// Cache the JWKS URI
	c.mu.Lock()
	c.jwksURICache[serverURL] = metadata.JWKSURI
	c.mu.Unlock()

	return metadata.JWKSURI, nil
}

// fetchJWKS fetches the JWKS from the given URI.
func (c *Client) fetchJWKS(ctx context.Context, jwksURI string) (*JWKS, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, oautherr.NewJWKSFetchError("fetchJWKS", jwksURI, err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, oautherr.NewJWKSFetchError("fetchJWKS", jwksURI, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, oautherr.NewJWKSFetchError("fetchJWKS", jwksURI,
			fmt.Errorf("jwks endpoint returned status %d", resp.StatusCode))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, oautherr.NewJWKSFetchError("fetchJWKS", jwksURI, err)
	}

	var jwks JWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, oautherr.NewJWKSFetchError("fetchJWKS", jwksURI, err)
	}

	return &jwks, nil
}

// jwkToPublicKey converts a JWK to a public key interface.
func (c *Client) jwkToPublicKey(jwk *JWK) (any, error) {
	switch jwk.KeyType {
	case "RSA":
		return c.jwkToRSAPublicKey(jwk)
	case "EC":
		return c.jwkToECDSAPublicKey(jwk)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", jwk.KeyType)
	}
}

// jwkToRSAPublicKey converts a JWK to an RSA public key.
func (c *Client) jwkToRSAPublicKey(jwk *JWK) (*rsa.PublicKey, error) {
	if jwk.N == "" || jwk.E == "" {
		return nil, fmt.Errorf("missing RSA key parameters")
	}

	// Decode base64url-encoded modulus
	nBytes, err := base64URLDecode(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}

	// Decode base64url-encoded exponent
	eBytes, err := base64URLDecode(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}

// jwkToECDSAPublicKey converts a JWK to an ECDSA public key.
func (c *Client) jwkToECDSAPublicKey(jwk *JWK) (*ecdsa.PublicKey, error) {
	if jwk.X == "" || jwk.Y == "" || jwk.Curve == "" {
		return nil, fmt.Errorf("missing EC key parameters")
	}

	// Decode coordinates
	xBytes, err := base64URLDecode(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode x coordinate: %w", err)
	}

	yBytes, err := base64URLDecode(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("failed to decode y coordinate: %w", err)
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	// Map curve name to crypto/elliptic curve
	curve, err := getCurve(jwk.Curve)
	if err != nil {
		return nil, err
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}
