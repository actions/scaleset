package scaleset

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTProvider creates short-lived JWTs for GitHub App authentication.
// Implementations must be safe for concurrent use.
//
// The returned JWT must be RS256-signed with iss (Client ID), iat, and exp claims.
// See https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app
type JWTProvider interface {
	Token(ctx context.Context) (string, error)
}

// SignerJWTProvider creates GitHub App JWTs using a [crypto.Signer].
// This enables KMS-backed keys (AWS KMS, GCP Cloud KMS, Azure Key Vault)
// where private key material never leaves the secure boundary.
// The Signer's Public() method must return *[crypto/rsa.PublicKey].
type SignerJWTProvider struct {
	ClientID string
	Signer   crypto.Signer
}

// Token creates a signed JWT for GitHub App authentication.
//
// It uses the JWT library to assemble the token, then signs the resulting
// digest through the crypto.Signer because SignedString requires a concrete
// *rsa.PrivateKey.
func (p *SignerJWTProvider) Token(ctx context.Context) (string, error) {
	if p == nil || p.Signer == nil {
		return "", fmt.Errorf("signer is required")
	}
	if p.ClientID == "" {
		return "", fmt.Errorf("client ID is required")
	}
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("sign app JWT: %w", err)
	}

	publicKey := p.Signer.Public()
	if _, ok := publicKey.(*rsa.PublicKey); !ok {
		return "", fmt.Errorf("signer public key must be *rsa.PublicKey, got %T", publicKey)
	}

	token := newGitHubAppJWT(p.ClientID)
	signingInput, err := token.SigningString()
	if err != nil {
		return "", fmt.Errorf("create app JWT signing input: %w", err)
	}

	digest := sha256.Sum256([]byte(signingInput))
	sig, err := p.Signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("sign app JWT: %w", err)
	}
	return signingInput + "." + token.EncodeSegment(sig), nil
}

// pemJWTProvider signs JWTs using a PEM-encoded RSA private key.
type pemJWTProvider struct {
	clientID   string
	privateKey *rsa.PrivateKey
}

// newPEMJWTProvider creates a JWTProvider from a PEM-encoded RSA private key string.
func newPEMJWTProvider(clientID, pemKey string) (*pemJWTProvider, error) {
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(pemKey))
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA private key from PEM: %w", err)
	}
	return &pemJWTProvider{
		clientID:   clientID,
		privateKey: privateKey,
	}, nil
}

func (p *pemJWTProvider) Token(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("sign app JWT: %w", err)
	}
	return newGitHubAppJWT(p.clientID).SignedString(p.privateKey)
}

func newGitHubAppJWT(clientID string) *jwt.Token {
	issuedAt := time.Now().Add(-time.Minute)
	expiresAt := issuedAt.Add(9 * time.Minute)

	return jwt.NewWithClaims(jwt.SigningMethodRS256, &jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(issuedAt),
		ExpiresAt: jwt.NewNumericDate(expiresAt),
		Issuer:    clientID,
	})
}

// Ensure both providers satisfy the interface at compile time.
var (
	_ JWTProvider = (*SignerJWTProvider)(nil)
	_ JWTProvider = (*pemJWTProvider)(nil)
	_ JWTProvider = JWTProviderFunc(nil)
)

// JWTProviderFunc adapts a function to a [JWTProvider].
type JWTProviderFunc func(ctx context.Context) (string, error)

// Token calls f with ctx.
func (f JWTProviderFunc) Token(ctx context.Context) (string, error) {
	if f == nil {
		return "", fmt.Errorf("JWT provider function is required")
	}
	return f(ctx)
}
