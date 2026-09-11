package scaleset

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}

func pemEncodeKey(key *rsa.PrivateKey) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
}

func parseTestJWT(t *testing.T, provider JWTProvider, key *rsa.PublicKey) *jwt.RegisteredClaims {
	t.Helper()
	claims := &jwt.RegisteredClaims{}

	tokenString, err := provider.Token(context.Background())
	require.NoError(t, err)

	token, err := jwt.ParseWithClaims(
		tokenString,
		claims,
		func(_ *jwt.Token) (any, error) { return key, nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
	)
	require.NoError(t, err)
	require.True(t, token.Valid)

	return claims
}

func TestJWTProviders(t *testing.T) {
	const clientID = "Iv1.test123"
	key := generateTestKey(t)
	pemProvider, err := newPEMJWTProvider(clientID, pemEncodeKey(key))
	require.NoError(t, err)

	tests := []struct {
		name     string
		provider JWTProvider
	}{
		{name: "PEM private key", provider: pemProvider},
		{name: "crypto signer", provider: &SignerJWTProvider{ClientID: clientID, Signer: key}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := parseTestJWT(t, tt.provider, &key.PublicKey)

			assert.Equal(t, clientID, claims.Issuer)
			require.NotNil(t, claims.IssuedAt)
			require.NotNil(t, claims.ExpiresAt)
			assert.WithinDuration(t, time.Now().Add(-time.Minute), claims.IssuedAt.Time, 2*time.Second)
			assert.Equal(t, 9*time.Minute, claims.ExpiresAt.Sub(claims.IssuedAt.Time))

			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_, err := tt.provider.Token(ctx)
			require.ErrorIs(t, err, context.Canceled)
		})
	}
}

func TestPEMJWTProviderInvalidPEM(t *testing.T) {
	_, err := newPEMJWTProvider("test", "not-a-valid-pem")
	require.Error(t, err)
}

type testSigner struct {
	publicKey crypto.PublicKey
	err       error
}

func (s *testSigner) Public() crypto.PublicKey {
	return s.publicKey
}

func (s *testSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, s.err
}

func TestSignerJWTProviderValidation(t *testing.T) {
	tests := []struct {
		name     string
		provider *SignerJWTProvider
		wantErr  string
	}{
		{name: "nil provider", wantErr: "signer is required"},
		{name: "missing signer", provider: &SignerJWTProvider{ClientID: "test"}, wantErr: "signer is required"},
		{
			name:     "missing client ID",
			provider: &SignerJWTProvider{Signer: &testSigner{publicKey: &rsa.PublicKey{}}},
			wantErr:  "client ID is required",
		},
		{
			name:     "non-RSA signer",
			provider: &SignerJWTProvider{ClientID: "test", Signer: &testSigner{publicKey: "not an RSA key"}},
			wantErr:  "signer public key must be *rsa.PublicKey",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.provider.Token(context.Background())
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestSignerJWTProviderSigningError(t *testing.T) {
	expectedErr := errors.New("KMS unavailable")
	provider := &SignerJWTProvider{
		ClientID: "test",
		Signer: &testSigner{
			publicKey: &rsa.PublicKey{},
			err:       expectedErr,
		},
	}

	_, err := provider.Token(context.Background())
	require.ErrorIs(t, err, expectedErr)
}

func TestJWTProviderFunc(t *testing.T) {
	t.Run("returns the function result", func(t *testing.T) {
		provider := JWTProviderFunc(func(_ context.Context) (string, error) {
			return "test-jwt-token", nil
		})

		token, err := provider.Token(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "test-jwt-token", token)
	})

	t.Run("propagates errors", func(t *testing.T) {
		expectedErr := errors.New("KMS unavailable")
		provider := JWTProviderFunc(func(_ context.Context) (string, error) {
			return "", expectedErr
		})

		_, err := provider.Token(context.Background())
		require.ErrorIs(t, err, expectedErr)
	})

	t.Run("rejects a nil function", func(t *testing.T) {
		var provider JWTProviderFunc
		_, err := provider.Token(context.Background())
		require.Error(t, err)
	})
}
