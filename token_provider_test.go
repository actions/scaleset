package scaleset

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenProviderFunc(t *testing.T) {
	provider := TokenProviderFunc(func(context.Context) (string, error) {
		return "ghs_test", nil
	})
	token, err := provider.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "ghs_test", token)
}

func TestNewClientWithTokenProvider(t *testing.T) {
	t.Run("requires a provider", func(t *testing.T) {
		_, err := NewClientWithTokenProvider(ClientWithTokenProviderConfig{
			GitHubConfigURL: "https://github.com/my-org",
		}, nil)
		assert.NotNil(t, err)
	})

	t.Run("consults the provider on every re-authentication", func(t *testing.T) {
		ctx := context.Background()

		var mu sync.Mutex
		var bearers []string
		var calls atomic.Int64

		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte(`{"count":1,"encodedJITConfig":"config"}`))
		}), withShortLivedAdminToken(t))
		server.Config.Handler = wrapRegistrationTokenCapture(server.Config.Handler, &mu, &bearers)

		provider := TokenProviderFunc(func(context.Context) (string, error) {
			return fmt.Sprintf("ghs_%d", calls.Add(1)), nil
		})

		client, err := NewClientWithTokenProvider(ClientWithTokenProviderConfig{
			GitHubConfigURL: server.configURLForOrg("my-org"),
		}, provider)
		require.NoError(t, err)

		// The admin token is already inside the refresh window, so each call
		// re-authenticates — and must pick up a fresh token from the provider.
		_, err = client.GenerateJitRunnerConfig(ctx, &RunnerScaleSetJitRunnerSetting{}, 1)
		require.NoError(t, err)
		_, err = client.GenerateJitRunnerConfig(ctx, &RunnerScaleSetJitRunnerSetting{}, 1)
		require.NoError(t, err)

		mu.Lock()
		defer mu.Unlock()
		assert.Equal(t, []string{"Bearer ghs_1", "Bearer ghs_2"}, bearers)
	})

	t.Run("provider errors fail the request", func(t *testing.T) {
		ctx := context.Background()

		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte(`{}`))
		}))

		provider := TokenProviderFunc(func(context.Context) (string, error) {
			return "", errors.New("token store unavailable")
		})

		client, err := NewClientWithTokenProvider(ClientWithTokenProviderConfig{
			GitHubConfigURL: server.configURLForOrg("my-org"),
		}, provider, WithRetryMax(0))
		require.NoError(t, err)

		_, err = client.GenerateJitRunnerConfig(ctx, &RunnerScaleSetJitRunnerSetting{}, 1)
		require.ErrorContains(t, err, "token store unavailable")
	})
}

// withShortLivedAdminToken issues admin tokens that are already within the
// client's refresh window, forcing a re-authentication on every request.
func withShortLivedAdminToken(t *testing.T) actionsServerOption {
	return func(s *actionsServer) {
		claims := &jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-10 * time.Minute)),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * time.Second)),
			Issuer:    "123",
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(samplePrivateKey))
		require.NoError(t, err)
		tokenString, err := token.SignedString(privateKey)
		require.NoError(t, err)
		s.token = tokenString
	}
}

// wrapRegistrationTokenCapture records the Authorization header of every
// registration-token request before delegating to the wrapped handler.
func wrapRegistrationTokenCapture(next http.Handler, mu *sync.Mutex, bearers *[]string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/runners/registration-token") {
			mu.Lock()
			*bearers = append(*bearers, r.Header.Get("Authorization"))
			mu.Unlock()
		}
		next.ServeHTTP(w, r)
	})
}
