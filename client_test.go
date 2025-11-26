package scaleset

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/actions/scaleset/internal/testserver"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http/httpproxy"
)

const exampleRequestID = "5ddf2050-dae0-013c-9159-04421ad31b68"

var testUserAgent = UserAgentInfo{
	Version:    "test",
	CommitSHA:  "test",
	ScaleSetID: 1,
}

func TestNewGitHubAPIRequest(t *testing.T) {
	ctx := context.Background()

	t.Run("uses the right host/path prefix", func(t *testing.T) {
		scenarios := []struct {
			configURL string
			path      string
			expected  string
		}{
			{
				configURL: "https://github.com/org/repo",
				path:      "/app/installations/123/access_tokens",
				expected:  "https://api.github.com/app/installations/123/access_tokens",
			},
			{
				configURL: "https://www.github.com/org/repo",
				path:      "/app/installations/123/access_tokens",
				expected:  "https://api.github.com/app/installations/123/access_tokens",
			},
			{
				configURL: "http://github.localhost/org/repo",
				path:      "/app/installations/123/access_tokens",
				expected:  "http://api.github.localhost/app/installations/123/access_tokens",
			},
			{
				configURL: "https://my-instance.com/org/repo",
				path:      "/app/installations/123/access_tokens",
				expected:  "https://my-instance.com/api/v3/app/installations/123/access_tokens",
			},
			{
				configURL: "http://localhost/org/repo",
				path:      "/app/installations/123/access_tokens",
				expected:  "http://localhost/api/v3/app/installations/123/access_tokens",
			},
		}

		for _, scenario := range scenarios {
			client, err := newClient(scenario.configURL, nil)
			require.NoError(t, err)

			req, err := client.newGitHubAPIRequest(ctx, http.MethodGet, scenario.path, nil)
			require.NoError(t, err)
			assert.Equal(t, scenario.expected, req.URL.String())
		}
	})

	t.Run("sets user agent header if present", func(t *testing.T) {
		client, err := newClient("http://localhost/my-org", nil)
		require.NoError(t, err)

		client.SetUserAgent(testUserAgent)

		req, err := client.newGitHubAPIRequest(ctx, http.MethodGet, "/app/installations/123/access_tokens", nil)
		require.NoError(t, err)

		assert.Equal(t, testUserAgent.String(), req.Header.Get("User-Agent"))
	})

	t.Run("sets the body we pass", func(t *testing.T) {
		client, err := newClient("http://localhost/my-org", nil)
		require.NoError(t, err)

		req, err := client.newGitHubAPIRequest(
			ctx,
			http.MethodGet,
			"/app/installations/123/access_tokens",
			strings.NewReader("the-body"),
		)
		require.NoError(t, err)

		b, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		assert.Equal(t, "the-body", string(b))
	})
}

func TestNewActionsServiceRequest(t *testing.T) {
	ctx := context.Background()
	defaultCreds := &ActionsAuth{Token: "token"}

	t.Run("manages authentication", func(t *testing.T) {
		t.Run("client is brand new", func(t *testing.T) {
			token := defaultActionsToken(t)
			server := testserver.New(t, nil, testserver.WithActionsToken(token))

			client, err := newClient(server.ConfigURLForOrg("my-org"), defaultCreds)
			require.NoError(t, err)

			req, err := client.newActionsServiceRequest(ctx, http.MethodGet, "my-path", nil)
			require.NoError(t, err)

			assert.Equal(t, "Bearer "+token, req.Header.Get("Authorization"))
		})

		t.Run("admin token is about to expire", func(t *testing.T) {
			newToken := defaultActionsToken(t)
			server := testserver.New(t, nil, testserver.WithActionsToken(newToken))

			client, err := newClient(server.ConfigURLForOrg("my-org"), defaultCreds)
			require.NoError(t, err)
			client.actionsServiceAdminToken = "expiring-token"
			client.actionsServiceAdminTokenExpiresAt = time.Now().Add(59 * time.Second)

			req, err := client.newActionsServiceRequest(ctx, http.MethodGet, "my-path", nil)
			require.NoError(t, err)

			assert.Equal(t, "Bearer "+newToken, req.Header.Get("Authorization"))
		})

		t.Run("admin token refresh failure", func(t *testing.T) {
			newToken := defaultActionsToken(t)
			errMessage := `{"message":"test"}`
			unauthorizedHandler := func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(errMessage))
			}
			server := testserver.New(
				t,
				nil,
				testserver.WithActionsToken("random-token"),
				testserver.WithActionsToken(newToken),
				testserver.WithActionsRegistrationTokenHandler(unauthorizedHandler),
			)
			client, err := newClient(server.ConfigURLForOrg("my-org"), defaultCreds)
			require.NoError(t, err)
			expiringToken := "expiring-token"
			expiresAt := time.Now().Add(59 * time.Second)
			client.actionsServiceAdminToken = expiringToken
			client.actionsServiceAdminTokenExpiresAt = expiresAt
			_, err = client.newActionsServiceRequest(ctx, http.MethodGet, "my-path", nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), errMessage)
			assert.Equal(t, client.actionsServiceAdminToken, expiringToken)
			assert.Equal(t, client.actionsServiceAdminTokenExpiresAt, expiresAt)
		})

		t.Run("admin token refresh retry", func(t *testing.T) {
			newToken := defaultActionsToken(t)
			errMessage := `{"message":"test"}`

			srv := "http://github.com/my-org"
			resp := &ActionsServiceAdminConnection{
				AdminToken:        &newToken,
				ActionsServiceURL: &srv,
			}
			failures := 0
			unauthorizedHandler := func(w http.ResponseWriter, r *http.Request) {
				if failures < 5 {
					failures++
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte(errMessage))
					return
				}

				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(resp)
			}
			server := testserver.New(t, nil, testserver.WithActionsToken("random-token"), testserver.WithActionsToken(newToken), testserver.WithActionsRegistrationTokenHandler(unauthorizedHandler))
			client, err := newClient(server.ConfigURLForOrg("my-org"), defaultCreds)
			require.NoError(t, err)
			expiringToken := "expiring-token"
			expiresAt := time.Now().Add(59 * time.Second)
			client.actionsServiceAdminToken = expiringToken
			client.actionsServiceAdminTokenExpiresAt = expiresAt

			_, err = client.newActionsServiceRequest(ctx, http.MethodGet, "my-path", nil)
			require.NoError(t, err)
			assert.Equal(t, client.actionsServiceAdminToken, newToken)
			assert.Equal(t, client.actionsServiceURL, srv)
			assert.NotEqual(t, client.actionsServiceAdminTokenExpiresAt, expiresAt)
		})

		t.Run("token is currently valid", func(t *testing.T) {
			tokenThatShouldNotBeFetched := defaultActionsToken(t)
			server := testserver.New(t, nil, testserver.WithActionsToken(tokenThatShouldNotBeFetched))

			client, err := newClient(server.ConfigURLForOrg("my-org"), defaultCreds)
			require.NoError(t, err)
			client.actionsServiceAdminToken = "healthy-token"
			client.actionsServiceAdminTokenExpiresAt = time.Now().Add(1 * time.Hour)

			req, err := client.newActionsServiceRequest(ctx, http.MethodGet, "my-path", nil)
			require.NoError(t, err)

			assert.Equal(t, "Bearer healthy-token", req.Header.Get("Authorization"))
		})
	})

	t.Run("builds the right URL including api version", func(t *testing.T) {
		server := testserver.New(t, nil)

		client, err := newClient(server.ConfigURLForOrg("my-org"), defaultCreds)
		require.NoError(t, err)

		req, err := client.newActionsServiceRequest(ctx, http.MethodGet, "/my/path?name=banana", nil)
		require.NoError(t, err)

		serverURL, err := url.Parse(server.URL)
		require.NoError(t, err)

		result := req.URL
		assert.Equal(t, serverURL.Host, result.Host)
		assert.Equal(t, "/tenant/123/my/path", result.Path)
		assert.Equal(t, "banana", result.Query().Get("name"))
		assert.Equal(t, "6.0-preview", result.Query().Get("api-version"))
	})

	t.Run("populates header", func(t *testing.T) {
		server := testserver.New(t, nil)

		client, err := newClient(server.ConfigURLForOrg("my-org"), defaultCreds)
		require.NoError(t, err)

		client.SetUserAgent(testUserAgent)

		req, err := client.newActionsServiceRequest(ctx, http.MethodGet, "/my/path", nil)
		require.NoError(t, err)

		assert.Equal(t, testUserAgent.String(), req.Header.Get("User-Agent"))
		assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
	})
}

func TestGetRunner(t *testing.T) {
	ctx := context.Background()
	auth := &ActionsAuth{
		Token: "token",
	}

	t.Run("Get Runner", func(t *testing.T) {
		var runnerID int64 = 1
		want := &RunnerReference{
			ID:   int(runnerID),
			Name: "self-hosted-ubuntu",
		}
		response := []byte(`{"id": 1, "name": "self-hosted-ubuntu"}`)

		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write(response)
		}))

		client, err := newClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		got, err := client.GetRunner(ctx, runnerID)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("Default retries on server error", func(t *testing.T) {
		var runnerID int64 = 1
		retryWaitMax := 1 * time.Millisecond
		retryMax := 1

		actualRetry := 0
		expectedRetry := retryMax + 1

		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
			actualRetry++
		}))

		client, err := newClient(server.configURLForOrg("my-org"), auth, WithRetryMax(retryMax), WithRetryWaitMax(retryWaitMax))
		require.NoError(t, err)

		_, err = client.GetRunner(ctx, runnerID)
		require.Error(t, err)
		assert.Equalf(t, actualRetry, expectedRetry, "A retry was expected after the first request but got: %v", actualRetry)
	})
}

func TestGetRunnerByName(t *testing.T) {
	ctx := context.Background()
	auth := &ActionsAuth{
		Token: "token",
	}

	t.Run("Get Runner by Name", func(t *testing.T) {
		var runnerID int64 = 1
		runnerName := "self-hosted-ubuntu"
		want := &RunnerReference{
			ID:   int(runnerID),
			Name: runnerName,
		}
		response := []byte(`{"count": 1, "value": [{"id": 1, "name": "self-hosted-ubuntu"}]}`)

		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write(response)
		}))

		client, err := newClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		got, err := client.GetRunnerByName(ctx, runnerName)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("Get Runner by name with not exist runner", func(t *testing.T) {
		runnerName := "self-hosted-ubuntu"
		response := []byte(`{"count": 0, "value": []}`)

		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write(response)
		}))

		client, err := newClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		got, err := client.GetRunnerByName(ctx, runnerName)
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("Default retries on server error", func(t *testing.T) {
		runnerName := "self-hosted-ubuntu"

		retryWaitMax := 1 * time.Millisecond
		retryMax := 1

		actualRetry := 0
		expectedRetry := retryMax + 1

		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
			actualRetry++
		}))

		client, err := newClient(server.configURLForOrg("my-org"), auth, WithRetryMax(retryMax), WithRetryWaitMax(retryWaitMax))
		require.NoError(t, err)

		_, err = client.GetRunnerByName(ctx, runnerName)
		require.Error(t, err)
		assert.Equalf(t, actualRetry, expectedRetry, "A retry was expected after the first request but got: %v", actualRetry)
	})
}

func TestDeleteRunner(t *testing.T) {
	ctx := context.Background()
	auth := &ActionsAuth{
		Token: "token",
	}

	t.Run("Delete Runner", func(t *testing.T) {
		var runnerID int64 = 1

		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))

		client, err := newClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		err = client.RemoveRunner(ctx, runnerID)
		assert.NoError(t, err)
	})

	t.Run("Default retries on server error", func(t *testing.T) {
		var runnerID int64 = 1

		retryWaitMax := 1 * time.Millisecond
		retryMax := 1

		actualRetry := 0
		expectedRetry := retryMax + 1

		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
			actualRetry++
		}))

		client, err := newClient(
			server.configURLForOrg("my-org"),
			auth,
			WithRetryMax(retryMax),
			WithRetryWaitMax(retryWaitMax),
		)
		require.NoError(t, err)

		err = client.RemoveRunner(ctx, runnerID)
		require.Error(t, err)
		assert.Equalf(t, actualRetry, expectedRetry, "A retry was expected after the first request but got: %v", actualRetry)
	})
}

func TestGetRunnerGroupByName(t *testing.T) {
	ctx := context.Background()
	auth := &ActionsAuth{
		Token: "token",
	}

	t.Run("Get RunnerGroup by Name", func(t *testing.T) {
		var runnerGroupID uint64 = 1
		runnerGroupName := "test-runner-group"
		want := &RunnerGroup{
			ID:   runnerGroupID,
			Name: runnerGroupName,
		}
		response := []byte(`{"count": 1, "value": [{"id": 1, "name": "test-runner-group"}]}`)

		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write(response)
		}))

		client, err := newClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		got, err := client.GetRunnerGroupByName(ctx, runnerGroupName)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("Get RunnerGroup by name with not exist runner group", func(t *testing.T) {
		runnerGroupName := "test-runner-group"
		response := []byte(`{"count": 0, "value": []}`)

		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write(response)
		}))

		client, err := newClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		got, err := client.GetRunnerGroupByName(ctx, runnerGroupName)
		assert.ErrorContains(t, err, "no runner group found with name")
		assert.Nil(t, got)
	})
}

func TestGetRunnerScaleSet(t *testing.T) {
	ctx := context.Background()
	auth := &ActionsAuth{
		Token: "token",
	}

	scaleSetName := "ScaleSet"
	runnerScaleSet := RunnerScaleSet{ID: 1, Name: scaleSetName}

	t.Run("Get existing scale set", func(t *testing.T) {
		want := &runnerScaleSet
		runnerScaleSetsResp := []byte(`{"count":1,"value":[{"id":1,"name":"ScaleSet"}]}`)
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Write(runnerScaleSetsResp)
		}))

		client, err := newClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		got, err := client.GetRunnerScaleSet(ctx, 1, scaleSetName)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("GetRunnerScaleSet calls correct url", func(t *testing.T) {
		runnerScaleSetsResp := []byte(`{"count":1,"value":[{"id":1,"name":"ScaleSet"}]}`)
		url := url.URL{}
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write(runnerScaleSetsResp)
			url = *r.URL
		}))

		client, err := newClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		_, err = client.GetRunnerScaleSet(ctx, 1, scaleSetName)
		require.NoError(t, err)

		expectedPath := "/tenant/123/_apis/runtime/runnerscalesets"
		assert.Equal(t, expectedPath, url.Path)
		assert.Equal(t, scaleSetName, url.Query().Get("name"))
		assert.Equal(t, "6.0-preview", url.Query().Get("api-version"))
	})

	t.Run("Status code not found", func(t *testing.T) {
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))

		client, err := newClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		_, err = client.GetRunnerScaleSet(ctx, 1, scaleSetName)
		assert.NotNil(t, err)
	})

	t.Run("Error when Content-Type is text/plain", func(t *testing.T) {
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "text/plain")
		}))

		client, err := newClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		_, err = client.GetRunnerScaleSet(ctx, 1, scaleSetName)
		assert.NotNil(t, err)
	})

	t.Run("Default retries on server error", func(t *testing.T) {
		actualRetry := 0
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
			actualRetry++
		}))

		retryMax := 1
		retryWaitMax := 1 * time.Microsecond

		client, err := newClient(
			server.configURLForOrg("my-org"),
			auth,
			WithRetryMax(retryMax),
			WithRetryWaitMax(retryWaitMax),
		)
		require.NoError(t, err)

		_, err = client.GetRunnerScaleSet(ctx, 1, scaleSetName)
		assert.NotNil(t, err)
		expectedRetry := retryMax + 1
		assert.Equalf(t, actualRetry, expectedRetry, "A retry was expected after the first request but got: %v", actualRetry)
	})

	t.Run("RunnerScaleSet count is zero", func(t *testing.T) {
		want := (*RunnerScaleSet)(nil)
		runnerScaleSetsResp := []byte(`{"count":0,"value":[{"id":1,"name":"ScaleSet"}]}`)
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Write(runnerScaleSetsResp)
		}))

		client, err := newClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		got, err := client.GetRunnerScaleSet(ctx, 1, scaleSetName)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("Multiple runner scale sets found", func(t *testing.T) {
		reqID := uuid.NewString()
		wantErr := &ActionsError{
			StatusCode: http.StatusOK,
			ActivityID: reqID,
			Err:        fmt.Errorf("multiple runner scale sets found with name %q", scaleSetName),
		}
		runnerScaleSetsResp := []byte(`{"count":2,"value":[{"id":1,"name":"ScaleSet"}]}`)
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set(headerActionsActivityID, reqID)
			w.Write(runnerScaleSetsResp)
		}))

		client, err := newClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		_, err = client.GetRunnerScaleSet(ctx, 1, scaleSetName)
		require.NotNil(t, err)
		assert.Equal(t, wantErr.Error(), err.Error())
	})
}

func TestGetRunnerScaleSetByID(t *testing.T) {
	ctx := context.Background()
	auth := &ActionsAuth{
		Token: "token",
	}

	scaleSetCreationDateTime := time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC)
	runnerScaleSet := RunnerScaleSet{ID: 1, Name: "ScaleSet", CreatedOn: scaleSetCreationDateTime, RunnerSetting: RunnerSetting{}}

	t.Run("Get existing scale set by Id", func(t *testing.T) {
		want := &runnerScaleSet
		rsl, err := json.Marshal(want)
		require.NoError(t, err)
		sservere := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Write(rsl)
		}))

		client, err := newClient(sservere.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		got, err := client.GetRunnerScaleSetByID(ctx, runnerScaleSet.ID)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("GetRunnerScaleSetByID calls correct url", func(t *testing.T) {
		rsl, err := json.Marshal(&runnerScaleSet)
		require.NoError(t, err)

		url := url.URL{}
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write(rsl)
			url = *r.URL
		}))

		client, err := newClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		_, err = client.GetRunnerScaleSetByID(ctx, runnerScaleSet.ID)
		require.NoError(t, err)

		expectedPath := fmt.Sprintf("/tenant/123/_apis/runtime/runnerscalesets/%d", runnerScaleSet.ID)
		assert.Equal(t, expectedPath, url.Path)
		assert.Equal(t, "6.0-preview", url.Query().Get("api-version"))
	})

	t.Run("Status code not found", func(t *testing.T) {
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))

		client, err := newClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		_, err = client.GetRunnerScaleSetByID(ctx, runnerScaleSet.ID)
		assert.NotNil(t, err)
	})

	t.Run("Error when Content-Type is text/plain", func(t *testing.T) {
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "text/plain")
		}))

		client, err := newClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		_, err = client.GetRunnerScaleSetByID(ctx, runnerScaleSet.ID)
		assert.NotNil(t, err)
	})

	t.Run("Default retries on server error", func(t *testing.T) {
		actualRetry := 0
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
			actualRetry++
		}))

		retryMax := 1
		retryWaitMax := 1 * time.Microsecond
		client, err := newClient(
			server.configURLForOrg("my-org"),
			auth,
			WithRetryMax(retryMax),
			WithRetryWaitMax(retryWaitMax),
		)
		require.NoError(t, err)

		_, err = client.GetRunnerScaleSetByID(ctx, runnerScaleSet.ID)
		require.NotNil(t, err)
		expectedRetry := retryMax + 1
		assert.Equalf(t, actualRetry, expectedRetry, "A retry was expected after the first request but got: %v", actualRetry)
	})

	t.Run("No RunnerScaleSet found", func(t *testing.T) {
		want := (*RunnerScaleSet)(nil)
		rsl, err := json.Marshal(want)
		require.NoError(t, err)
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Write(rsl)
		}))

		client, err := newClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		got, err := client.GetRunnerScaleSetByID(ctx, runnerScaleSet.ID)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})
}

func TestCreateRunnerScaleSet(t *testing.T) {
	ctx := context.Background()
	auth := &ActionsAuth{
		Token: "token",
	}

	scaleSetCreationDateTime := time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC)
	runnerScaleSet := RunnerScaleSet{ID: 1, Name: "ScaleSet", CreatedOn: scaleSetCreationDateTime, RunnerSetting: RunnerSetting{}}

	t.Run("Create runner scale set", func(t *testing.T) {
		want := &runnerScaleSet
		rsl, err := json.Marshal(want)
		require.NoError(t, err)
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Write(rsl)
		}))

		client, err := newClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		got, err := client.CreateRunnerScaleSet(ctx, &runnerScaleSet)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("CreateRunnerScaleSet calls correct url", func(t *testing.T) {
		rsl, err := json.Marshal(&runnerScaleSet)
		require.NoError(t, err)
		url := url.URL{}
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write(rsl)
			url = *r.URL
		}))

		client, err := newClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		_, err = client.CreateRunnerScaleSet(ctx, &runnerScaleSet)
		require.NoError(t, err)

		expectedPath := "/tenant/123/_apis/runtime/runnerscalesets"
		assert.Equal(t, expectedPath, url.Path)
		assert.Equal(t, "6.0-preview", url.Query().Get("api-version"))
	})

	t.Run("Error when Content-Type is text/plain", func(t *testing.T) {
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "text/plain")
		}))

		client, err := newClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		_, err = client.CreateRunnerScaleSet(ctx, &runnerScaleSet)
		require.NotNil(t, err)
		var expectedErr *ActionsError
		assert.True(t, errors.As(err, &expectedErr))
	})

	t.Run("Default retries on server error", func(t *testing.T) {
		actualRetry := 0
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
			actualRetry++
		}))

		retryMax := 1
		retryWaitMax := 1 * time.Microsecond

		client, err := newClient(
			server.configURLForOrg("my-org"),
			auth,
			WithRetryMax(retryMax),
			WithRetryWaitMax(retryWaitMax),
		)
		require.NoError(t, err)

		_, err = client.CreateRunnerScaleSet(ctx, &runnerScaleSet)
		require.NotNil(t, err)
		expectedRetry := retryMax + 1
		assert.Equalf(t, actualRetry, expectedRetry, "A retry was expected after the first request but got: %v", actualRetry)
	})
}

func TestUpdateRunnerScaleSet(t *testing.T) {
	ctx := context.Background()
	auth := &ActionsAuth{
		Token: "token",
	}

	scaleSetCreationDateTime := time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC)
	runnerScaleSet := RunnerScaleSet{ID: 1, Name: "ScaleSet", RunnerGroupID: 1, RunnerGroupName: "group", CreatedOn: scaleSetCreationDateTime, RunnerSetting: RunnerSetting{}}

	t.Run("Update runner scale set", func(t *testing.T) {
		want := &runnerScaleSet
		rsl, err := json.Marshal(want)
		require.NoError(t, err)
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Write(rsl)
		}))

		client, err := newClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		got, err := client.UpdateRunnerScaleSet(ctx, 1, &RunnerScaleSet{RunnerGroupID: 1})
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("UpdateRunnerScaleSet calls correct url", func(t *testing.T) {
		rsl, err := json.Marshal(&runnerScaleSet)
		require.NoError(t, err)
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			expectedPath := "/tenant/123/_apis/runtime/runnerscalesets/1"
			assert.Equal(t, expectedPath, r.URL.Path)
			assert.Equal(t, http.MethodPatch, r.Method)
			assert.Equal(t, "6.0-preview", r.URL.Query().Get("api-version"))

			w.Write(rsl)
		}))

		client, err := newClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		_, err = client.UpdateRunnerScaleSet(ctx, 1, &runnerScaleSet)
		require.NoError(t, err)
	})
}

func TestDeleteRunnerScaleSet(t *testing.T) {
	ctx := context.Background()
	auth := &ActionsAuth{
		Token: "token",
	}

	t.Run("Delete runner scale set", func(t *testing.T) {
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "DELETE", r.Method)
			assert.Contains(t, r.URL.String(), "/_apis/runtime/runnerscalesets/10?api-version=6.0-preview")
			w.WriteHeader(http.StatusNoContent)
		}))

		client, err := newClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		err = client.DeleteRunnerScaleSet(ctx, 10)
		assert.NoError(t, err)
	})

	t.Run("Delete calls with error", func(t *testing.T) {
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "DELETE", r.Method)
			assert.Contains(t, r.URL.String(), "/_apis/runtime/runnerscalesets/10?api-version=6.0-preview")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"message": "test error"}`))
		}))

		client, err := newClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		err = client.DeleteRunnerScaleSet(ctx, 10)
		assert.ErrorContains(t, err, "test error")
	})
}

func TestCreateMessageSession(t *testing.T) {
	ctx := context.Background()
	auth := &ActionsAuth{
		Token: "token",
	}

	t.Run("CreateMessageSession unmarshals correctly", func(t *testing.T) {
		owner := "foo"
		runnerScaleSet := RunnerScaleSet{
			ID:            1,
			Name:          "ScaleSet",
			CreatedOn:     time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC),
			RunnerSetting: RunnerSetting{},
		}

		want := &RunnerScaleSetSession{
			OwnerName: "foo",
			RunnerScaleSet: &RunnerScaleSet{
				ID:   1,
				Name: "ScaleSet",
			},
			MessageQueueURL:         "http://fake.github.com/123",
			MessageQueueAccessToken: "fake.jwt.here",
		}

		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			resp := []byte(`{
					"ownerName": "foo",
					"runnerScaleSet": {
						"id": 1,
						"name": "ScaleSet"
					},
					"messageQueueUrl": "http://fake.github.com/123",
					"messageQueueAccessToken": "fake.jwt.here"
				}`)
			w.Write(resp)
		}))

		client, err := newClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		got, err := client.CreateMessageSession(ctx, runnerScaleSet.ID, owner)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("CreateMessageSession unmarshals errors into ActionsError", func(t *testing.T) {
		owner := "foo"
		runnerScaleSet := RunnerScaleSet{
			ID:            1,
			Name:          "ScaleSet",
			CreatedOn:     time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC),
			RunnerSetting: RunnerSetting{},
		}

		want := &ActionsError{
			ActivityID: exampleRequestID,
			StatusCode: http.StatusBadRequest,
			Err: &ActionsExceptionError{
				ExceptionName: "CSharpExceptionNameHere",
				Message:       "could not do something",
			},
		}

		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set(headerActionsActivityID, exampleRequestID)
			w.WriteHeader(http.StatusBadRequest)
			resp := []byte(`{"typeName": "CSharpExceptionNameHere","message": "could not do something"}`)
			w.Write(resp)
		}))

		client, err := newClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		_, err = client.CreateMessageSession(ctx, runnerScaleSet.ID, owner)
		require.NotNil(t, err)

		errorTypeForComparison := &ActionsError{}
		assert.True(
			t,
			errors.As(err, &errorTypeForComparison),
			"CreateMessageSession expected to be able to parse the error into ActionsError type: %v",
			err,
		)

		assert.Equal(t, want, errorTypeForComparison)
	})

	t.Run("CreateMessageSession call is retried the correct amount of times", func(t *testing.T) {
		owner := "foo"
		runnerScaleSet := RunnerScaleSet{
			ID:            1,
			Name:          "ScaleSet",
			CreatedOn:     time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC),
			RunnerSetting: RunnerSetting{},
		}

		gotRetries := 0
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			gotRetries++
		}))

		retryMax := 3
		retryWaitMax := 1 * time.Microsecond

		wantRetries := retryMax + 1

		client, err := newClient(
			server.configURLForOrg("my-org"),
			auth,
			WithRetryMax(retryMax),
			WithRetryWaitMax(retryWaitMax),
		)
		require.NoError(t, err)

		_, err = client.CreateMessageSession(ctx, runnerScaleSet.ID, owner)
		assert.NotNil(t, err)
		assert.Equalf(t, gotRetries, wantRetries, "CreateMessageSession got unexpected retry count: got=%v, want=%v", gotRetries, wantRetries)
	})
}

func TestDeleteMessageSession(t *testing.T) {
	ctx := context.Background()
	auth := &ActionsAuth{
		Token: "token",
	}

	t.Run("DeleteMessageSession call is retried the correct amount of times", func(t *testing.T) {
		runnerScaleSet := RunnerScaleSet{
			ID:            1,
			Name:          "ScaleSet",
			CreatedOn:     time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC),
			RunnerSetting: RunnerSetting{},
		}

		gotRetries := 0
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			gotRetries++
		}))

		retryMax := 3
		retryWaitMax := 1 * time.Microsecond

		wantRetries := retryMax + 1

		client, err := newClient(
			server.configURLForOrg("my-org"),
			auth,
			WithRetryMax(retryMax),
			WithRetryWaitMax(retryWaitMax),
		)
		require.NoError(t, err)

		sessionID := uuid.New()

		err = client.DeleteMessageSession(ctx, runnerScaleSet.ID, sessionID)
		assert.NotNil(t, err)
		assert.Equalf(t, gotRetries, wantRetries, "CreateMessageSession got unexpected retry count: got=%v, want=%v", gotRetries, wantRetries)
	})
}

func TestRefreshMessageSession(t *testing.T) {
	auth := &ActionsAuth{
		Token: "token",
	}

	t.Run("RefreshMessageSession call is retried the correct amount of times", func(t *testing.T) {
		runnerScaleSet := RunnerScaleSet{
			ID:            1,
			Name:          "ScaleSet",
			CreatedOn:     time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC),
			RunnerSetting: RunnerSetting{},
		}

		gotRetries := 0
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			gotRetries++
		}))

		retryMax := 3
		retryWaitMax := 1 * time.Microsecond

		wantRetries := retryMax + 1

		client, err := newClient(
			server.configURLForOrg("my-org"),
			auth,
			WithRetryMax(retryMax),
			WithRetryWaitMax(retryWaitMax),
		)
		require.NoError(t, err)

		sessionID := uuid.New()

		_, err = client.RefreshMessageSession(context.Background(), runnerScaleSet.ID, sessionID)
		assert.NotNil(t, err)
		assert.Equalf(t, gotRetries, wantRetries, "CreateMessageSession got unexpected retry count: got=%v, want=%v", gotRetries, wantRetries)
	})
}

func TestGetMessage(t *testing.T) {
	ctx := context.Background()
	auth := &ActionsAuth{
		Token: "token",
	}

	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjI1MTYyMzkwMjJ9.tlrHslTmDkoqnc4Kk9ISoKoUNDfHo-kjlH-ByISBqzE"
	runnerScaleSetMessage := &RunnerScaleSetMessage{
		MessageID:   1,
		MessageType: "rssType",
	}

	t.Run("Get Runner Scale Set Message", func(t *testing.T) {
		want := runnerScaleSetMessage
		response := []byte(`{"messageId":1,"messageType":"rssType"}`)
		s := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Write(response)
		}))

		client, err := newClient(s.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		got, err := client.GetMessage(ctx, s.URL, token, 0, 10)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("GetMessage sets the last message id if not 0", func(t *testing.T) {
		want := runnerScaleSetMessage
		response := []byte(`{"messageId":1,"messageType":"rssType"}`)
		s := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query()
			assert.Equal(t, "1", q.Get("lastMessageId"))
			w.Write(response)
		}))

		client, err := newClient(s.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		got, err := client.GetMessage(ctx, s.URL, token, 1, 10)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("Default retries on server error", func(t *testing.T) {
		retryMax := 1

		actualRetry := 0
		expectedRetry := retryMax + 1

		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
			actualRetry++
		}))

		client, err := newClient(
			server.configURLForOrg("my-org"),
			auth,
			WithRetryMax(retryMax),
			WithRetryWaitMax(1*time.Millisecond),
		)
		require.NoError(t, err)

		_, err = client.GetMessage(ctx, server.URL, token, 0, 10)
		assert.NotNil(t, err)
		assert.Equalf(t, actualRetry, expectedRetry, "A retry was expected after the first request but got: %v", actualRetry)
	})

	t.Run("Message token expired", func(t *testing.T) {
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))

		client, err := newClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		_, err = client.GetMessage(ctx, server.URL, token, 0, 10)
		require.NotNil(t, err)

		var expectedErr *MessageQueueTokenExpiredError
		require.True(t, errors.As(err, &expectedErr))
	})

	t.Run("Status code not found", func(t *testing.T) {
		want := ActionsError{
			Err:        errors.New("unknown exception"),
			StatusCode: 404,
		}
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))

		client, err := newClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		_, err = client.GetMessage(ctx, server.URL, token, 0, 10)
		require.NotNil(t, err)
		assert.Equal(t, want.Error(), err.Error())
	})

	t.Run("Error when Content-Type is text/plain", func(t *testing.T) {
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "text/plain")
		}))

		client, err := newClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		_, err = client.GetMessage(ctx, server.URL, token, 0, 10)
		assert.NotNil(t, err)
	})

	t.Run("Capacity error handling", func(t *testing.T) {
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hc := r.Header.Get(HeaderScaleSetMaxCapacity)
			c, err := strconv.Atoi(hc)
			require.NoError(t, err)
			assert.GreaterOrEqual(t, c, 0)

			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "text/plain")
		}))

		client, err := newClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		_, err = client.GetMessage(ctx, server.URL, token, 0, 0)
		assert.Error(t, err)
		var expectedErr *ActionsError
		assert.ErrorAs(t, err, &expectedErr)
		assert.Equal(t, http.StatusBadRequest, expectedErr.StatusCode)
	})
}

func TestDeleteMessage(t *testing.T) {
	ctx := context.Background()
	auth := &ActionsAuth{
		Token: "token",
	}

	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjI1MTYyMzkwMjJ9.tlrHslTmDkoqnc4Kk9ISoKoUNDfHo-kjlH-ByISBqzE"
	runnerScaleSetMessage := &RunnerScaleSetMessage{
		MessageID:   1,
		MessageType: "rssType",
	}

	t.Run("Delete existing message", func(t *testing.T) {
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))

		client, err := newClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		err = client.DeleteMessage(ctx, server.URL, token, runnerScaleSetMessage.MessageID)
		assert.Nil(t, err)
	})

	t.Run("Message token expired", func(t *testing.T) {
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))

		client, err := newClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		err = client.DeleteMessage(ctx, server.URL, token, 0)
		require.NotNil(t, err)
		var expectedErr *MessageQueueTokenExpiredError
		assert.True(t, errors.As(err, &expectedErr))
	})

	t.Run("Error when Content-Type is text/plain", func(t *testing.T) {
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "text/plain")
		}))

		client, err := newClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		err = client.DeleteMessage(ctx, server.URL, token, runnerScaleSetMessage.MessageID)
		require.NotNil(t, err)
		var expectedErr *ActionsError
		assert.True(t, errors.As(err, &expectedErr))
	},
	)

	t.Run("Default retries on server error", func(t *testing.T) {
		actualRetry := 0
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
			actualRetry++
		}))

		retryMax := 1
		client, err := newClient(
			server.configURLForOrg("my-org"),
			auth,
			WithRetryMax(retryMax),
			WithRetryWaitMax(1*time.Nanosecond),
		)
		require.NoError(t, err)
		err = client.DeleteMessage(ctx, server.URL, token, runnerScaleSetMessage.MessageID)
		assert.NotNil(t, err)
		expectedRetry := retryMax + 1
		assert.Equalf(t, actualRetry, expectedRetry, "A retry was expected after the first request but got: %v", actualRetry)
	})

	t.Run("No message found", func(t *testing.T) {
		want := (*RunnerScaleSetMessage)(nil)
		rsl, err := json.Marshal(want)
		require.NoError(t, err)

		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Write(rsl)
		}))

		client, err := newClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		err = client.DeleteMessage(ctx, server.URL, token, runnerScaleSetMessage.MessageID+1)
		var expectedErr *ActionsError
		require.True(t, errors.As(err, &expectedErr))
	})
}

func TestClientProxy(t *testing.T) {
	serverCalled := false

	proxy := testserver.New(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverCalled = true
	}))

	proxyConfig := &httpproxy.Config{
		HTTPProxy: proxy.URL,
	}
	proxyFunc := func(req *http.Request) (*url.URL, error) {
		return proxyConfig.ProxyFunc()(req.URL)
	}

	c, err := newClient("http://github.com/org/repo", nil, WithProxy(proxyFunc))
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
	require.NoError(t, err)

	_, err = c.do(req)
	require.NoError(t, err)

	assert.True(t, serverCalled)
}

func TestGenerateJitRunnerConfig(t *testing.T) {
	ctx := context.Background()
	auth := &ActionsAuth{
		Token: "token",
	}

	t.Run("Get JIT Config for Runner", func(t *testing.T) {
		want := &RunnerScaleSetJitRunnerConfig{}
		response := []byte(`{"count":1,"value":[{"id":1,"name":"scale-set-name"}]}`)

		runnerSettings := &RunnerScaleSetJitRunnerSetting{}

		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Write(response)
		}))
		client, err := newClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		got, err := client.GenerateJitRunnerConfig(ctx, runnerSettings, 1)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("Default retries on server error", func(t *testing.T) {
		runnerSettings := &RunnerScaleSetJitRunnerSetting{}

		retryMax := 1
		actualRetry := 0
		expectedRetry := retryMax + 1

		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
			actualRetry++
		}))

		client, err := newClient(
			server.configURLForOrg("my-org"),
			auth,
			WithRetryMax(1),
			WithRetryWaitMax(1*time.Millisecond),
		)
		require.NoError(t, err)

		_, err = client.GenerateJitRunnerConfig(ctx, runnerSettings, 1)
		assert.NotNil(t, err)
		assert.Equalf(t, actualRetry, expectedRetry, "A retry was expected after the first request but got: %v", actualRetry)
	})
}

func TestClient_Do(t *testing.T) {
	t.Run("trims byte order mark from response if present", func(t *testing.T) {
		t.Run("when there is no body", func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			}))
			defer server.Close()

			client, err := newClient("https://localhost/org/repo", &ActionsAuth{Token: "token"})
			require.NoError(t, err)

			req, err := http.NewRequest("GET", server.URL, nil)
			require.NoError(t, err)

			resp, err := client.do(req)
			require.NoError(t, err)

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Empty(t, string(body))
		})

		responses := []string{
			"\xef\xbb\xbf{\"foo\":\"bar\"}",
			"{\"foo\":\"bar\"}",
		}

		for _, response := range responses {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(response))
			}))
			defer server.Close()

			client, err := newClient("https://localhost/org/repo", &ActionsAuth{Token: "token"})
			require.NoError(t, err)

			req, err := http.NewRequest("GET", server.URL, nil)
			require.NoError(t, err)

			resp, err := client.do(req)
			require.NoError(t, err)

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Equal(t, "{\"foo\":\"bar\"}", string(body))
		}
	})
}

// newActionsServer returns a new httptest.Server that handles the
// authentication requests neeeded to create a new client. Any requests not
// made to the /actions/runners/registration-token or
// /actions/runner-registration endpoints will be handled by the provided
// handler. The returned server is started and will be automatically closed
// when the test ends.
func newActionsServer(t *testing.T, handler http.Handler, options ...actionsServerOption) *actionsServer {
	s := httptest.NewServer(nil)
	server := &actionsServer{
		Server: s,
	}
	t.Cleanup(func() {
		server.Close()
	})

	for _, option := range options {
		option(server)
	}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// handle getRunnerRegistrationToken
		if strings.HasSuffix(r.URL.Path, "/runners/registration-token") {
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"token":"token"}`))
			return
		}

		// handle getActionsServiceAdminConnection
		if strings.HasSuffix(r.URL.Path, "/actions/runner-registration") {
			if server.token == "" {
				server.token = defaultActionsToken(t)
			}

			w.Write([]byte(`{"url":"` + s.URL + `/tenant/123/","token":"` + server.token + `"}`))
			return
		}

		handler.ServeHTTP(w, r)
	})

	server.Config.Handler = h

	return server
}

type actionsServerOption func(*actionsServer)

type actionsServer struct {
	*httptest.Server

	token string
}

func (s *actionsServer) configURLForOrg(org string) string {
	return s.URL + "/" + org
}

func defaultActionsToken(t *testing.T) string {
	claims := &jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(time.Now().Add(-10 * time.Minute)),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
		Issuer:    "123",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(samplePrivateKey))
	require.NoError(t, err)
	tokenString, err := token.SignedString(privateKey)
	require.NoError(t, err)
	return tokenString
}

func TestServerWithSelfSignedCertificates(t *testing.T) {
	ctx := context.Background()
	// this handler is a very very barebones replica of actions api
	// used during the creation of a a new client
	var u string
	h := func(w http.ResponseWriter, r *http.Request) {
		// handle get registration token
		if strings.HasSuffix(r.URL.Path, "/runners/registration-token") {
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"token":"token"}`))
			return
		}

		// handle getActionsServiceAdminConnection
		if strings.HasSuffix(r.URL.Path, "/actions/runner-registration") {
			claims := &jwt.RegisteredClaims{
				IssuedAt:  jwt.NewNumericDate(time.Now().Add(-1 * time.Minute)),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Minute)),
				Issuer:    "123",
			}

			token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
			privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(samplePrivateKey))
			require.NoError(t, err)
			tokenString, err := token.SignedString(privateKey)
			require.NoError(t, err)
			w.Write([]byte(`{"url":"` + u + `","token":"` + tokenString + `"}`))
			return
		}

		// default happy response for RemoveRunner
		w.WriteHeader(http.StatusNoContent)
	}

	certPath := filepath.Join("testdata", "server.crt")
	keyPath := filepath.Join("testdata", "server.key")

	t.Run("client without ca certs", func(t *testing.T) {
		server := startNewTLSTestServer(t, certPath, keyPath, http.HandlerFunc(h))
		u = server.URL
		configURL := server.URL + "/my-org"

		auth := &ActionsAuth{
			Token: "token",
		}
		client, err := newClient(configURL, auth)
		require.NoError(t, err)
		require.NotNil(t, client)

		err = client.RemoveRunner(ctx, 1)
		require.NotNil(t, err)

		if runtime.GOOS == "linux" {
			assert.True(t, errors.As(err, &x509.UnknownAuthorityError{}))
		}

		// on macOS we only get an untyped error from the system verifying the
		// certificate
		if runtime.GOOS == "darwin" {
			assert.True(t, strings.HasSuffix(err.Error(), "certificate is not trusted"))
		}
	})

	t.Run("client with ca certs", func(t *testing.T) {
		server := startNewTLSTestServer(
			t,
			certPath,
			keyPath,
			http.HandlerFunc(h),
		)
		u = server.URL
		configURL := server.URL + "/my-org"

		auth := &ActionsAuth{
			Token: "token",
		}

		cert, err := os.ReadFile(filepath.Join("testdata", "rootCA.crt"))
		require.NoError(t, err)

		pool := x509.NewCertPool()
		require.True(t, pool.AppendCertsFromPEM(cert))

		client, err := newClient(
			configURL,
			auth,
			WithRootCAs(pool),
		)
		require.NoError(t, err)
		assert.NotNil(t, client)

		err = client.RemoveRunner(ctx, 1)
		assert.NoError(t, err)
	})

	t.Run("client with ca chain certs", func(t *testing.T) {
		server := startNewTLSTestServer(
			t,
			filepath.Join("testdata", "leaf.crt"),
			filepath.Join("testdata", "leaf.key"),
			http.HandlerFunc(h),
		)
		u = server.URL
		configURL := server.URL + "/my-org"

		auth := &ActionsAuth{
			Token: "token",
		}

		cert, err := os.ReadFile(filepath.Join("testdata", "intermediate.crt"))
		require.NoError(t, err)

		pool := x509.NewCertPool()
		require.True(t, pool.AppendCertsFromPEM(cert))

		client, err := newClient(
			configURL,
			auth,
			WithRootCAs(pool),
			WithRetryMax(0),
		)
		require.NoError(t, err)
		require.NotNil(t, client)

		err = client.RemoveRunner(ctx, 1)
		assert.NoError(t, err)
	})

	t.Run("client skipping tls verification", func(t *testing.T) {
		server := startNewTLSTestServer(t, certPath, keyPath, http.HandlerFunc(h))
		configURL := server.URL + "/my-org"

		auth := &ActionsAuth{
			Token: "token",
		}

		client, err := newClient(configURL, auth, WithoutTLSVerify())
		require.NoError(t, err)
		assert.NotNil(t, client)
	})
}

func startNewTLSTestServer(t *testing.T, certPath, keyPath string, handler http.Handler) *httptest.Server {
	server := httptest.NewUnstartedServer(handler)
	t.Cleanup(func() {
		server.Close()
	})

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	require.NoError(t, err)

	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	server.StartTLS()

	return server
}

func TestUserAgentInfoString(t *testing.T) {
	userAgentInfo := UserAgentInfo{
		System:     "actions-runner-controller",
		Version:    "0.1.0",
		CommitSHA:  "1234567890abcdef",
		ScaleSetID: 10,
		Subsystem:  "test",
	}

	userAgent := userAgentInfo.String()
	expectedProduct := fmt.Sprintf(
		"actions-runner-controller/0.1.0 (1234567890abcdef; test) ScaleSetID/10; client (%s; %s)",
		packageVersion,
		commitSHA,
	)
	assert.Contains(t, userAgent, expectedProduct)
}

const samplePrivateKey = `-----BEGIN PRIVATE KEY-----
MIIEugIBADANBgkqhkiG9w0BAQEFAASCBKQwggSgAgEAAoIBAQC7tgquvNIp+Ik3
rRVZ9r0zJLsSzTHqr2dA6EUUmpRiQ25MzjMqKqu0OBwvh/pZyfjSIkKrhIridNK4
DWnPfPWHE2K3Muh0X2sClxtqiiFmXsvbiTzhUm5a+zCcv0pJCWYnKi0HmyXpAXjJ
iN8mWliZN896verVYXWrod7EaAnuST4TiJeqZYW4bBBG81fPNc/UP4j6CKAW8nx9
HtcX6ApvlHeCLZUTW/qhGLO0nLKoEOr3tXCPW5VjKzlm134Dl+8PN6f1wv6wMAoA
lo7Ha5+c74jhPL6gHXg7cRaHQmuJCJrtl8qbLkFAulfkBixBw/6i11xoM/MOC64l
TWmXqrxTAgMBAAECgf9zYlxfL+rdHRXCoOm7pUeSPL0dWaPFP12d/Z9LSlDAt/h6
Pd+eqYEwhf795SAbJuzNp51Ls6LUGnzmLOdojKwfqJ51ahT1qbcBcMZNOcvtGqZ9
xwLG993oyR49C361Lf2r8mKrdrR5/fW0B1+1s6A+eRFivqFOtsOc4V4iMeHYsCVJ
hM7yMu0UfpolDJA/CzopsoGq3UuQlibUEUxKULza06aDjg/gBH3PnP+fQ1m0ovDY
h0pX6SCq5fXVJFS+Pbpu7j2ePNm3mr0qQhrUONZq0qhGN/piCbBZe1CqWApyO7nA
B95VChhL1eYs1BKvQePh12ap83woIUcW2mJF2F0CgYEA+aERTuKWEm+zVNKS9t3V
qNhecCOpayKM9OlALIK/9W6KBS+pDsjQQteQAUAItjvLiDjd5KsrtSgjbSgr66IP
b615Pakywe5sdnVGzSv+07KMzuFob9Hj6Xv9als9Y2geVhUZB2Frqve/UCjmC56i
zuQTSele5QKCSSTFBV3423cCgYEAwIBv9ChsI+mse6vPaqSPpZ2n237anThMcP33
aS0luYXqMWXZ0TQ/uSmCElY4G3xqNo8szzfy6u0HpldeUsEUsIcBNUV5kIIb8wKu
Zmgcc8gBIjJkyUJI4wuz9G/fegEUj3u6Cttmmj4iWLzCRscRJdfGpqwRIhOGyXb9
2Rur5QUCgYAGWIPaH4R1H4XNiDTYNbdyvV1ZOG7cHFq89xj8iK5cjNzRWO7RQ2WX
7WbpwTj3ePmpktiBMaDA0C5mXfkP2mTOD/jfCmgR6f+z2zNbj9zAgO93at9+yDUl
AFPm2j7rQgBTa+HhACb+h6HDZebDMNsuqzmaTWZuJ+wr89VWV5c17QKBgH3jwNNQ
mCAIUidynaulQNfTOZIe7IMC7WK7g9CBmPkx7Y0uiXr6C25hCdJKFllLTP6vNWOy
uCcQqf8LhgDiilBDifO3op9xpyuOJlWMYocJVkxx3l2L/rSU07PYcbKNAFAxXuJ4
xym51qZnkznMN5ei/CPFxVKeqHgaXDpekVStAoGAV3pSWAKDXY/42XEHixrCTqLW
kBxfaf3g7iFnl3u8+7Z/7Cb4ZqFcw0bRJseKuR9mFvBhcZxSErbMDEYrevefU9aM
APeCxEyw6hJXgbWKoG7Fw2g2HP3ytCJ4YzH0zNitHjk/1h4BG7z8cEQILCSv5mN2
etFcaQuTHEZyRhhJ4BU=
-----END PRIVATE KEY-----`
