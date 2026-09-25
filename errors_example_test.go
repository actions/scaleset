package scaleset_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/actions/scaleset"
)

func ExampleRequestResponseError() {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-GitHub-Request-Id", "request-123")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client, err := scaleset.NewClientWithPersonalAccessToken(
		scaleset.NewClientWithPersonalAccessTokenConfig{
			GitHubConfigURL:     server.URL + "/example",
			PersonalAccessToken: "example-token",
		},
		scaleset.WithRetry(scaleset.RetryConfig{}),
	)
	if err != nil {
		panic(err)
	}
	_, err = client.GetRunner(context.Background(), 1)
	var responseErr *scaleset.RequestResponseError
	if errors.As(err, &responseErr) && responseErr.Response != nil {
		resp := responseErr.Response
		fmt.Println(resp.StatusCode, resp.Header.Get("X-GitHub-Request-Id"))
	}
	fmt.Println(errors.Is(err, scaleset.UnauthorizedError))
	// Output:
	// 401 request-123
	// true
}
