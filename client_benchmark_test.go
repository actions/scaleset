package scaleset

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/actions/scaleset/internal/testserver"
	"github.com/hashicorp/go-retryablehttp"
)

func BenchmarkClientLocalMetadataParallel(b *testing.B) {
	client, err := newClient(
		testSystemInfo,
		"https://github.com/my-org/my-repo",
		actionsAuth{token: "token"},
	)
	if err != nil {
		b.Fatalf("new client: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = client.SystemInfo()
			_ = client.DebugInfo()
		}
	})
}

func BenchmarkClientReadAPIsParallel(b *testing.B) {
	client := newBenchmarkClient(b)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	runParallelBenchmark(b, func(iteration int) error {
		switch iteration % 5 {
		case 0:
			_, err := client.GetRunner(ctx, 1)
			return err
		case 1:
			_, err := client.GetRunnerByName(ctx, "self-hosted-ubuntu")
			return err
		case 2:
			_, err := client.GetRunnerScaleSet(ctx, 1, "ScaleSet")
			return err
		case 3:
			_, err := client.GetRunnerScaleSetByID(ctx, 1)
			return err
		default:
			_, err := client.GetRunnerGroupByName(ctx, "Default")
			return err
		}
	})
}

func BenchmarkClientWriteAPIsParallel(b *testing.B) {
	client := newBenchmarkClient(b)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	runParallelBenchmark(b, func(iteration int) error {
		runnerScaleSet := &RunnerScaleSet{
			Name: "ScaleSet",
			Labels: []Label{{
				Name: "self-hosted-ubuntu",
				Type: "System",
			}},
		}

		switch iteration % 5 {
		case 0:
			_, err := client.CreateRunnerScaleSet(ctx, runnerScaleSet)
			return err
		case 1:
			_, err := client.UpdateRunnerScaleSet(ctx, 1, runnerScaleSet)
			return err
		case 2:
			return client.DeleteRunnerScaleSet(ctx, 1)
		case 3:
			_, err := client.GenerateJitRunnerConfig(ctx, &RunnerScaleSetJitRunnerSetting{Name: "runner", WorkFolder: "_work"}, 1)
			return err
		default:
			return client.RemoveRunner(ctx, 1)
		}
	})
}

func BenchmarkClientNewActionsServiceRequestParallel(b *testing.B) {
	client := newBenchmarkClient(b)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	runParallelBenchmark(b, func(iteration int) error {
		switch iteration % 5 {
		case 0:
			_, err := client.newActionsServiceRequest(ctx, http.MethodGet, "/_apis/distributedtask/pools/0/agents/1", nil)
			return err
		case 1:
			_, err := client.newActionsServiceRequestWithQuery(ctx, http.MethodGet, "/_apis/distributedtask/pools/0/agents", url.Values{"agentName": {"self-hosted-ubuntu"}}, nil)
			return err
		case 2:
			_, err := client.newActionsServiceRequestWithQuery(ctx, http.MethodGet, "/_apis/runtime/runnerscalesets", url.Values{"runnerGroupId": {"1"}, "name": {"ScaleSet"}}, nil)
			return err
		case 3:
			_, err := client.newActionsServiceRequest(ctx, http.MethodGet, "/_apis/runtime/runnerscalesets/1", nil)
			return err
		default:
			_, err := client.newActionsServiceRequestWithQuery(ctx, http.MethodGet, "/_apis/runtime/runnergroups/", url.Values{"groupName": {"Default"}}, nil)
			return err
		}
	})
}

func BenchmarkClientMixedPublicMethodsParallel(b *testing.B) {
	client := newBenchmarkClient(b)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	runParallelBenchmark(b, func(iteration int) error {
		switch iteration % 8 {
		case 0:
			client.SetSystemInfo(SystemInfo{
				System:     "benchmark",
				Subsystem:  "mixed",
				Version:    "test-version",
				CommitSHA:  "test-sha",
				ScaleSetID: iteration % 16,
			})
			return nil
		case 1:
			_ = client.SystemInfo()
			return nil
		case 2:
			_ = client.DebugInfo()
			return nil
		case 3:
			_, err := client.GetRunner(ctx, 1)
			return err
		case 4:
			_, err := client.GetRunnerByName(ctx, "self-hosted-ubuntu")
			return err
		case 5:
			_, err := client.GetRunnerScaleSet(ctx, 1, "ScaleSet")
			return err
		case 6:
			_, err := client.GetRunnerScaleSetByID(ctx, 1)
			return err
		default:
			_, err := client.GetRunnerGroupByName(ctx, "Default")
			return err
		}
	})
}

func BenchmarkMessageSessionClientSessionParallel(b *testing.B) {
	client := newBenchmarkMessageSessionClient(b)

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if client.Session().MessageQueueAccessToken == "" {
				b.Fatal("missing message queue access token")
			}
		}
	})
}

func BenchmarkMessageSessionClientGetMessageAcceptedParallel(b *testing.B) {
	client := newBenchmarkMessageSessionClient(b)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	runParallelBenchmark(b, func(iteration int) error {
		_, err := client.GetMessage(ctx, iteration, 10)
		return err
	})
}

func BenchmarkMessageSessionClientMutatingAPIsParallel(b *testing.B) {
	client := newBenchmarkMessageSessionClient(b)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	runParallelBenchmark(b, func(iteration int) error {
		switch iteration % 2 {
		case 0:
			return client.DeleteMessage(ctx, iteration+1)
		default:
			_, err := client.AcquireJobs(ctx, []int64{int64(iteration + 1), int64(iteration + 2)})
			return err
		}
	})
}

func BenchmarkMessageSessionClientLifecycleParallel(b *testing.B) {
	client := newBenchmarkClient(b)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	runParallelBenchmark(b, func(iteration int) error {
		sessionClient, err := client.MessageSessionClient(ctx, 1, "benchmark")
		if err != nil {
			return err
		}

		return sessionClient.Close(ctx)
	})
}

func newBenchmarkClient(b *testing.B) *Client {
	b.Helper()

	server := testserver.New(b, http.HandlerFunc(handleBenchmarkClientRequest))
	client, err := newClient(
		testSystemInfo,
		server.ConfigURLForOrg("my-org"),
		actionsAuth{token: "token"},
		WithRetryableHTTPClint(newBenchmarkRetryableHTTPClient()),
	)
	if err != nil {
		b.Fatalf("new client: %v", err)
	}

	if _, err := client.GetRunner(context.Background(), 1); err != nil {
		b.Fatalf("warm client token: %v", err)
	}

	return client
}

func newBenchmarkMessageSessionClient(b *testing.B) *MessageSessionClient {
	b.Helper()

	serverURL := ""
	server := testserver.New(b, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "sessions") {
			_, _ = fmt.Fprintf(w, `{"sessionId":"11111111-1111-1111-1111-111111111111","ownerName":"benchmark","messageQueueUrl":"%s","messageQueueAccessToken":"message-token"}`, serverURL)
			return
		}
		if strings.Contains(r.URL.Path, "/sessions/") {
			if r.Method == http.MethodDelete {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			_, _ = fmt.Fprintf(w, `{"sessionId":"11111111-1111-1111-1111-111111111111","ownerName":"benchmark","messageQueueUrl":"%s","messageQueueAccessToken":"message-token"}`, serverURL)
			return
		}
		if strings.Contains(r.URL.Path, "acquirejobs") {
			_, _ = w.Write([]byte(`{"count":2,"value":[1,2]}`))
			return
		}
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		w.WriteHeader(http.StatusAccepted)
	}))
	serverURL = server.URL

	client, err := newClient(
		testSystemInfo,
		server.ConfigURLForOrg("my-org"),
		actionsAuth{token: "token"},
		WithRetryableHTTPClint(newBenchmarkRetryableHTTPClient()),
	)
	if err != nil {
		b.Fatalf("new client: %v", err)
	}

	sessionClient, err := client.MessageSessionClient(context.Background(), 1, "benchmark")
	if err != nil {
		b.Fatalf("new message session client: %v", err)
	}

	return sessionClient
}

func newBenchmarkRetryableHTTPClient() *retryablehttp.Client {
	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = 0
	retryClient.RetryWaitMax = time.Nanosecond
	retryClient.HTTPClient.Transport = &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		MaxIdleConns:        1024,
		MaxIdleConnsPerHost: 1024,
	}

	return retryClient
}

func handleBenchmarkClientRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch {
	case strings.Contains(r.URL.Path, runnerEndpoint) && r.Method == http.MethodDelete:
		w.WriteHeader(http.StatusNoContent)

	case strings.Contains(r.URL.Path, runnerEndpoint) && r.Method == http.MethodGet:
		if r.URL.Query().Get("agentName") != "" {
			_, _ = w.Write([]byte(`{"count":1,"value":[{"id":1,"name":"self-hosted-ubuntu"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":1,"name":"self-hosted-ubuntu"}`))

	case strings.Contains(r.URL.Path, scaleSetEndpoint) && r.Method == http.MethodDelete:
		w.WriteHeader(http.StatusNoContent)

	case strings.Contains(r.URL.Path, "generatejitconfig") && r.Method == http.MethodPost:
		_, _ = w.Write([]byte(`{"runner":{"id":1,"name":"runner","runnerScaleSetId":1},"encodedJITConfig":"encoded"}`))

	case strings.Contains(r.URL.Path, scaleSetEndpoint) && (r.Method == http.MethodPost || r.Method == http.MethodPatch):
		_, _ = w.Write([]byte(`{"id":1,"name":"ScaleSet","labels":[{"name":"self-hosted-ubuntu","type":"System"}]}`))

	case strings.Contains(r.URL.Path, scaleSetEndpoint) && r.Method == http.MethodGet:
		if r.URL.Query().Get("name") != "" {
			_, _ = w.Write([]byte(`{"count":1,"value":[{"id":1,"name":"ScaleSet"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":1,"name":"ScaleSet"}`))

	case strings.Contains(r.URL.Path, "/_apis/runtime/runnergroups") && r.Method == http.MethodGet:
		_, _ = w.Write([]byte(`{"count":1,"value":[{"id":1,"name":"Default"}]}`))

	default:
		http.Error(w, fmt.Sprintf("unexpected benchmark request: %s %s", r.Method, r.URL.String()), http.StatusNotFound)
	}
}

func runParallelBenchmark(b *testing.B, run func(iteration int) error) {
	b.Helper()

	var failed atomic.Bool
	var firstErr error
	var once sync.Once
	recordErr := func(err error) {
		if err == nil {
			return
		}

		once.Do(func() {
			firstErr = err
			failed.Store(true)
		})
	}

	b.RunParallel(func(pb *testing.PB) {
		iteration := 0
		for pb.Next() {
			if failed.Load() {
				continue
			}

			recordErr(run(iteration))
			iteration++
		}
	})

	if firstErr != nil {
		b.Fatal(firstErr)
	}
}
