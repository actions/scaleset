# GitHub Actions Runner Scale Set Client (Public Preview)

> Status: **Public Preview** – While the API is stable, interfaces and examples in this repository may change.

This repository provides a standalone Go client for the GitHub Actions **Runner Scale Set** APIs. It is extracted from the `actions-runner-controller` project so that platform teams, integrators, and infrastructure providers can build **their own custom autoscaling solutions** for GitHub Actions runners.

You do *not* need to adopt the full controller (and Kubernetes) to take advantage of scale sets. This package contains all the primitives you need: create/update/delete scale sets, generate just‑in‑time (JIT) runner configs, and manage message sessions.

---

## What is a Scale Set?

A runner scale set is a group of self-hosted runners that autoscales based on workflow demand. Here's how it works:

1. **Registration**: You create a scale set with a name, which also serves as the label workflows use to target it (e.g., `runs-on: my-scale-set`). Multiple labels can be assigned per scale set (on GHES, this requires enabling a feature flag — see [GitHub Enterprise Server](#github-enterprise-server)). Like regular self-hosted runners, scale sets can be registered at the repository, organization, or enterprise level.
2. **Polling**: Your scale set client continuously polls the API, reporting its maximum capacity (how many runners it can produce).
3. **Job matching**: GitHub matches jobs to your scale set based on the label and runner group policies, just like regular self-hosted runners.
4. **Scaling signal**: The API responds with how many runners your scale set needs online (`statistics.TotalAssignedJobs`).
5. **Runner provisioning**: Your client creates or maintains enough runners to meet demand. Runners can be created just-in-time as jobs arrive, or pre-provisioned ahead of demand to reduce latency.
6. **Job assignment**: GitHub assigns a pending job to any idle runner in the scale set.

Runners in a scale set are ephemeral by default: each runner executes one job and is then removed. This ensures a clean environment for every job.

---

## High-Level Flow

1. Create a `Client` with either a GitHub App credential (recommended) or a PAT.
2. Create a Runner Scale Set with a name.
3. Start a message session and poll for scaling events. The `listener` package handles this for you.
4. When the API indicates runners are needed:
   - Call `GenerateJitRunnerConfig` to get a JIT config for a new runner.
   - Start your runner (process, container, VM, etc.) with the JIT config.
5. Idle runners are assigned jobs automatically by GitHub.

You can also pre-provision runners before jobs arrive to reduce startup latency. See [`examples/dockerscaleset`](./examples/dockerscaleset) for a complete example that supports both `minRunners` (pre-provisioned) and just-in-time scaling.

---

## Autoscaling

Use `statistics.TotalAssignedJobs` from each message response to determine how many runners your scale set needs online. This value represents the total number of jobs assigned to your scale set, including both jobs waiting for a runner and jobs already running (`TotalAssignedJobs >= TotalRunningJobs`).

Do not count individual job messages (`JobAssigned`, `JobStarted`, `JobCompleted`) in the response body to determine scaling:

- Responses contain at most 50 messages. Large backlogs will be truncated.
- The `statistics` field is always current and reflects the true state of your scale set.

When polling for messages, include your scale set's maximum capacity via the `maxCapacity` parameter (sent as the `X-ScaleSetMaxCapacity` header). This allows the backend to assign jobs accurately and avoid creating backlogs your scale set cannot fulfill.

Here's a simplified polling loop:

```go
var lastMessageID int
for {
    msg, err := client.GetMessage(ctx, lastMessageID, maxCapacity)
    if err != nil {
        return err
    }

    if msg == nil {
        // No messages available (202 response), poll again
        continue
    }

    lastMessageID = msg.MessageID

    // Scale based on statistics, not message counts
    desiredRunners := msg.Statistics.TotalAssignedJobs
    scaleToDesired(desiredRunners)

    // Acknowledge the message
    if err := client.DeleteMessage(ctx, msg.MessageID); err != nil {
        return err
    }
}
```

The `listener` package provides a ready-to-use implementation of this pattern, handling session management, polling, and acknowledgment. See [`listener/listener.go`](./listener/listener.go).

### Job lifecycle messages

Individual job messages (`JobStarted`, `JobCompleted`, etc.) are useful for purposes beyond scaling. For example, [actions-runner-controller](https://github.com/actions/actions-runner-controller) uses `JobStarted` to mark runner pods as busy, preventing premature cleanup during scale-down. These messages can also be used for metrics or logging.

See [`types.go`](./types.go) for payload definitions.

---

## How the Message API Works

### Long Polling

`GetMessage` uses long polling:

1. If messages are available, they are returned immediately.
2. Otherwise, the request blocks for up to ~50 seconds.
3. If no messages arrive, a 202 response is returned (`nil, nil` in the Go client).

Each poll waits at most `MessagePollTimeout` (2 minutes). That is above the ~50 second hold, with room if the service holds the poll longer. A stuck connection fails there instead of sitting for the 5 minute client timeout. If the session token has expired, the refresh is separate and the retry gets a new window of the same length. A `*http.Client` with a shorter timeout is not used as-is for a poll: the SDK copies it and raises the copy. The client you passed is not modified. A custom `HTTPClient` must allow an attempt of at least `MessagePollTimeout`.

Poll again immediately after handling each response.

### Message Acknowledgment

Call `DeleteMessage` after processing a message. This acts as an acknowledgment:

- Unacknowledged messages are redelivered on the next poll.
- This prevents message loss if your client crashes mid-processing.

### Message ID Tracking

Pass the ID of the last processed message to `GetMessage`. Omitting this (or passing 0) returns the first available message, potentially causing reprocessing.

### Job Reassignment

Jobs may appear multiple times as `JobAssigned` followed by `JobCompleted` (with `result: "canceled"`). This occurs when a job is assigned to your scale set but not acquired by a runner in time—GitHub cancels the assignment and requeues the job. This can happen up to 3 times with incremental delays.

Each attempt generates new messages, but they represent the same workflow job. This is why `statistics.TotalAssignedJobs` is the correct scaling metric: it reflects the current state, not the message history.

---

## Getting Started

```bash
go get github.com/actions/scaleset@latest
```

Import:

```go
import "github.com/actions/scaleset"
```

### Using Without Go Experience

If you are not a Go developer, you can still:

- Treat this repo as reference documentation to design an API integration in another language.
- Vendor the code and compile a minimal binary that exposes a simpler CLI.
- Use the example CLI (`examples/dockerscaleset`) as inspiration—its flags show required inputs.
- Copilot can also help you translate this Go code into your language of choice.

---

## Authentication

Three options:

1. **GitHub App (preferred):** Stronger scoping & rotation. Provide: `ClientID`, `InstallationID`, `PrivateKey`.
2. **GitHub App with custom JWT signing:** For KMS/HSM-backed keys where private key material cannot be in memory. Provide a `JWTProvider` implementation.
3. **PAT (personal access token):** Simpler but broader scoped.

The client automatically exchanges credentials for a registration token + admin token behind the scenes and refreshes them before expiry.

### Custom JWT Signing (KMS/HSM)

For organizations that require private key material to stay within a KMS or HSM boundary:

```go
// Using a crypto.Signer (AWS KMS, GCP Cloud KMS, Azure Key Vault, etc.)
provider := &scaleset.SignerJWTProvider{
    ClientID: "Iv1.abc123",
    Signer:   myKMSSigner, // any crypto.Signer with an RSA key
}

client, err := scaleset.NewClientWithJWTProvider(
    scaleset.ClientWithJWTProviderConfig{
        GitHubConfigURL: "https://github.com/my-org",
        InstallationID:  12345,
    },
    provider,
)
```

Or wrap any function that returns a signed JWT:

```go
provider := scaleset.JWTProviderFunc(func(ctx context.Context) (string, error) {
    return getJWTFromExternalService(ctx)
})
```

You can find more details on required permissions in the [GitHub Docs](https://docs.github.com/en/actions/tutorials/use-actions-runner-controller/authenticate-to-the-api).

GitHub Enterprise Server (GHES) is supported out of the box—just use your GHES URL when creating the client.

### GitHub Enterprise Server

#### Multiple labels per scale set

Assigning more than one label to a scale set is supported on **GHES 3.18 and later** and requires the `DistributedTask.AllowRunnerScaleSetCustomLabels` feature flag to be enabled on the appliance. Without it, the scale set name is used as the only label, and any additional labels you provide are silently dropped.

- **GHES 3.18 – 3.20:** the flag is **off by default**. A site admin needs to enable it on the appliance:

  ```bash
  # SSH into the GHES appliance as admin
  ghe-actions-console -s actions
  # In the LightRail prompt:
  Set-FeatureFlag -FeatureName DistributedTask.AllowRunnerScaleSetCustomLabels -State On
  ```

- **GHES 3.21 and later:** the flag is **on by default**, no action required.

---

## HTTP Transport and Retries

Transport belongs to you; retries belong to the SDK.

`WithHTTPClient` accepts anything with a `Do(*http.Request) (*http.Response, error)` method, including `*http.Client`. The SDK never writes to the client, its `Transport`, or its `tls.Config`, so TLS, proxies, connection pooling, and per-attempt timeouts stay under your control. The one exception is `GetMessage`: it bounds each poll attempt by `MessagePollTimeout`, and polls through a copy of an `*http.Client` whose shorter `Timeout` is raised to that value. The SDK calls `Do` concurrently, sharing one client across a `Client`, its message sessions, and goroutines, so a custom implementation must be safe for concurrent use, as `*http.Client` is.

```go
httpClient := &http.Client{
    // A bare http.Client has no timeout. DefaultTimeout is the 5 minute
    // per-attempt timeout the SDK used to set. GetMessage does not use a
    // shorter value on this client: each poll attempt waits up to
    // MessagePollTimeout.
    Timeout:   scaleset.DefaultTimeout,
    Transport: myInstrumentedTransport,
}

client, err := scaleset.NewClientWithPersonalAccessToken(config,
    scaleset.WithHTTPClient(httpClient),
)
```

If you don't want to assemble a transport by hand, `NewHTTPClient` builds a sensible `*http.Client` for the common cases. Leaving `Timeout` unset applies `DefaultTimeout` (5 minutes), the same client timeout as before:

```go
httpClient := scaleset.NewHTTPClient(scaleset.HTTPClientConfig{
    RootCAs:      myCertPool,
    Certificates: []tls.Certificate{myClientCert}, // mTLS
})
```

Retries are layered above the client and keep their state per request, which is what lets the SDK vary the policy for an individual call without touching shared state. `WithRetry` replaces the policy wholesale, so start from `DefaultRetryConfig` when tweaking:

```go
retry := scaleset.DefaultRetryConfig()
retry.Max = 8

client, err := scaleset.NewClientWithPersonalAccessToken(config,
    scaleset.WithRetry(retry),
)
```

`RetryConfig{}` (or `Max: 0`) disables retries entirely.

`RetryConfig.MaxElapsed` optionally limits each HTTP request, including all
attempts, waits, and reading the final response body. Zero leaves it unlimited.
A wait that would reach or pass this budget or the request context's deadline is
skipped, preserving the last response and any `RateLimitError.RetryAfter` hint.
If the budget expires during an attempt or body read, the error matches both
`MaxElapsedExceededError` and `context.DeadlineExceeded`. If the caller cancels or
its deadline fires first, its context error is preserved instead.

### Rate limits

By default, transport errors, 5xx responses (except 501), and 429 responses are retried up to 4 times with exponential backoff. A 429 waits for its full `Retry-After`; a rate-limited 403 is not retried, except on the admin token exchange that already retries 401/403. A wait that would reach or pass the context deadline is skipped, and the last response is returned instead of a context error.

A rate-limited response (any 429, or a 403 carrying `Retry-After`, `X-RateLimit-Remaining: 0`, or a secondary-limit message) comes back as a `*RateLimitError`:

```go
var rl *scaleset.RateLimitError
if errors.As(err, &rl) {
    // rl.Kind       RateLimitPrimary (spent quota, no secondary-limit message) or RateLimitSecondary
    // rl.StatusCode 429 or 403
    // rl.RetryAfter how long the server asked to wait, from Retry-After or X-RateLimit-Reset
    // rl.Reset      when the rate limit window resets, from X-RateLimit-Reset
    // rl.Retries    rate-limited retries the SDK already made for this request
}
```

`RetryConfig.OnRateLimit` decides whether and how long to wait on a rate-limited response, in place of `ShouldRetry`. A zero wait with `retry=true` uses `Backoff`. `RateLimitRetries` builds a hook from a rule per kind. Set it client-wide with `WithRetry`:

```go
retry := scaleset.DefaultRetryConfig()
retry.OnRateLimit = scaleset.RateLimitRetries(
    scaleset.RateLimitRule{},                                     // primary: return immediately
    scaleset.RateLimitRule{MaxRetries: 2, MaxWait: 5 * time.Second}, // secondary: short retry
)

client, err := scaleset.NewClientWithPersonalAccessToken(config,
    scaleset.WithRetry(retry),
)
```

The hook and final error use the same classification, including secondary-limit
messages in JSON or plain-text 403/429 bodies. Read and close failures remain in
the final error chain. `RateLimitError.Retries` counts
the rate-limited retries already made for this request, across both kinds;
transport and other HTTP retries do not increase it. A server hint longer than
`MaxWait` is rejected, not shortened. `Max`, `MaxElapsed`, and the context
deadline still bound retries. Hooks may run concurrently.

When requeuing rate-limited work, preserve a positive `RetryAfter` hint and
use a positive fallback (for example, one minute) when it is zero.
In controller-runtime, `RequeueAfter: 0` with a nil error schedules no retry.

To change the policy for one call only, wrap its context with `WithRequestRetry`. The function gets a copy of the client's `RetryConfig`, so other calls, including concurrent ones on the same `Client`, keep the client's policy. A controller can give up on a rate limit quickly and requeue the work instead of blocking:

```go
ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
defer cancel()

ctx = scaleset.WithRequestRetry(ctx, func(c *scaleset.RetryConfig) {
    c.OnRateLimit = scaleset.RateLimitRetries(
        scaleset.RateLimitRule{},                                     // primary: return immediately
        scaleset.RateLimitRule{MaxRetries: 2, MaxWait: 5 * time.Second}, // secondary: short retry
    )
    c.MaxElapsed = 20 * time.Second
})

jit, err := client.GenerateJitRunnerConfig(ctx, setting, scaleSetID)
var rl *scaleset.RateLimitError
if errors.As(err, &rl) {
    return ctrl.Result{RequeueAfter: max(rl.RetryAfter, minBackoff)}, nil
}
```

`WithRequestRetry` works with every `Client` and `MessageSessionClient` method, and nested calls apply outer first. A `MaxElapsed` set this way applies to each HTTP request the call makes; the context deadline bounds the whole call. The SDK's own per-request adjustments run after yours, so replacing `ShouldRetry` does not stop the admin token exchange from retrying 401 and 403 within your `Max`. A rate-limited 403 is the exception: an `OnRateLimit` you set still decides it. `GetMessage` bounds each poll attempt by `MessagePollTimeout`; retries get a new window, so only the context deadline bounds the whole call.

### Migrating from the transport options

If you never passed an HTTP option, you change no code. The constructors are the same, and the defaults are the same.

That path did not have the shared-client race. With no custom client, each call built its own HTTP client, so token refresh had nothing shared to write. The race only happened when `WithRetryableHTTPClint` made every call share one client.

Change code only if you used one of the options below. Four things still differ for everyone: a retry that runs out returns the final response instead of `"giving up after N attempts"`, each `GetMessage` poll attempt times out after `MessagePollTimeout` (2 minutes) instead of the 5 minute client timeout and is then retried like any other failed attempt, a redirect loop, a bad scheme, or an invalid header can be retried, and `DefaultBackoff` adds up to 50% random jitter to each exponential delay, so a retry can wait somewhat longer than before (still capped at `WaitMax`). Certificate errors still are not retried.

`WithRetry` replaces the policy wholesale. Start from `DefaultRetryConfig()` and change the field you care about. A literal `RetryConfig{WaitMax: d}` also sets `Max` to 0, which disables retries.

| Removed | Replacement |
| --- | --- |
| `WithRetryableHTTPClint(c)` | `WithHTTPClient(c.HTTPClient)` — retries move to `WithRetry`. retryablehttp's client has no `Timeout`, which the SDK used to raise to 5 minutes; set `c.HTTPClient.Timeout = scaleset.DefaultTimeout` to keep that limit |
| `WithRetryMax(n)` | `retry := DefaultRetryConfig(); retry.Max = n`; `WithRetry(retry)` |
| `WithRetryWaitMax(d)` | `retry := DefaultRetryConfig(); retry.WaitMax = d`; `WithRetry(retry)`. `WaitMax: 0` now means `DefaultRetryWaitMax`; for the old `WithRetryWaitMax(0)` (retry immediately, still honoring `Retry-After`), use `time.Nanosecond` |
| `WithTimeout(d)` | `NewHTTPClient(HTTPClientConfig{Timeout: d})`. Unset or `0` now means `DefaultTimeout` (5 minutes); for the old `WithTimeout(0)` (no timeout), set `Timeout = 0` on the returned client |
| `WithProxy(f)` | `NewHTTPClient(HTTPClientConfig{Proxy: f})` |
| `WithRootCAs(pool)` | `NewHTTPClient(HTTPClientConfig{RootCAs: pool})` |
| `WithoutTLSVerify()` | `NewHTTPClient(HTTPClientConfig{InsecureSkipVerify: true})` |
| `WithTLSClientCertificate(cert)` | `NewHTTPClient(HTTPClientConfig{Certificates: []tls.Certificate{cert}})` |
| `WithTLSClientCertificateFromFile(c, k)` | `tls.LoadX509KeyPair` + `Certificates` |

---

## Security Notes

- Always prefer GitHub App credentials; rotate PATs if you must use them.
- Use `SignerJWTProvider` or `JWTProviderFunc` to keep private key material in a KMS/HSM.
- Treat JIT configs as secrets until consumed.

---

## Requirements

- Go 1.25 or later

---

## License

This project is licensed under the terms of the MIT open source license. Please refer to [LICENSE](./LICENSE) for the full terms.

---

## Maintainers

See [CODEOWNERS](./.github/CODEOWNERS) for the list of maintainers.

---

## Support

Please refer to [SUPPORT.md](./SUPPORT.md) for information on how to get help with this project.
