# GitHub Actions Runner Scale Set Client (Private Preview)

> Status: **Private Preview** – While the API is stable, interfaces and examples in this repository may change.

This repository provides a standalone Go client for the GitHub Actions **Runner Scale Set** APIs. It is extracted from the `actions-runner-controller` project so that platform teams, integrators, and infrastructure providers can build **their own custom autoscaling solutions** for GitHub Actions runners.

You do *not* need to adopt the full controller (and Kubernetes) to take advantage of scale sets. This package contains all the primitives you need: create/update/delete scale sets, generate just‑in‑time (JIT) runner configs, and manage message sessions.

---

## What is a Scale Set?

A runner scale set is a group of self-hosted runners that autoscales based on workflow demand. Here's how it works:

1. **Registration**: You create a scale set with a name, which also serves as the label workflows use to target it (e.g., `runs-on: my-scale-set`). Like regular self-hosted runners, scale sets can be registered at the repository, organization, or enterprise level.
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

Two options:

1. **GitHub App (preferred):** Stronger scoping & rotation. Provide: `ClientID`, `InstallationID`, `PrivateKey`.
2. **PAT (personal access token):** Simpler but broader scoped.

The client automatically exchanges credentials for a registration token + admin token behind the scenes and refreshes them before expiry.

You can find more details on required permissions in the [GitHub Docs](https://docs.github.com/en/actions/tutorials/use-actions-runner-controller/authenticate-to-the-api).

GitHub Enterprise Server (GHES) is supported out of the box—just use your GHES URL when creating the client.

---

## Security Notes

- Always prefer GitHub App credentials; rotate PATs if you must use them.
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
