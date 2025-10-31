# GitHub Actions Runner Scale Set Client (Private Preview)

> Status: **Private Preview** – While the API is stable, interfaces and examples in this repository may change.

This repository provides a standalone Go client for the GitHub Actions **Runner Scale Set** APIs. It is extracted from the `actions-runner-controller` project so that platform teams, integrators, and infrastructure providers can build **their own custom autoscaling solutions** for GitHub Actions runners.

You do *not* need to adopt the full controller (and Kubernetes) to take advantage of scale sets. This package contains all the primitives you need: create/update/delete scale sets, generate just‑in‑time (JIT) runner configs, manage message sessions, and react to job lifecycle events.

---

## High-Level Flow

1. Create a `Client` with either a GitHub App credential (recommended) or a PAT.
2. Create a Runner Scale Set specifying labels & settings.
3. Start a message session to receive scale / job events: the `listener` package in this repo can give you a headstart with this.
4. What you need to bring is what it means **to your infrastructure** to provision/tear down a runner:
   - Call `GenerateJitRunnerConfig` to obtain an encoded JIT config for a new runner belonging to your scale set.
   - Start a fresh runner process/container/VM passing the JIT config.
   - 🎉 You have a new runner!

You can find a complete example of a Docker-based scale set in [`examples/dockerscaleset`](./examples/dockerscaleset).

> [!NOTE]
> It's important to let the API know about your scale set maximum capacity using the `X-ScaleSetMaxCapacity` header when starting a message session so that job assignment can be as accurate as possible.

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

---

## Working With Messages

- Call `CreateMessageSession` to obtain `messageQueueUrl` and `messageQueueAccessToken`.
- Poll with `GetMessage(lastMessageID, maxCapacity)`; you get scaling / job events.
- After processing a message, call `DeleteMessage(messageId)`.
- Refresh or delete the session as needed (`RefreshMessageSession`, `DeleteMessageSession`).

Scaling logic uses the statistics & job events to decide how many new JIT configs to generate.

---

## Security Notes

- Always prefer GitHub App credentials; rotate PATs if you must use them.
- Treat JIT config blobs as secrets until consumed.

---
