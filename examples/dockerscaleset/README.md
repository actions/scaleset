# Docker Runner Scale Set Example

This example showcases a Docker implementation of GitHub Actions runner scale sets, using the `github.com/actions/scaleset` client to provision ephemeral GitHub Actions runners as Docker containers.

The goal of this example is to show how simple and powerful it is when you only need to focus on the core logic of scaling runners up and down, while the client handles all the API interactions.

> [!WARNING]
> This is a simplified example meant for demonstration and learning purposes. It is not intended for production use.

> [!NOTE]
> When exiting normally all runners and the scale set itself are cleaned up automatically.

## Getting started

You can install the example with:

```bash
go install github.com/actions/scaleset/examples/dockerscaleset@latest
```

You'll then need:

- Docker installed and running on your machine.
- A URL for the target repository, organization, or enterprise where you want to register your scale set.
- [Credentials that have access to the above target](https://docs.github.com/en/actions/tutorials/use-actions-runner-controller/authenticate-to-the-api): you can use either a GitHub App (recommended) or a Personal Access Token (PAT).
- A name for your scale set (this must be unique within the runner group the scale set is created in).

---

## Flags

| Flag | Required | Description |
|------|----------|-------------|
| `--url` | Yes | Registration target (org, repo, or enterprise URL, e.g. `https://github.com/org/repo`). |
| `--name` | Yes | Runner scale set name (must be unique within the runner group). |
| `--max-runners` | No | Upper bound of concurrently provisioned runners (default 10). |
| `--min-runners` | No | Lower bound to maintain (default 0). |
| `--runner-group` | No | Runner group name (default `default`). |
| `--app-client-id` | Cond.* | GitHub App Client (App) ID. |
| `--app-installation-id` | Cond.* | GitHub App Installation ID. |
| `--app-private-key` | Cond.* | GitHub App private key PEM contents. |
| `--token` | Cond.* | Personal Access Token (alternative to App). |
| `--log-level` | No | `debug`, `info`, `warn`, `error` (default `info`). |
| `--log-format` | No | `text`, `json`, or `none` (any invalid → no logs). |
| `--runner-image` | No | Override container image (defaults to latest official). |

*Provide either App credentials (all three) OR a PAT.*
