# ci-dispatcher

`ci-dispatcher` serves every self-hosted GitHub Actions runner scale set of an
account from **one process**, instead of one ARC listener per scale set. It is
built on the scaleset library of this repository (a fork of
[`actions/scaleset`](https://github.com/actions/scaleset)); the library itself
is left untouched so upstream updates merge cleanly.

What it does:

- opens one message session per queue (repository × profile) and adopts the
  scale set of that name when it already exists, so it can take over a queue
  created by ARC without changing any workflow label;
- builds each runner pod from a **profile** of a catalog (image, Docker
  sidecar, caches, nodes, resources);
- keeps a **warm pool** of ready pods per profile: a job picks a pod that
  already pulled its image and ran its init containers;
- hands the JIT runner configuration to the pod through an in-cluster
  **claim** endpoint, authenticated by the pod's projected service account
  token;
- accounts runner places **per node** across every queue, with round-robin
  fairness between repositories;
- exposes the ARC listener metrics (`gha_*`, same names and labels) plus its
  own (`ci_dispatcher_*`).

Only outbound connections: no webhook, no ingress.

## Layout

| Path | Role |
|---|---|
| `cmd/ci-dispatcher` | the service (`run`, `validate`, `render`, `delete-queues`) |
| `cmd/ci-runner-agent` | the agent started in every runner pod |
| `dispatcher/catalog` | catalog loading, validation and resolution into queues |
| `dispatcher/gh` | the only package calling GitHub (scaleset library + a few REST calls) |
| `dispatcher/sessions` | one goroutine and message session per queue |
| `dispatcher/controller` | runner accounting, warm or cold provisioning, deletion, garbage collection |
| `dispatcher/budget` | per-node places and fairness |
| `dispatcher/pods` | pod templates, rendering and Kubernetes operations |
| `dispatcher/warmpool` | warm pod selection |
| `dispatcher/claim` | claim endpoint (`/v1/ready`, `/v1/claim`) |
| `dispatcher/metrics` | Prometheus collectors |
| `charts/ci-dispatcher` | Helm chart |
| `docker/Dockerfile.dispatcher` | image with both binaries |

## Runner pod life cycle

1. A session reports `statistics.TotalAssignedJobs` for a queue. The wanted
   runner count is that number, bounded by `maxRunners`, with `minRunners`
   as a floor.
2. For every missing runner the budget grants a place. The controller takes
   the oldest **ready** warm pod of the queue profile; without one, it
   creates a **cold** pod with the same template, the repository already
   known.
3. It registers a JIT runner named after the pod (`ci-<profile>-<5 chars>`),
   labels the pod with its repository and deposits the configuration in the
   pod's mailbox.
4. The agent of the pod (`POST /v1/ready`, then `GET /v1/claim?wait=50s`)
   receives the configuration **once**; it is then erased from memory. The
   agent exports `ACTIONS_RUNNER_INPUT_JITCONFIG` and runs
   `/home/runner/run.sh`, forwarding `SIGTERM`/`SIGINT`, and empties the
   per-pod state directory when the runner exits.
5. The pod is deleted when the runner exits, or 60 s after `JobCompleted`.
   Idle surplus runners (assigned for more than 2 minutes, no job) are
   unregistered and deleted.

A queue whose runner registrations fail backs off (2 s doubling to 60 s)
instead of retrying at every reconciliation. A registration answered `not
found` means the scale set was deleted on GitHub (by ARC finishing its
cleanup after an adoption, for example): the session on it is closed and the
scale set is adopted again by name, or recreated. At startup, a repository
whose visibility stays unknown after a few retries is left out, logged and
counted in `ci_dispatcher_session_errors_total{reason="visibility"}`; the
other repositories are served, and the dispatcher restarts to serve it as
soon as a recheck (every 5 minutes) reaches it. With no repository's
visibility known, the dispatcher stops (and Kubernetes restarts it).

Garbage collection (startup, then every 5 minutes): pods of an unknown queue,
assigned pods that never claimed their configuration within 10 minutes or
whose configuration was lost (dispatcher restart), warm pods that never
became ready; every 15 minutes, offline `ci-*` runners without a pod.

## Claim security

- Runner pods get no API token (`automountServiceAccountToken: false`) but a
  projected token of audience `ci-dispatcher`, valid 10 minutes.
- The dispatcher validates it with a `TokenReview`, reads the pod name and
  UID bound to the token and only answers for a pod of its namespace, with
  that UID and the label `app.kubernetes.io/managed-by: ci-dispatcher`.
- A configuration is delivered once (`410 Gone` afterwards). The claim
  service is a `ClusterIP`; only the leader replica is ready, so claims
  always reach the replica holding the mailboxes.
- The job itself can read the token file. It can only ask for its own pod's
  configuration, already delivered, and the API server rejects that
  audience.

## Catalog

The catalog is one YAML document (a ConfigMap in the chart). Unknown keys,
unknown profiles, unpinned images and unsafe public profiles stop the
dispatcher at startup. A complete example: `dispatcher/examples/catalog.yaml`.

```yaml
github:
  owner: example-owner
  auth:                       # the Secret is mounted by the chart, never created
    type: pat                 # or app: appClientID, installationID, privateKeyKey
    secretRef: {name: github-pat, key: github_token}
discovery: {enabled: false}   # app only: serve every repository of the installation
runtime:
  namespace: ci-runners
  claimURL: http://ci-dispatcher-claim.ci-runners.svc.cluster.local:8081
  labelPrefix: ci.example.com # prefix of profile, state, trust, repo, scale-set-id labels
  forbiddenPublicNodes: [node-cp]
caches:
  language-nfs: {type: language, hostPath: /var/lib/runner-cache, serverNode: node-c}
  proxies: {type: proxies, env: {GOPROXY: http://go-proxy:3000}, aptConfigMap: runner-apt-proxy}
profiles:
  docker: {template: docker, image: <pinned>, dind: {image: <image>}, caches: [language-nfs, proxies], nodes: [node-a, node-b], warm: 0}
  light:  {template: light,  image: <pinned>, caches: [proxies], nodes: [node-a], warm: 2}
  public: {template: light,  image: <pinned>, nodes: [node-a], trust: public}
defaults: {profiles: [docker], maxRunners: 6, publicProfile: public}
repos:
  demo: {profiles: [docker, light]}
  api-server: {priority: high, nodes: ["+node-c"], resources: {limits: {memory: 8Gi}}}
  OpenTool: {fileNames: {docker: runner-OpenTool}}
capacity:
  enforce: false              # true: no pod without a free place
  nodes: {node-a: 4, node-b: 6, node-cp: auto}
fileNames: {docker: "runner-{repo}", light: "runner-{repo}-light", "*": "runner-{repo}-{profile}"}
```

Per repository (and per repository and profile under `perProfile`):
`image`, `resources`, `dockerDataLimit`, `dindMemory`, `maxRunners`,
`minRunners`, `nodes` (`["+node"]` adds, a plain list replaces),
`preferNodes`, `serviceAccountName`, `cacheProfile` (`nfs` or `local`), `env`,
`profiles`, `fileNames`, `priority`, `name` (exact GitHub name when it differs
from the key).

**Public repositories** (visibility read from the GitHub API) are always
served by the public profile, whatever they ask for, under the queue names
they asked for: workflows keep their labels. Their node and cache overrides
are ignored, their caches are pod-local, and a public profile can never mount
the shared language cache, the registry credentials or a control-plane node.

`ci-dispatcher validate --catalog <file>` lists the queues; `ci-dispatcher
render --catalog <file> <queue>` prints the cold pod of a queue.

## Templates

`docker` (runner, privileged dind native sidecar, runner externals,
per-repository language cache, package proxies) and `light` (runner alone)
are built in. `templates:` in the catalog adds or replaces a template (Go
`text/template` rendering a Pod). Whatever the template, the dispatcher sets
the name, labels, `restartPolicy: Never`, the agent init container, the
projected token and the runner command, and rejects a template with more than
one container or host namespaces.

**Warm docker pods** (`warm > 0` on a docker profile) mount the whole
language cache root, since the repository is only known at claim time; the
agent prepares the repository directories and points `GOCACHE`,
`GOMODCACHE` and `UV_CACHE_DIR` at them. Every warm pod can then read every
repository's cache: keep `warm: 0` on docker profiles unless that is
acceptable.

## Budget

Every runner pod of the namespace counts on its node (pods created by
another controller included), pending pods pinned to one node count on that
node. `capacity.nodes` gives the places, `auto` none. With `enforce: false`
the plan grants everything and only exposes `ci_dispatcher_budget_blocked`.
With `enforce: true`, a runner without a free place waits in its GitHub
queue (no Pending pod) and the pod is pinned to the node chosen.

## Metrics

`gha_started_jobs_total`, `gha_completed_jobs_total`, `gha_assigned_jobs`,
`gha_running_jobs`, `gha_registered_runners`, `gha_busy_runners`,
`gha_idle_runners`, `gha_min_runners`, `gha_max_runners`,
`gha_desired_runners`, `gha_job_startup_duration_seconds`,
`gha_job_execution_duration_seconds` (labels of the ARC listener), and
`ci_dispatcher_sessions{state}`, `ci_dispatcher_session_errors_total{reason}`,
`ci_dispatcher_warm_pods{profile,state}`,
`ci_dispatcher_claim_duration_seconds{profile,source}`,
`ci_dispatcher_budget_blocked{profile}`, `ci_dispatcher_budget_free{node}`,
`ci_dispatcher_pods_created_total`, `ci_dispatcher_pod_errors_total`,
`ci_dispatcher_github_ratelimit_remaining`, `ci_dispatcher_gc_removed_total`.

The dispatcher pod carries `app.kubernetes.io/component:
runner-scale-set-listener` and a `metrics` port, like ARC listeners.

## Running

```sh
helm install ci-dispatcher oci://ghcr.io/didlawowo/charts/ci-dispatcher -n ci-runners -f values.yaml
```

Local run against a cluster (the token is read from a file or a pipe):

```sh
go run ./cmd/ci-dispatcher run --catalog catalog.yaml --kube-context my-cluster --github-token-file <(gh auth token) --leader-elect=false
```

RBAC: pods (get, list, watch, create, delete, patch) and leases in the
namespace; tokenreviews (create) and nodes (list, watch) cluster-wide.
Nothing else.

## Releases

A merge on main whose `ci-dispatcher` checks pass cuts a release
(`release.yml`: conventional commits, `cliff.toml`, tag `dispatcher-vX.Y.Z`).
`cd.yml` then delivers that tag:

1. publishes `ghcr.io/didlawowo/ci-dispatcher:X.Y.Z` (amd64, arm64) and the
   chart `oci://ghcr.io/didlawowo/charts/ci-dispatcher`;
2. writes the digest in `acceptance/values.yaml`: a candidate dispatcher,
   deployed apart with its own namespace, Lease and a catalog limited to the
   `ci-acceptance` queue of this repository, picks it up;
3. runs `acceptance.yml`: real jobs on that queue, each checking that
   `DISPATCHER_IMAGE` (the image of the dispatcher that served it, given to
   every runner in its claim) is the candidate's digest;
4. green only, writes the digest in `charts/ci-dispatcher/values.yaml`, which
   production reads on main.

A failed acceptance leaves production on the last validated digest. Rollback:
revert the promote commit. Nobody tags by hand.

## Limits

- `actions/scaleset` is a public preview.
- Mailboxes live in memory: a dispatcher restart loses the configurations of
  pods not yet claimed; those pods are collected and recreated.
- Discovery runs at startup only.
