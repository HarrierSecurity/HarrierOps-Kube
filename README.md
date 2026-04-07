# Harrier Ops Kube

Harrier Ops Kube is a Go-first, `kubectl`-first CLI scaffold for offensive-focused Kubernetes
recon and chaining.

It is part of the HarrierOps tool family:

- Harrier Ops Kube
- Harrier Ops Azure
- Harrier Ops AWS
- Harrier Ops GCP

It is being shaped as a sibling project to AzureFox: flat commands, deterministic output
contracts, artifact emission for every run, and operator-readable output that stays inside the recon
boundary.

## Current Repo State

The repo currently contains a fixture-backed Go scaffold:

- existing planning docs, schemas, fixtures, and output contracts remain the source of truth
- the current Go implementation focuses on command shape, artifact writing, and regression tests
- live `kubectl` collection still needs to be rebuilt on top of this scaffold
- the runnable command set is intentionally narrower than the full planned Phase 1 family

## Current Command Surface

Runnable now:

- `whoami`
- `inventory`
- `rbac`
- `service-accounts`
- `workloads`
- `exposure`

Planned Phase 1 commands, not implemented yet:

- `permissions`
- `secrets`
- `privesc`

Later depth surface, not part of the current runnable Phase 1 core:

- `images`

## References

This repo is being shaped against:

- [OWASP Kubernetes Top Ten](https://owasp.org/www-project-kubernetes-top-ten/)
- the AzureFox repo and its proof lab

For project-specific coding and product-boundary guidance, see
[AGENTS.md](/Users/cfarley/Documents/HarrierOps-Kube/AGENTS.md).

## Quickstart

```bash
go test ./...
HARRIEROPS_KUBE_FIXTURE_DIR=testdata/fixtures/lab_cluster \
  go run ./cmd/harrierops-kube --outdir /tmp/harrierops-kube-demo whoami --output json
HARRIEROPS_KUBE_FIXTURE_DIR=testdata/fixtures/lab_cluster \
  go run ./cmd/harrierops-kube --outdir /tmp/harrierops-kube-demo inventory --output json
```

## Kubernetes Access Assumptions

Harrier Ops Kube expects existing Kubernetes access. It is not meant to be a login manager or a
custom auth flow.

By default, Harrier Ops Kube should use the same cluster access an operator already has, such as:

- the current working `kubectl` context
- a `kubeconfig` file, usually from `~/.kube/config`
- `KUBECONFIG` when it points to a different config path
- later, a direct service-account-token mode when that foothold is added explicitly

Plain-language shortcut:

- AzureFox starts from cloud credentials
- Harrier Ops Kube starts from Kubernetes credentials

That means a realistic workstation or operator path may include:

- a locally stored `kubeconfig`
- a cloud-backed `kubeconfig` that can refresh cluster access through an existing cloud session
- a shell where `kubectl` already works and Harrier Ops Kube can reuse that active context

Harrier Ops Kube also assumes the current machine can actually reach the Kubernetes API it is trying
to use.

- if the `kubeconfig` points to a private or internal address, the operator still needs network
  reachability from the current host
- Harrier Ops Kube can use the credentials and context it is given, but it cannot solve off-network
  access by itself

Current limitation:

- Harrier Ops Kube is `kubectl`-first right now
- it reuses the Kubernetes access and visibility the current `kubectl` session already has
- it is not using a separate native Kubernetes API collector yet

If the current session cannot read much, Harrier Ops Kube should say the view is partial or blocked
instead of pretending the cluster is quiet.

## Data Sources

Harrier Ops Kube is `kubectl`-first right now.

For repeatable development and testing, set `HARRIEROPS_KUBE_FIXTURE_DIR` to use local JSON
fixtures. The current Go scaffold is fixture-backed while the live `kubectl` collectors are being
rebuilt.

```bash
HARRIEROPS_KUBE_FIXTURE_DIR=testdata/fixtures/lab_cluster \
  go run ./cmd/harrierops-kube inventory --output json
```

## Output Modes

- `--output table` (default)
- `--output json`
- `--output csv`

All commands write artifacts under `<outdir>/`:

- `loot/<command>.json`
- `json/<command>.json`
- `table/<command>.txt`
- `csv/<command>.csv`

## Sections

- `identity`: `whoami`, `rbac`, `service-accounts`
- `core`: `inventory`
- `workload`: `workloads`
- `exposure`: `exposure`

## Development

```bash
gofmt -w ./cmd ./internal
go test ./...
bash scripts/setup_local_guardrails.sh
```

## GitHub Guardrails

The repo now mirrors the AzureFox-style lightweight publish guardrails:

- local pre-push hook for branch naming, direct `main` push blocking, formatting checks, tests, and optional `gitleaks`
- CI checks for PR metadata policy, `gitleaks`, formatting, and `go test ./...`
- Dependabot for GitHub Actions and Go modules
- PR template plus contributor and security guidance

## Phase 1 Direction

The current Phase 1 direction is Kubernetes-first:

- `whoami`, `inventory`, `rbac`, `service-accounts`, `workloads`, and `exposure` are the current runnable scaffold
- `permissions`, `secrets`, and `privesc` remain part of the planned Phase 1 core
- `images` stays demoted to a later depth surface unless implementation proves it should move up
- output should stay plain-language, operator-readable, and inside the recon boundary
