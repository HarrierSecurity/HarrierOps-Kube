# Harrier Ops Kube

Harrier Ops Kube is a Go CLI for offensive-focused Kubernetes recon and chaining.
It helps operators and testers understand what Kubernetes identity, workload, RBAC, and exposure
signals they can actually see from the access they already have.

It is being shaped as a sibling project to AzureFox: flat commands, deterministic output
contracts, artifact emission for every run, and operator-readable output that stays inside the recon
boundary.

## Quickstart

Download the right binary for your platform from GitHub Releases and extract it.

```bash
harrierops-kube <command> [global options]
```

By default, Harrier Ops Kube writes artifacts into your current directory. If you want them
somewhere else, pass `--outdir`:

```bash
harrierops-kube whoami --output table --outdir ./harrierops-kube-demo
```

## Currently Supported Commands

| Section | Commands |
| --- | --- |
| `core` | `inventory` |
| `identity` | `whoami`, `rbac`, `service-accounts` |
| `workload` | `workloads` |
| `exposure` | `exposure` |

Planned Phase 1 commands not implemented yet:

- `permissions`
- `secrets`
- `privesc`

Later-depth surface, not part of the current runnable Phase 1 core:

- `images`

## Releases

Tagged releases publish prebuilt binaries through GitHub Releases.
Release artifacts include macOS binaries for both Apple Silicon (`darwin-arm64`) and Intel
(`darwin-amd64`), plus Linux and Windows builds.

## CLI Invocation

Shared flags include `--context`, `--namespace`, `--output`, `--outdir`, and `--debug`.
They work before or after the command, but the examples below lead with the command name for
readability.

```bash
harrierops-kube <command> [global options]
```

These forms are equivalent:

```bash
harrierops-kube whoami --output json --outdir ./harrierops-kube-demo
harrierops-kube --output json --outdir ./harrierops-kube-demo whoami
harrierops-kube inventory --context prod-cluster --namespace payments
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
fixtures. The current implementation is fixture-backed while the live `kubectl` collectors are
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

Artifact intent:

- `json/` is the full structured command record.
- `loot/` is the smaller high-value handoff for quick operator follow-up.
- `table/` and `csv/` are convenience views rendered from the same underlying command result.

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

## Roadmap

The current Phase 1 direction is Kubernetes-first:

- `whoami`, `inventory`, `rbac`, `service-accounts`, `workloads`, and `exposure` are the current runnable scaffold
- `permissions`, `secrets`, and `privesc` remain part of the planned Phase 1 core
- `images` stays demoted to a later depth surface unless implementation proves it should move up
- output should stay plain-language, operator-readable, and inside the recon boundary
