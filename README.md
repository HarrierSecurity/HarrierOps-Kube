# Harrier Ops Kube

Harrier Ops Kube tells you what your current Kubernetes foothold can actually do, what it can reach, and what matters next.

> Most Kubernetes tools give you objects.
> Most inventory views tell you what exists.
> Harrier Ops Kube tells you what your foothold means.
> It prioritizes consequence, attack paths, and the next move.

## Why Run This First

Run this first when:

- you have a `kubeconfig` and need to know whether it lands near exposed workloads, meaningful
  service accounts, or stronger control paths
- you landed in a pod and need to know what identity, token, or host-level access that foothold
  really carries
- you found a service account or token reference and need to know whether it is just background
  noise or the start of a real escalation path

This is not the point where you want a generic object dump.
This is the point where you want to know what your foothold changes right now.

## Fast Proof

In seconds, Harrier Ops Kube shows you:

- what identity you are really running as
- what cluster, namespace, and context you actually landed in
- which workloads and services look exposed first
- which service accounts and token paths matter
- which visible paths look like real escalation or control expansion leads

## Quickstart

Run the foothold, edge, workload, and escalation flow:

```bash
harrierops-kube whoami
harrierops-kube inventory
harrierops-kube exposure
harrierops-kube workloads
harrierops-kube privesc
```

If identity and token paths matter more than the edge first:

```bash
harrierops-kube service-accounts
```

## Operator Outcome

After one short pass, you understand:

- what your foothold really is
- which workloads, identities, and exposed paths deserve attention first
- whether there is a believable token, service-account, or escalation story nearby
- where to go next without reading the whole cluster like a spreadsheet

## What Makes This Different

- Foothold-first: it starts from the access you already have, not from a generic cluster census.
- Prioritized: it lifts the workloads, identities, and paths that change the next move.
- Attack-path-aware: it keeps exposure, service accounts, tokens, and escalation in the same
  operator workflow.
- Not an object dump: it is built to reduce noise, not produce more of it.

## Use Cases

- You have cluster access through a `kubeconfig` and need fast blast-radius triage.
- You landed in a pod and need to understand the service account, token posture, and nearby risk.
- You are validating how far a foothold, token, or service account could realistically go.

## Install

Download the right binary for your platform from GitHub Releases and extract it.

## Currently Supported Commands

| Section | Commands |
| --- | --- |
| `core` | `inventory` |
| `identity` | `whoami`, `rbac`, `service-accounts`, `permissions`, `privesc` |
| `workload` | `workloads` |
| `exposure` | `exposure` |
| `secrets` | `secrets` |

Later depth surface:

- `images`

## Kubernetes Access

Harrier Ops Kube expects existing Kubernetes access.
It is not a login manager or a custom auth flow.

The intended operator path is the Kubernetes access you already have:

- the current working `kubectl` context
- a `kubeconfig` file, usually from `~/.kube/config`
- `KUBECONFIG` when it points to a different config path

It also assumes the current machine can reach the Kubernetes API it is trying to use.
If the `kubeconfig` points to a private endpoint, you still need network reachability from the
current host.

## Current Runtime Note

The current build is fixture-backed while the live `kubectl` collectors are rebuilt.
If you want repeatable local output today, set `HARRIEROPS_KUBE_FIXTURE_DIR`:

```bash
HARRIEROPS_KUBE_FIXTURE_DIR=testdata/fixtures/lab_cluster \
  go run ./cmd/harrierops-kube whoami --output table
```

The command surface and output contracts match the operator-facing command set above.

## CLI Invocation

Shared flags include `--context`, `--namespace`, `--output`, `--outdir`, and `--debug`.
Commands come first, then shared flags or `help`.

```bash
harrierops-kube <command> [global options]
```

Examples:

```bash
harrierops-kube whoami --output json --outdir ./harrierops-kube-demo
harrierops-kube inventory --context prod-cluster --namespace payments
harrierops-kube permissions help
```

## Output Modes

- `--output table` (default)
- `--output json`
- `--output csv`

When `--outdir` is set, commands write artifacts under `<outdir>/`:

- `loot/<command>.json`
- `json/<command>.json`
- `table/<command>.txt`
- `csv/<command>.csv`

## Development

```bash
gofmt -w ./cmd ./internal
go test ./...
bash scripts/setup_local_guardrails.sh
```
