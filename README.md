# HarrierOps Kube

Find attack paths, exposed workloads, and control-expansion opportunities in Kubernetes before you drown in objects.

Most Kubernetes tools tell you what exists.
HarrierOps Kube tells you what the foothold you already have can actually do.
Most Kubernetes tools dump objects and permissions.
HarrierOps Kube highlights which workloads, service accounts, token paths, and escalation leads matter first.

## Why This Matters

You have:

- a `kubeconfig`
- a pod foothold
- a service account or token clue
- partial cluster visibility

You need to answer quickly:

- What identity am I actually holding?
- What can it reach or control right now?
- Which workloads or services are exposed first?
- Which service account, token, or secret path matters next?
- Which path is most likely to become escalation or broader cluster control?

HarrierOps Kube is built for that workflow.

## Why This Is Different

- Attack-path thinking, not inventory-first reporting
- Foothold-first workflow, not isolated object output
- Workload, service-account, and token consequence, not just raw Kubernetes listings
- Operator guidance that points to the next path worth investigating
- Broader than a foothold check: useful for movement, consequence, and follow-on access across the cluster

## Core Capabilities

- Show the current Kubernetes identity, context, namespace, and foothold shape you are operating from
- Surface exposed services, ingress paths, and joined workloads that change the next move
- Highlight service-account usage, token posture, and secret-bearing trust paths that deserve follow-up
- Show the RBAC evidence and practical capability paths that matter for the current foothold
- Expose escalation opportunities and likely next steps instead of leaving you to sort raw cluster data

## Install

Download the right binary for your platform from GitHub Releases and extract it.

## Operator Workflow

Start with the foothold you have, then work outward toward exposure, identity consequence, and control expansion:

```bash
harrierops-kube whoami
harrierops-kube inventory
harrierops-kube exposure
harrierops-kube workloads
harrierops-kube service-accounts
harrierops-kube privesc
```

Typical flow:
- `whoami`: confirm the current foothold, context, namespace, and identity confidence
- `inventory`: determine what kind of cluster slice you actually landed in
- `exposure` and `workloads`: identify which exposed paths and running workloads matter first
- `service-accounts`: follow workload-linked identity and token paths toward the next useful pivot
- `privesc`: surface direct abuse or escalation leads rooted in the current access

If identity-path review matters more than edge-first triage:

```bash
harrierops-kube service-accounts
harrierops-kube chains
```

## Operator Outcome

After one short pass, you understand:
- which foothold matters
- what access is real versus merely visible
- where the best pivot or escalation opportunities are
- which path deserves follow-up first

HarrierOps Kube reduces noise by ranking consequence, not just returning Kubernetes objects.

## Use Cases

- Triage a `kubeconfig`, pod foothold, or service account and determine what Kubernetes control it enables
- Work outward from a workload, token, or exposed service to identify the next usable pivot path
- Validate how far a foothold can realistically go before you spend time on lower-signal cluster detail

## Run It

Start with the current Kubernetes foothold and the strongest visible consequence:

```bash
harrierops-kube whoami
harrierops-kube workloads
```

## Currently Supported Commands

| Section | Commands |
| --- | --- |
| `core` | `inventory` |
| `identity` | `whoami`, `rbac`, `service-accounts`, `permissions`, `privesc` |
| `orchestration` | `chains` |
| `workload` | `workloads` |
| `exposure` | `exposure` |
| `secrets` | `secrets` |

Later depth surface:

- `images`

## Kubernetes Access

HarrierOps Kube expects existing Kubernetes access.
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
The `chains` surface is scaffolded now so the first grouped family contract, claim boundary, and
backing commands are visible before runnable path execution lands. The scaffold now also makes the
planned row shape, path-type guide, and internal proof ladder visible so future chain wording can
stay deterministic before family logic ships.

## CLI Invocation

Shared flags include `--context`, `--namespace`, `--output`, `--outdir`, and `--debug`.
Commands come first, then shared flags or `help`.

```bash
harrierops-kube <command> [global options]
```

Examples:

```bash
harrierops-kube whoami --output json --outdir ./harrierops-kube-demo
harrierops-kube chains workload-identity-pivot --output table
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
