# Output Contracts

Each HarrierOps Kube command output is represented by a versioned contract definition and rendered
into table/JSON/CSV from the same payload.

## Schema Version

- Current: `1.0.0`

## Contract Rules

- JSON output is deterministic with sorted keys in emitted artifacts.
- Table output only renders fields present in the JSON contract.
- Each command schema is stored under `schemas/<command>.schema.json`.
- Fixture snapshots under `testdata/golden/` are regression baselines.

## Current Contract Notes

- `chains` is scaffolded today. Its contract is already versioned and schema-backed even though the
  first grouped family is not runnable yet.
- `rbac` now preserves exact workload-side operator actions under `workload_actions` without
  removing the broader `dangerous_rights` summary.
- `permissions` now preserves the exact workload-side action surface with:
  - `action_verb`
  - `target_group`
  - `target_resources`

These fields let grouped chain work reason about concrete Kubernetes actions such as creating pods
or patching workload controllers without forcing later commands to reverse-engineer broad
`change workloads` summaries.
