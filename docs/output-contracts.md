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
