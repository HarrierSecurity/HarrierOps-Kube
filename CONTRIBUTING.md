# Contributing

## Local Setup

Harrier Ops Kube is a Go-first repo with fixture-backed command tests right now.

```bash
bash scripts/setup_local_guardrails.sh
```

If you want local secret scanning before push, install `gitleaks` separately. The pre-push hook will
run it when available and will otherwise leave that check to CI.

## Default Validation

```bash
gofmt -w ./cmd ./internal
go test ./...
```

## Test Shape

- Smoke tests: CLI command execution using fixtures
- Contract tests: schema and golden-output regression coverage
- Provider tests: normalized fixture loading and override behavior

## Semantics And Contracts

- Keep command boundaries stable.
- Keep command logic on normalized models under `internal/model/`.
- Keep JSON output deterministic and schema-compatible.
- Update schemas and golden outputs in the same change when a command contract moves.

## Lightweight Guardrails

- Create a short-lived branch per change, such as `feat/...`, `fix/...`, or `docs/...`.
- Open a PR into `main` even when working solo.
- Keep PRs small and single-purpose.
- Merge only after CI is green.
- If command output contracts change, update schema snapshots and golden fixtures in the same PR.
- Local pre-push hook blocks `codex` branch names, blocks direct pushes to `main`, checks formatting, runs tests, and runs `gitleaks` when installed locally.
- CI blocks Codex-branded PR titles and runs `gitleaks` plus the Go validation suite.
- Temporary bypass for emergency push: `HARRIEROPS_KUBE_ALLOW_MAIN_PUSH=1 git push`
