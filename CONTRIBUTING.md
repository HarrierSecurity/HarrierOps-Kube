# Contributing

## Local Setup

HarrierOps Kube is a Go-first repo with fixture-backed command tests right now.

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

## Shared Family Baseline

Shared family rules for wording, output truthfulness, CLI/help shape, support types, claim-strength
handling, and artifact conventions are maintained outside this repo by workspace maintainers.

Do not turn this repo into a second source of truth for family-wide rules.
If HarrierOps Kube needs to differ from the shared family baseline, make that exception explicit in
the shared family documentation instead of leaving the difference implied only in README prose, help
text, or tests.

## Documentation Boundary

- Keep operator-facing documentation in the repo.
- Keep package, build, install, schema, and release metadata in the repo when the repo needs it to
  build, validate, publish, or package correctly.
- Move maintainer-only reference notes that operators do not need into the workspace-level
  reference area instead of keeping them under the repo tree.
- Do not commit repo-local reference docs that restate family rules, contract notes, or planning
  notes when those can live in the reference area outside the repo.

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
