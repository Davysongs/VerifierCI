# VerifierCI

VerifierCI is a production-oriented foundation for auditing coding-agent verifiers through versioned contracts, reproducible execution, and two-sided acceptance matrices.

At the current stage (**Phase 1: Minimal Vertical Slice — in progress through PR 1.4 Unit 3**), the repository implements the core domain model, immutable SQLite storage and content-addressed artifact engine, fenced job queue, local task adapter, deterministic planner, isolated fixture worker, outcome parser, Phase 1 acceptance matrix reducer, static atomic JSON reporter, and Click CLI commands (`task import`, `panel validate`, `audit`).

## Current Architecture

- `src/verifierci/models/`: Immutable `@dataclass(frozen=True, slots=True)` domain entities (`task.py`, `panel.py`, `verifier.py`, `result.py`, `protocol.py`), canonical JSON hashing (`canonical_bytes`), and validation invariants.
- `src/verifierci/errors.py`: Typed diagnostic hierarchy (`ProtectionError`, `ValidationError`, `IdentityConflict`, `InfrastructureError`, `LeaseLost`) and canonical CLI exit categories (`0`/`1`/`2`/`3`).
- `src/verifierci/storage/`: SQLite storage engine (`db.py`) with WAL mode, foreign keys, recursive triggers, and immutability migrations (`001_initial_schema.sql`, `002_immutability_triggers.sql`), plus content-addressed `ArtifactStore` (`artifacts.py`).
- `src/verifierci/adapters/`: `TaskAdapter` protocol (`base.py`) and `LocalAdapter` (`local.py`) with YAML size, nesting-depth, alias, symlink, and traversal defenses.
- `src/verifierci/execution/`:
  - `planner.py`: Deterministic manifest builder and job expansion (`AuditManifest`, `Job`).
  - `jobs.py`: Lease-fenced SQLite job queue (`claim`, `heartbeat`, `complete`, `reap_expired`, `request_cancel`).
  - `sandbox.py`: Fresh `0700` attempt workspaces, isolated Git diff application, monotonic deadlines, capped stream draining, and non-redirectable `out_dir` boundary checks.
  - `worker.py`: Single-attempt execution worker with heartbeat renewal and stale-evidence quarantine on lease loss.
  - `outcomes.py`: Normative classification precedence hierarchy (infrastructure error -> patch/build error -> timeout/cancellation/limits -> report validation -> accept/reject).
  - `matrix.py`: Phase 1 acceptance matrix reducer (`aggregate_cell`, `build_matrix`, `AcceptanceMatrixBuilder`) with fenced attempt selection, repetition aggregation (`accept`, `reject`, `flaky`, `invalid_evaluation`, `error`), and pending-job finalization guards.
- `src/verifierci/evaluators/`: `PytestReportParser` (`pytest_report.py`) and compatibility evaluator stubs (`compatibility.py`).
- `src/verifierci/metrics/rates.py`: Basic IAR/VRR helper functions (full Phase 2 challenge-panel scoring and Phase 8 uncertainty intervals upcoming).
- `src/verifierci/reports/render.py`: Atomic static JSON reporter (`render_json`, `render_summary`, `ReportRenderer`) serializing `AuditResult` envelopes with credential-sanitized artifact URIs (`fsync` + atomic rename); HTML rendering arrives in Phase 3.
- `src/verifierci/cli.py`: Click CLI entry point (`verifierci`) supporting global options (`--db`, `--artifact-dir`, `--config`, `--json`, `--version`, `--help`), `task import`, `panel validate`, `audit` group, and canonical `0`/`1`/`2`/`3` exit category mapping.
- `src/verifierci/execution/service.py`: Phase 1 orchestration connecting `LocalAdapter`, `PanelRegistry`, `planner`, SQLite persistence, `Worker`, `matrix`, and `reports.render`.
- `schemas/` & `examples/retry-contract/`: Versioned JSON schemas and the synthetic 5-case, 2-verifier `retry-contract` fixture (SDD §1.3).

## Local setup

1. Set up Python `>=3.11,<3.13` (for example via `uv` or `.venv`).
2. Install development dependencies:
   - `make install`
3. Run checks and tests:
   - `make lint`
   - `make test-unit`
   - `make test-integration`

## Development commands

- `make install` — installs editable package + dev/test dependencies.
- `make lint` — runs Python bytecode compilation checks across `src` and `tests` (also run `ruff check .`, `ruff format --check .`, and `PYTHONPATH=src mypy src tests`).
- `make test-unit` — runs unit tests under `tests/unit`.
- `make test-integration` — runs integration tests under `tests/integration`.
- `make test-property` / `make test-security` — prepared test targets for Phase 2 / Phase 4 layers.
- `make test` — runs unit tests.

## Implementation status

- ✅ **PR 1.1:** Core domain models, canonical JSON hashing, typed error codes, and initial registry scaffolds
- ✅ **PR 1.2:** SQLite storage engine, immutability triggers, content-addressed `ArtifactStore`, and fenced job queue
- ✅ **PR 1.3:** `LocalAdapter`, deterministic audit planner, isolated sandbox supervisor, outcome/pytest-report parsers, and single-attempt `Worker`
- ✅ **PR 1.4 (Units 1–3):** Phase 1 acceptance matrix reducer (`verifierci.execution.matrix`), atomic static JSON reporter (`verifierci.reports.render`), and Click CLI (`verifierci.cli` with `task import`, `panel validate`, `audit`)
- 🟡 **PR 1.4 (Remaining):** End-to-end `examples/retry-contract` 30-job vertical slice fixture & verification
- ⏳ **Phases 2–8:** Full scoring/metrics & property tests (Phase 2), CI gate & HTML reporter (Phase 3), Docker sandbox (Phase 4), external adapters & panel/statistical workflows (Phases 5–8)
