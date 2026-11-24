# Changelog

## Unreleased (Phase 1 — In Progress)

### Added
- Immutable typed domain models (`models/task.py`, `models/panel.py`, `models/verifier.py`, `models/result.py`, `models/protocol.py`), canonical JSON hashing (`canonical_bytes`), and typed error hierarchy (`errors.py`) with 0/1/2/3 CLI exit mapping.
- SQLite storage engine (`storage/db.py`), WAL/FK/recursive-trigger configuration, schema and immutability-trigger migrations (`001_initial_schema.sql`, `002_immutability_triggers.sql`), and content-addressed `ArtifactStore` (`storage/artifacts.py`).
- Lease-fenced SQLite job queue (`execution/jobs.py`) supporting atomic `claim`, `heartbeat`, `complete`, `reap_expired`, and `request_cancel`.
- `TaskAdapter` protocol and hardened `LocalAdapter` (`adapters/base.py`, `adapters/local.py`) enforcing YAML size/depth/alias/symlink/traversal bounds and requirement-file deduplication.
- Deterministic audit planner and job expander (`execution/planner.py`) with policy timeout capping and job-count ceilings.
- Isolated attempt workspace preparation and subprocess supervisor (`execution/sandbox.py`), single-attempt lease-fenced `Worker` (`execution/worker.py`), normative classification precedence (`execution/outcomes.py`), and `PytestReportParser` (`evaluators/pytest_report.py`).
- Phase 1 acceptance matrix reducer (`execution/matrix.py`) with fence-selected authoritative attempts, SDD §8.4 repetition aggregation, and refusal of matrix finalization when planned jobs remain pending.
- Atomic static JSON report renderer (`reports/render.py`) serializing `AuditResult` envelopes with credential-sanitized artifact URIs (`fsync` + atomic rename) and matching JSON schema (`schemas/audit-result.schema.json`).
- Panel validation registry (`panels/registry.py`) supporting schema, split, lineage, review-status, and artifact verification.
- Click CLI entrypoint (`cli.py`) and orchestration service (`execution/service.py`) providing `--db`, `--artifact-dir`, `--config`, `--json`, `task import`, `panel validate`, `audit` group, and strict 0/1/2/3 exit code mapping.

## 0.1.0 - 2026-09-09

### Added
- Initial repository skeleton and production-oriented structure.
- CLI entrypoint and minimal package models.
- Adapter/execution/evaluator module layout.
- Schema and dataset directory scaffolds.
- Test foundation, Makefile command set, and CI workflow stubs.
