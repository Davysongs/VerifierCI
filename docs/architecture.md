# Architecture

High-level architecture for VerifierCI (currently at **Phase 1: Minimal Vertical Slice Complete**; see `build/VerifierCI-Software-Design-Document.md` §2–§5 for full target specifications).

## Implemented Phase 1 Pipeline

1. **Task Import (`verifierci.adapters`):** `LocalAdapter` parses native local task, contract, environment, verifier, and requirement YAML manifests into a typed `ImportBundle`, enforcing size, nesting depth, alias, symlink, and traversal bounds.
2. **Audit Planning (`verifierci.execution.planner`):** `plan_audit` and `expand` deterministically cross-product pinned task cases, baseline/candidate verifiers, and planned repetitions into an immutable `AuditManifest` and `Job` sequence under policy limits.
3. **Storage & Fenced Queue (`verifierci.storage`, `verifierci.execution.jobs`):** SQLite persistence with immutability triggers (`001_initial_schema.sql`, `002_immutability_triggers.sql`), content-addressed `ArtifactStore`, and atomic lease-fenced `claim`/`heartbeat`/`complete`/`reap_expired`/`request_cancel` transitions.
4. **Isolated Execution & Classification (`verifierci.execution.sandbox`, `worker`, `outcomes`, `verifierci.evaluators.pytest_report`):** `Worker` prepares fresh `0700` attempt workspaces, applies diffs via isolated Git, executes fixture commands under monotonic deadlines and capped stream capture, parses structured reports, and commits authoritative attempts through live lease fences (or quarantines stale evidence on lease expiry).
5. **Acceptance Matrix Reducer (`verifierci.execution.matrix`):** `build_matrix` and `aggregate_cell` select one fence-authoritative attempt per job, aggregate planned repetitions per SDD §8.4, and refuse finalization when planned jobs remain pending unless explicitly requested as provisional.
6. **Static JSON Reporter (`verifierci.reports.render`):** `render_json` and `ReportRenderer` serialize `AuditResult` envelopes with credential-sanitized artifact URIs via temporary file, `fsync`, and atomic `os.replace`.
7. **Click CLI & Orchestration (`verifierci.cli`, `verifierci.execution.service`, `verifierci.panels.registry`, `verifierci.snapshots.registry`):** Implements global `--db`/`--artifact-dir`/`--config`/`--json` flags, `task import`, `panel validate`, `audit` group (`invoke_without_command=True`), trusted fixture digest verification (`SnapshotRegistry`), and strict `0`/`1`/`2`/`3` exit category mapping.
8. **Canonical Vertical Slice (`examples/retry-contract/`, `datasets/`, `tests/e2e/`):** 1-task, 5-case, 2-verifier, 3-repetition (30-job) fixture suite with weak `v1` and over-specific `v2` verifiers, pinned SHA-256 digests, and synthetic/provisional diagnostic labels.

## Remaining / Upcoming Components

- **PR 1.4 Complete:** `examples/retry-contract` 30-job vertical slice fixture, `make slice`, and end-to-end CLI verification (`tests/e2e/test_cli_slice.py`, `tests/e2e/test_phase1_vertical_slice.py`).
- **Phases 2–8:** Full scoring/metrics & property tests, CI gate & HTML reporter, Docker sandbox, external task adapters, independent adjudication/panel workflows, and statistical analysis.
