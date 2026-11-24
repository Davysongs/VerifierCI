# Architecture

High-level architecture for VerifierCI (currently at Phase 1 through PR 1.4 Unit 2; see `build/VerifierCI-Software-Design-Document.md` §2–§5 for full target specifications).

## Implemented Phase 1 Pipeline

1. **Task Import (`verifierci.adapters`):** `LocalAdapter` parses native local task, contract, environment, verifier, and requirement YAML manifests into a typed `ImportBundle`, enforcing size, nesting depth, alias, symlink, and traversal bounds.
2. **Audit Planning (`verifierci.execution.planner`):** `plan_audit` and `expand` deterministically cross-product pinned task cases, baseline/candidate verifiers, and planned repetitions into an immutable `AuditManifest` and `Job` sequence under policy limits.
3. **Storage & Fenced Queue (`verifierci.storage`, `verifierci.execution.jobs`):** SQLite persistence with immutability triggers (`001_initial_schema.sql`, `002_immutability_triggers.sql`), content-addressed `ArtifactStore`, and atomic lease-fenced `claim`/`heartbeat`/`complete`/`reap_expired`/`request_cancel` transitions.
4. **Isolated Execution & Classification (`verifierci.execution.sandbox`, `worker`, `outcomes`, `verifierci.evaluators.pytest_report`):** `Worker` prepares fresh `0700` attempt workspaces, applies diffs via isolated Git, executes fixture commands under monotonic deadlines and capped stream capture, parses structured reports, and commits authoritative attempts through live lease fences (or quarantines stale evidence on lease expiry).
5. **Acceptance Matrix Reducer (`verifierci.execution.matrix`):** `build_matrix` and `aggregate_cell` select one fence-authoritative attempt per job, aggregate planned repetitions per SDD §8.4, and refuse finalization when planned jobs remain pending unless explicitly requested as provisional.
6. **Static JSON Reporter (`verifierci.reports.render`):** `render_json` and `ReportRenderer` serialize `AuditResult` envelopes with credential-sanitized artifact URIs via temporary file, `fsync`, and atomic `os.replace`.

## Remaining / Upcoming Components

- **PR 1.4 Remaining:** Click CLI commands (`cli.py`) and end-to-end `examples/retry-contract` vertical slice verification.
- **Phases 2–8:** Full scoring/metrics & property tests, CI gate & HTML reporter, Docker sandbox, external task adapters, independent adjudication/panel workflows, and statistical analysis.
