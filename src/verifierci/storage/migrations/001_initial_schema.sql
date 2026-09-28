-- 001_initial_schema.sql: VerifierCI Core Schema per SDD Section 4.1 & 4.4

-- 1. Artifacts
CREATE TABLE artifacts (
  digest TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
  storage_uri TEXT NOT NULL,
  media_type TEXT NOT NULL,
  access_policy TEXT NOT NULL CHECK(access_policy IN ('public','restricted','sealed')),
  retention_until TEXT,
  available INTEGER NOT NULL CHECK(available IN (0,1)),
  created_at TEXT NOT NULL
);

-- 2. Environments
CREATE TABLE environments (
  environment_id TEXT PRIMARY KEY,
  backend TEXT NOT NULL CHECK(backend IN ('fixture','docker')),
  image_digest TEXT,
  platform TEXT NOT NULL,
  recipe_digest TEXT NOT NULL,
  lock_digests TEXT NOT NULL CHECK(json_valid(lock_digests)),
  service_manifests TEXT NOT NULL CHECK(json_valid(service_manifests)),
  resource_policy_hash TEXT NOT NULL,
  runtime_fingerprint TEXT NOT NULL,
  mirror_uris TEXT NOT NULL CHECK(json_valid(mirror_uris)),
  CHECK(backend != 'docker' OR (image_digest IS NOT NULL AND image_digest LIKE '%@sha256:%'))
);

-- 3. Requirements
CREATE TABLE requirements (
  requirement_hash TEXT PRIMARY KEY,
  requirement_id TEXT NOT NULL,
  text TEXT NOT NULL,
  source_kind TEXT NOT NULL CHECK(source_kind IN ('explicit','repository','clarification')),
  evidence_digests TEXT NOT NULL CHECK(json_valid(evidence_digests)),
  source_locator TEXT NOT NULL,
  allowed_variation TEXT NOT NULL
);

-- 4. Contracts
CREATE TABLE contracts (
  contract_hash TEXT PRIMARY KEY,
  task_id TEXT NOT NULL,
  version TEXT NOT NULL,
  requirement_hashes TEXT NOT NULL CHECK(json_valid(requirement_hashes)),
  allowed_variation TEXT NOT NULL,
  unresolved_questions TEXT NOT NULL CHECK(json_valid(unresolved_questions)),
  evidence_digests TEXT NOT NULL CHECK(json_valid(evidence_digests)),
  created_at TEXT NOT NULL,
  UNIQUE(task_id, version)
);

CREATE TABLE contract_requirements (
  contract_hash TEXT NOT NULL REFERENCES contracts(contract_hash),
  requirement_hash TEXT NOT NULL REFERENCES requirements(requirement_hash),
  PRIMARY KEY(contract_hash, requirement_hash)
);

-- 5. Repository Snapshots
CREATE TABLE repository_snapshots (
  snapshot_digest TEXT PRIMARY KEY REFERENCES artifacts(digest),
  repository_id TEXT NOT NULL,
  commit_oid TEXT NOT NULL,
  archive_uri TEXT NOT NULL,
  tree_digest TEXT NOT NULL,
  submodule_digests TEXT NOT NULL CHECK(json_valid(submodule_digests)),
  lock_digests TEXT NOT NULL CHECK(json_valid(lock_digests)),
  licence TEXT NOT NULL,
  created_at TEXT NOT NULL
);

-- 6. Tasks
CREATE TABLE tasks (
  task_key TEXT PRIMARY KEY,
  task_id TEXT NOT NULL,
  version TEXT NOT NULL,
  statement TEXT NOT NULL,
  adapter TEXT NOT NULL,
  contract_hash TEXT NOT NULL REFERENCES contracts(contract_hash),
  snapshot_digest TEXT NOT NULL REFERENCES repository_snapshots(snapshot_digest),
  environment_id TEXT NOT NULL REFERENCES environments(environment_id),
  licence TEXT NOT NULL,
  provenance TEXT NOT NULL,
  eligibility TEXT NOT NULL CHECK(eligibility IN ('eligible','excluded','pending')),
  notes TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(task_id, version)
);

-- 7. Verifier Manifests
CREATE TABLE verifier_manifests (
  manifest_hash TEXT PRIMARY KEY,
  mode TEXT NOT NULL CHECK(mode IN ('compatibility','blackbox')),
  command TEXT NOT NULL CHECK(json_valid(command)),
  build_command TEXT NOT NULL CHECK(json_valid(build_command)),
  expected_collection TEXT NOT NULL CHECK(json_valid(expected_collection)),
  parser_id TEXT NOT NULL,
  report_path TEXT NOT NULL,
  payload_digest TEXT NOT NULL REFERENCES artifacts(digest),
  allowed_edit_paths TEXT NOT NULL CHECK(json_valid(allowed_edit_paths)),
  required_pass_ids TEXT NOT NULL CHECK(json_valid(required_pass_ids)),
  permitted_skips TEXT NOT NULL CHECK(json_valid(permitted_skips)),
  timeout_seconds INTEGER NOT NULL CHECK(timeout_seconds > 0)
);

-- 8. Verifier Versions
CREATE TABLE verifier_versions (
  verifier_key TEXT PRIMARY KEY,
  verifier_id TEXT NOT NULL,
  version TEXT NOT NULL,
  parent_key TEXT REFERENCES verifier_versions(verifier_key),
  manifest_hash TEXT NOT NULL UNIQUE REFERENCES verifier_manifests(manifest_hash),
  payload_digest TEXT NOT NULL REFERENCES artifacts(digest),
  compatible_contract_hashes TEXT NOT NULL CHECK(json_valid(compatible_contract_hashes)),
  created_at TEXT NOT NULL,
  UNIQUE(verifier_id, version)
);

-- 9. Agent Runs
CREATE TABLE agent_runs (
  agent_run_id TEXT PRIMARY KEY,
  agent_version TEXT NOT NULL,
  model_identifier TEXT NOT NULL,
  prompt_digest TEXT NOT NULL,
  config_hash TEXT NOT NULL,
  budget TEXT NOT NULL CHECK(json_valid(budget)),
  patch_digest TEXT NOT NULL REFERENCES artifacts(digest),
  trajectory_digest TEXT REFERENCES artifacts(digest),
  model_usage TEXT CHECK(model_usage IS NULL OR json_valid(model_usage)),
  exposure_record_digest TEXT NOT NULL,
  created_at TEXT NOT NULL
);

-- 10. Patch Cases
CREATE TABLE patch_cases (
  case_id TEXT PRIMARY KEY,
  task_key TEXT NOT NULL REFERENCES tasks(task_key),
  diff_digest TEXT NOT NULL REFERENCES artifacts(digest),
  base_snapshot_digest TEXT NOT NULL REFERENCES repository_snapshots(snapshot_digest),
  source TEXT NOT NULL CHECK(source IN ('human','agent','mutation','reference','noop')),
  source_run_id TEXT REFERENCES agent_runs(agent_run_id),
  parent_case_ids TEXT NOT NULL CHECK(json_valid(parent_case_ids)),
  family_id TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('challenge','reference','noop')),
  provenance_digest TEXT NOT NULL,
  licence TEXT NOT NULL,
  created_at TEXT NOT NULL
);

-- 11. Witnesses
CREATE TABLE witnesses (
  witness_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES patch_cases(case_id),
  contract_hash TEXT NOT NULL REFERENCES contracts(contract_hash),
  requirement_hashes TEXT NOT NULL CHECK(json_valid(requirement_hashes)),
  input_digest TEXT NOT NULL REFERENCES artifacts(digest),
  expected_digest TEXT NOT NULL REFERENCES artifacts(digest),
  observed_digest TEXT NOT NULL REFERENCES artifacts(digest),
  reproducer_command TEXT NOT NULL CHECK(json_valid(reproducer_command)),
  environment_id TEXT NOT NULL REFERENCES environments(environment_id),
  reviewed_by TEXT NOT NULL CHECK(json_valid(reviewed_by)),
  reproduced_at TEXT
);

-- 12. Adjudications
CREATE TABLE adjudications (
  adjudication_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES patch_cases(case_id),
  contract_hash TEXT NOT NULL REFERENCES contracts(contract_hash),
  version INTEGER NOT NULL CHECK(version > 0),
  label TEXT NOT NULL CHECK(label IN ('valid','invalid','unresolved')),
  review_status TEXT NOT NULL CHECK(review_status IN ('provisional','independent','disputed')),
  votes TEXT NOT NULL CHECK(json_valid(votes)),
  rationale TEXT NOT NULL,
  requirement_hashes TEXT NOT NULL CHECK(json_valid(requirement_hashes)),
  witness_ids TEXT NOT NULL CHECK(json_valid(witness_ids)),
  uncertainty TEXT NOT NULL,
  supersedes_id TEXT REFERENCES adjudications(adjudication_id),
  created_at TEXT NOT NULL,
  UNIQUE(case_id, contract_hash, version),
  CHECK(review_status != 'disputed' OR label = 'unresolved')
);

CREATE TABLE adjudication_witnesses (
  adjudication_id TEXT NOT NULL REFERENCES adjudications(adjudication_id),
  witness_id TEXT NOT NULL REFERENCES witnesses(witness_id),
  PRIMARY KEY(adjudication_id, witness_id)
);

-- 13. Patch Panels
CREATE TABLE patch_panels (
  panel_key TEXT PRIMARY KEY,
  panel_id TEXT NOT NULL,
  version TEXT NOT NULL,
  split TEXT NOT NULL CHECK(split IN ('development','assessment','train')),
  membership_digest TEXT NOT NULL,
  sampling_policy TEXT NOT NULL,
  exposed_at TEXT,
  development_used_at TEXT,
  sealed_at TEXT,
  retired_at TEXT,
  parent_panel_key TEXT REFERENCES patch_panels(panel_key),
  UNIQUE(panel_id, version)
);

CREATE TABLE panel_memberships (
  panel_key TEXT NOT NULL REFERENCES patch_panels(panel_key),
  case_id TEXT NOT NULL REFERENCES patch_cases(case_id),
  adjudication_id TEXT NOT NULL REFERENCES adjudications(adjudication_id),
  ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
  expected_control_outcomes TEXT NOT NULL CHECK(json_valid(expected_control_outcomes)),
  PRIMARY KEY(panel_key, case_id),
  UNIQUE(panel_key, ordinal)
);

CREATE TABLE split_reservations (
  reservation_key TEXT PRIMARY KEY,
  assessment_panel_key TEXT NOT NULL REFERENCES patch_panels(panel_key),
  reserved_at TEXT NOT NULL
);

CREATE TABLE exposure_events (
  event_id TEXT PRIMARY KEY,
  panel_key TEXT NOT NULL REFERENCES patch_panels(panel_key),
  case_id TEXT REFERENCES patch_cases(case_id),
  audience TEXT NOT NULL,
  purpose TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  evidence_digest TEXT NOT NULL
);

-- 14. Audit Manifests & Audit Runs
CREATE TABLE audit_manifests (
  manifest_hash TEXT PRIMARY KEY,
  run_id TEXT NOT NULL UNIQUE,
  benchmark_version TEXT NOT NULL,
  task_pins TEXT NOT NULL CHECK(json_valid(task_pins)),
  panel_key TEXT NOT NULL REFERENCES patch_panels(panel_key),
  adjudication_version TEXT NOT NULL,
  evaluation_harness_version TEXT NOT NULL,
  config_hash TEXT NOT NULL,
  policy_hash TEXT NOT NULL,
  analysis_plan_hash TEXT,
  timestamp TEXT NOT NULL,
  host_fingerprint TEXT NOT NULL,
  seed INTEGER,
  agent_version TEXT,
  model_identifier TEXT,
  max_repetitions INTEGER NOT NULL CHECK(max_repetitions >= 1),
  max_attempts_per_job INTEGER NOT NULL CHECK(max_attempts_per_job BETWEEN 1 AND 3),
  timeout_seconds INTEGER NOT NULL CHECK(timeout_seconds > 0),
  resource_policy TEXT NOT NULL,
  expansion_digest TEXT NOT NULL,
  parent_run_id TEXT
);

CREATE TABLE audit_runs (
  run_id TEXT PRIMARY KEY,
  manifest_hash TEXT NOT NULL UNIQUE REFERENCES audit_manifests(manifest_hash),
  state TEXT NOT NULL CHECK(state IN ('PLANNED','RUNNING','COMPLETE','CANCELLED','FAILED')),
  cancel_requested INTEGER NOT NULL CHECK(cancel_requested IN (0,1)),
  created_at TEXT NOT NULL,
  finished_at TEXT,
  diagnostic_code TEXT
);

-- 15. Jobs & Evaluation Attempts
CREATE TABLE jobs (
  job_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES audit_runs(run_id),
  task_key TEXT NOT NULL REFERENCES tasks(task_key),
  case_id TEXT NOT NULL REFERENCES patch_cases(case_id),
  verifier_key TEXT NOT NULL REFERENCES verifier_versions(verifier_key),
  repetition INTEGER NOT NULL CHECK(repetition >= 0),
  state TEXT NOT NULL CHECK(state IN ('PENDING','CLAIMED','RUNNING','DONE','FAILED','ABANDONED')),
  fence INTEGER NOT NULL DEFAULT 0 CHECK(fence >= 0),
  attempt_id TEXT,
  lease_token TEXT,
  worker_id TEXT,
  lease_expires_ms INTEGER,
  attempts_started INTEGER NOT NULL DEFAULT 0 CHECK(attempts_started >= 0),
  selected_attempt_id TEXT REFERENCES evaluation_attempts(attempt_id),
  terminal_reason TEXT,
  UNIQUE(run_id, task_key, case_id, verifier_key, repetition)
);

CREATE TABLE evaluation_attempts (
  attempt_id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL REFERENCES jobs(job_id),
  fence INTEGER NOT NULL CHECK(fence > 0),
  outcome TEXT CHECK(outcome IS NULL OR outcome IN ('accept','reject','invalid_evaluation','error')),
  evaluation_validity TEXT NOT NULL CHECK(evaluation_validity IN ('pending','valid','invalid')),
  error_code TEXT,
  disposition TEXT NOT NULL CHECK(disposition IN ('active','authoritative','stale','abandoned')),
  started_at TEXT NOT NULL,
  finished_at TEXT,
  exit_code INTEGER,
  stdout_hash TEXT REFERENCES artifacts(digest),
  stderr_hash TEXT REFERENCES artifacts(digest),
  report_digest TEXT REFERENCES artifacts(digest),
  test_collection TEXT NOT NULL CHECK(json_valid(test_collection)),
  tests_passed INTEGER CHECK(tests_passed >= 0),
  tests_failed INTEGER CHECK(tests_failed >= 0),
  resources TEXT NOT NULL CHECK(json_valid(resources)),
  artifact_digests TEXT NOT NULL CHECK(json_valid(artifact_digests)),
  capture_truncated INTEGER NOT NULL CHECK(capture_truncated IN (0,1)),
  CHECK(
    (evaluation_validity='pending' AND outcome IS NULL AND disposition='active')
    OR (evaluation_validity='valid' AND outcome IS NOT NULL AND outcome IN ('accept','reject'))
    OR (evaluation_validity='invalid' AND (
      (outcome IS NOT NULL AND outcome IN ('invalid_evaluation','error'))
      OR (outcome IS NULL AND disposition IN ('abandoned','stale'))
    ))
  )
);

-- 16. Results & Decisions
CREATE TABLE acceptance_matrices (
  matrix_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES audit_runs(run_id),
  reducer_version TEXT NOT NULL,
  cells TEXT NOT NULL CHECK(json_valid(cells)),
  complete INTEGER NOT NULL CHECK(complete IN (0,1)),
  source_attempts_digest TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(run_id, reducer_version, source_attempts_digest)
);

CREATE TABLE metric_results (
  metric_id TEXT PRIMARY KEY,
  matrix_id TEXT NOT NULL REFERENCES acceptance_matrices(matrix_id),
  name TEXT NOT NULL,
  definition_version TEXT NOT NULL,
  verifier_key TEXT,
  cohort TEXT NOT NULL CHECK(cohort IN ('challenge','controls','all')),
  value REAL,
  numerator INTEGER CHECK(numerator >= 0),
  denominator INTEGER CHECK(denominator >= 0),
  task_terms TEXT NOT NULL CHECK(json_valid(task_terms)),
  ci_low REAL,
  ci_high REAL,
  analysis_plan_hash TEXT,
  coverage TEXT NOT NULL CHECK(json_valid(coverage)),
  CHECK(numerator IS NULL OR denominator IS NULL OR numerator <= denominator)
);

CREATE TABLE gate_decisions (
  decision_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES audit_runs(run_id),
  matrix_id TEXT REFERENCES acceptance_matrices(matrix_id),
  policy_hash TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('PASSED','BLOCKED','INCONCLUSIVE','INSUFFICIENT_EVIDENCE','INFRASTRUCTURE_ERROR')),
  exit_code INTEGER NOT NULL CHECK(exit_code BETWEEN 0 AND 3),
  reasons TEXT NOT NULL CHECK(json_valid(reasons)),
  evidence TEXT NOT NULL CHECK(json_valid(evidence)),
  reliability_flags TEXT NOT NULL CHECK(json_valid(reliability_flags)),
  created_at TEXT NOT NULL,
  CHECK((state='PASSED' AND exit_code=0) OR (state='BLOCKED' AND exit_code=1) OR (state IN ('INCONCLUSIVE','INSUFFICIENT_EVIDENCE') AND exit_code=2) OR (state='INFRASTRUCTURE_ERROR' AND exit_code=3))
);

-- 17. Auxiliary Phase Tables
CREATE TABLE analysis_plans (
  plan_hash TEXT PRIMARY KEY,
  registered_at TEXT NOT NULL,
  cohort_digest TEXT NOT NULL,
  verifier_candidates TEXT NOT NULL CHECK(json_valid(verifier_candidates)),
  primary_outcomes TEXT NOT NULL CHECK(json_valid(primary_outcomes)),
  min_iar_improvement REAL NOT NULL,
  vrr_noninferiority_margin REAL NOT NULL,
  alpha REAL NOT NULL CHECK(alpha > 0 AND alpha < 1),
  bootstrap_draws INTEGER NOT NULL CHECK(bootstrap_draws > 0),
  seed INTEGER NOT NULL,
  budgets TEXT NOT NULL CHECK(json_valid(budgets)),
  exclusions TEXT NOT NULL CHECK(json_valid(exclusions)),
  secondary_hypotheses TEXT NOT NULL CHECK(json_valid(secondary_hypotheses)),
  stopping_rule TEXT NOT NULL
);

CREATE TABLE benchmark_versions (
  benchmark_key TEXT PRIMARY KEY,
  task_keys TEXT NOT NULL CHECK(json_valid(task_keys)),
  panel_keys TEXT NOT NULL CHECK(json_valid(panel_keys)),
  analysis_plan_hash TEXT REFERENCES analysis_plans(plan_hash),
  release_digest TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL
);

CREATE TABLE telemetry_events (
  event_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES audit_runs(run_id),
  attempt_id TEXT NOT NULL REFERENCES evaluation_attempts(attempt_id),
  occurred_at TEXT NOT NULL,
  payload TEXT NOT NULL CHECK(json_valid(payload))
);

CREATE TABLE worker_requests (
  request_id TEXT PRIMARY KEY,
  operation TEXT NOT NULL,
  request_digest TEXT NOT NULL,
  response_json TEXT NOT NULL CHECK(json_valid(response_json)),
  completed_at TEXT NOT NULL
);

-- 18. Mandatory Indexes
CREATE INDEX task_eligibility_idx ON tasks(eligibility, task_id);
CREATE INDEX snapshot_repo_idx ON repository_snapshots(repository_id, commit_oid);
CREATE INDEX case_task_family_idx ON patch_cases(task_key, family_id);
CREATE INDEX adjudication_case_idx ON adjudications(case_id, contract_hash, version);
CREATE INDEX panel_split_idx ON patch_panels(split, sealed_at);
CREATE INDEX membership_case_idx ON panel_memberships(case_id);
CREATE INDEX attempt_job_idx ON evaluation_attempts(job_id, fence);
CREATE UNIQUE INDEX attempt_authority_idx ON evaluation_attempts(job_id)
  WHERE disposition='authoritative';
CREATE INDEX matrix_run_idx ON acceptance_matrices(run_id);
CREATE INDEX metric_matrix_idx ON metric_results(matrix_id, name);
CREATE INDEX gate_run_idx ON gate_decisions(run_id, created_at);
CREATE INDEX artifact_retention_idx ON artifacts(retention_until, available);
CREATE INDEX jobs_claim_idx ON jobs(state, run_id, job_id);
CREATE INDEX jobs_lease_idx ON jobs(lease_expires_ms) WHERE state IN ('CLAIMED','RUNNING');

-- 19. Split Reservation Triggers
CREATE TRIGGER reserve_no_update BEFORE UPDATE ON split_reservations
BEGIN SELECT RAISE(ABORT, 'assessment reservation is permanent'); END;

CREATE TRIGGER reserve_no_delete BEFORE DELETE ON split_reservations
BEGIN SELECT RAISE(ABORT, 'assessment reservation is permanent'); END;

CREATE TRIGGER guard_development_membership BEFORE INSERT ON panel_memberships
WHEN (SELECT split FROM patch_panels WHERE panel_key=NEW.panel_key)
     IN ('development','train')
AND EXISTS (
  SELECT 1 FROM patch_cases c JOIN split_reservations r
    ON r.reservation_key = 'family:' || c.family_id
    OR r.reservation_key = 'case:' || c.task_key || ':' || c.diff_digest
  WHERE c.case_id=NEW.case_id
)
BEGIN SELECT RAISE(ABORT, 'assessment case or family is reserved'); END;

-- 20. Generated Immutable Content Row Triggers
-- Tasks
CREATE TRIGGER tasks_no_update BEFORE UPDATE ON tasks
BEGIN SELECT RAISE(ABORT, 'immutable entity tasks cannot be updated'); END;
CREATE TRIGGER tasks_no_delete BEFORE DELETE ON tasks
BEGIN SELECT RAISE(ABORT, 'immutable entity tasks cannot be deleted'); END;

-- Requirements
CREATE TRIGGER requirements_no_update BEFORE UPDATE ON requirements
BEGIN SELECT RAISE(ABORT, 'immutable entity requirements cannot be updated'); END;
CREATE TRIGGER requirements_no_delete BEFORE DELETE ON requirements
BEGIN SELECT RAISE(ABORT, 'immutable entity requirements cannot be deleted'); END;

-- Contracts
CREATE TRIGGER contracts_no_update BEFORE UPDATE ON contracts
BEGIN SELECT RAISE(ABORT, 'immutable entity contracts cannot be updated'); END;
CREATE TRIGGER contracts_no_delete BEFORE DELETE ON contracts
BEGIN SELECT RAISE(ABORT, 'immutable entity contracts cannot be deleted'); END;

-- Contract Requirements
CREATE TRIGGER contract_requirements_no_update BEFORE UPDATE ON contract_requirements
BEGIN SELECT RAISE(ABORT, 'immutable entity contract_requirements cannot be updated'); END;
CREATE TRIGGER contract_requirements_no_delete BEFORE DELETE ON contract_requirements
BEGIN SELECT RAISE(ABORT, 'immutable entity contract_requirements cannot be deleted'); END;

-- Repository Snapshots
CREATE TRIGGER repository_snapshots_no_update BEFORE UPDATE ON repository_snapshots
BEGIN SELECT RAISE(ABORT, 'immutable entity repository_snapshots cannot be updated'); END;
CREATE TRIGGER repository_snapshots_no_delete BEFORE DELETE ON repository_snapshots
BEGIN SELECT RAISE(ABORT, 'immutable entity repository_snapshots cannot be deleted'); END;

-- Environments
CREATE TRIGGER environments_no_update BEFORE UPDATE ON environments
BEGIN SELECT RAISE(ABORT, 'immutable entity environments cannot be updated'); END;
CREATE TRIGGER environments_no_delete BEFORE DELETE ON environments
BEGIN SELECT RAISE(ABORT, 'immutable entity environments cannot be deleted'); END;

-- Verifier Manifests
CREATE TRIGGER verifier_manifests_no_update BEFORE UPDATE ON verifier_manifests
BEGIN SELECT RAISE(ABORT, 'immutable entity verifier_manifests cannot be updated'); END;
CREATE TRIGGER verifier_manifests_no_delete BEFORE DELETE ON verifier_manifests
BEGIN SELECT RAISE(ABORT, 'immutable entity verifier_manifests cannot be deleted'); END;

-- Verifier Versions
CREATE TRIGGER verifier_versions_no_update BEFORE UPDATE ON verifier_versions
BEGIN SELECT RAISE(ABORT, 'immutable entity verifier_versions cannot be updated'); END;
CREATE TRIGGER verifier_versions_no_delete BEFORE DELETE ON verifier_versions
BEGIN SELECT RAISE(ABORT, 'immutable entity verifier_versions cannot be deleted'); END;

-- Agent Runs
CREATE TRIGGER agent_runs_no_update BEFORE UPDATE ON agent_runs
BEGIN SELECT RAISE(ABORT, 'immutable entity agent_runs cannot be updated'); END;
CREATE TRIGGER agent_runs_no_delete BEFORE DELETE ON agent_runs
BEGIN SELECT RAISE(ABORT, 'immutable entity agent_runs cannot be deleted'); END;

-- Patch Cases
CREATE TRIGGER patch_cases_no_update BEFORE UPDATE ON patch_cases
BEGIN SELECT RAISE(ABORT, 'immutable entity patch_cases cannot be updated'); END;
CREATE TRIGGER patch_cases_no_delete BEFORE DELETE ON patch_cases
BEGIN SELECT RAISE(ABORT, 'immutable entity patch_cases cannot be deleted'); END;

-- Witnesses
CREATE TRIGGER witnesses_no_update BEFORE UPDATE ON witnesses
BEGIN SELECT RAISE(ABORT, 'immutable entity witnesses cannot be updated'); END;
CREATE TRIGGER witnesses_no_delete BEFORE DELETE ON witnesses
BEGIN SELECT RAISE(ABORT, 'immutable entity witnesses cannot be deleted'); END;

-- Adjudications
CREATE TRIGGER adjudications_no_update BEFORE UPDATE ON adjudications
BEGIN SELECT RAISE(ABORT, 'immutable entity adjudications cannot be updated'); END;
CREATE TRIGGER adjudications_no_delete BEFORE DELETE ON adjudications
BEGIN SELECT RAISE(ABORT, 'immutable entity adjudications cannot be deleted'); END;

-- Adjudication Witnesses
CREATE TRIGGER adjudication_witnesses_no_update BEFORE UPDATE ON adjudication_witnesses
BEGIN SELECT RAISE(ABORT, 'immutable entity adjudication_witnesses cannot be updated'); END;
CREATE TRIGGER adjudication_witnesses_no_delete BEFORE DELETE ON adjudication_witnesses
BEGIN SELECT RAISE(ABORT, 'immutable entity adjudication_witnesses cannot be deleted'); END;

-- Panel Memberships
CREATE TRIGGER panel_memberships_no_update BEFORE UPDATE ON panel_memberships
BEGIN SELECT RAISE(ABORT, 'immutable entity panel_memberships cannot be updated'); END;
CREATE TRIGGER panel_memberships_no_delete BEFORE DELETE ON panel_memberships
BEGIN SELECT RAISE(ABORT, 'immutable entity panel_memberships cannot be deleted'); END;

-- Audit Manifests
CREATE TRIGGER audit_manifests_no_update BEFORE UPDATE ON audit_manifests
BEGIN SELECT RAISE(ABORT, 'immutable entity audit_manifests cannot be updated'); END;
CREATE TRIGGER audit_manifests_no_delete BEFORE DELETE ON audit_manifests
BEGIN SELECT RAISE(ABORT, 'immutable entity audit_manifests cannot be deleted'); END;

-- Acceptance Matrices
CREATE TRIGGER acceptance_matrices_no_update BEFORE UPDATE ON acceptance_matrices
BEGIN SELECT RAISE(ABORT, 'immutable entity acceptance_matrices cannot be updated'); END;
CREATE TRIGGER acceptance_matrices_no_delete BEFORE DELETE ON acceptance_matrices
BEGIN SELECT RAISE(ABORT, 'immutable entity acceptance_matrices cannot be deleted'); END;

-- Metric Results
CREATE TRIGGER metric_results_no_update BEFORE UPDATE ON metric_results
BEGIN SELECT RAISE(ABORT, 'immutable entity metric_results cannot be updated'); END;
CREATE TRIGGER metric_results_no_delete BEFORE DELETE ON metric_results
BEGIN SELECT RAISE(ABORT, 'immutable entity metric_results cannot be deleted'); END;

-- Gate Decisions
CREATE TRIGGER gate_decisions_no_update BEFORE UPDATE ON gate_decisions
BEGIN SELECT RAISE(ABORT, 'immutable entity gate_decisions cannot be updated'); END;
CREATE TRIGGER gate_decisions_no_delete BEFORE DELETE ON gate_decisions
BEGIN SELECT RAISE(ABORT, 'immutable entity gate_decisions cannot be deleted'); END;

-- Artifacts: digest, kind, size_bytes, media_type, created_at, storage_uri, access_policy, retention_until are immutable.
CREATE TRIGGER artifacts_no_core_update BEFORE UPDATE OF digest, kind, size_bytes, media_type, created_at, storage_uri, access_policy, retention_until ON artifacts
BEGIN SELECT RAISE(ABORT, 'immutable artifact core metadata cannot be updated'); END;
CREATE TRIGGER artifacts_no_delete BEFORE DELETE ON artifacts
WHEN OLD.access_policy = 'sealed'
BEGIN SELECT RAISE(ABORT, 'sealed artifacts cannot be deleted'); END;

-- Evaluation Attempts: authoritative attempts cannot be modified or deleted.
CREATE TRIGGER attempts_authoritative_no_update BEFORE UPDATE ON evaluation_attempts
WHEN OLD.disposition = 'authoritative'
BEGIN SELECT RAISE(ABORT, 'authoritative evaluation attempt cannot be updated'); END;
CREATE TRIGGER attempts_authoritative_no_delete BEFORE DELETE ON evaluation_attempts
WHEN OLD.disposition = 'authoritative'
BEGIN SELECT RAISE(ABORT, 'authoritative evaluation attempt cannot be deleted'); END;

