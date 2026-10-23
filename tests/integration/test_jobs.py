"""Integration tests for fenced job queue, lease management, and concurrency.

SDD Section 7.1, 7.2, and 9.2:
- Private temporary database roots and disk SQLite databases with WAL mode.
- Concurrency and atomic claim transactions (no double claims or orphaned attempts).
- Lease expiry, reaping (ABANDONED -> PENDING with incremented fence), and retry budget exhaustion.
- Heartbeat verification requiring matching token, worker ID, and fence.
- Monotonic fencing invariant: late results from earlier expired fences cannot overwrite authoritative results.
- Crash between artifact persistence and DB commit.
- Cooperative cancellation idempotency.
"""

from __future__ import annotations

import concurrent.futures
from datetime import UTC, datetime
from pathlib import Path

import pytest

from verifierci.errors import (
    ErrorCode,
    IdentityConflict,
    LeaseLost,
)
from verifierci.execution.jobs import (
    claim,
    complete,
    get_job,
    heartbeat,
    mark_running,
    reap_expired,
    request_cancel,
)
from verifierci.models.protocol import Job, ResourceUsage
from verifierci.models.result import EvaluationAttempt
from verifierci.storage.artifacts import ArtifactStore
from verifierci.storage.db import Database, connect, transaction


def _setup_test_db(db_path: Path, num_jobs: int = 1) -> Database:
    """Initialize disk database with schema and relational entities."""
    db = Database(db_path)
    db.migrate()
    conn = db.connection

    conn.execute(
        """
        INSERT INTO artifacts (digest, kind, size_bytes, storage_uri, media_type, access_policy, available, created_at)
        VALUES ('snap1_hash', 'snapshot', 10, 'file:///s', 'text/plain', 'public', 1, '2026-09-21T00:00:00Z'),
               ('diff1_hash', 'diff', 10, 'file:///d', 'text/x-diff', 'public', 1, '2026-09-21T00:00:00Z'),
               ('pay1_hash', 'payload', 10, 'file:///p', 'application/zip', 'public', 1, '2026-09-21T00:00:00Z'),
               ('out1_hash', 'stdout', 20, 'file:///o', 'text/plain', 'public', 1, '2026-09-21T00:00:00Z'),
               ('err1_hash', 'stderr', 20, 'file:///e', 'text/plain', 'public', 1, '2026-09-21T00:00:00Z'),
               ('rep1_hash', 'report', 20, 'file:///r', 'application/json', 'public', 1, '2026-09-21T00:00:00Z')
        """
    )
    conn.execute(
        """
        INSERT INTO environments (environment_id, backend, platform, recipe_digest, lock_digests, service_manifests, resource_policy_hash, runtime_fingerprint, mirror_uris)
        VALUES ('env1', 'fixture', 'linux/arm64', 'rec1', '[]', '{}', 'p1', 'fp1', '[]')
        """
    )
    conn.execute(
        """
        INSERT INTO repository_snapshots (snapshot_digest, repository_id, commit_oid, archive_uri, tree_digest, submodule_digests, lock_digests, licence, created_at)
        VALUES ('snap1_hash', 'repo1', 'oid1', 'file:///s', 'tree1', '[]', '[]', 'MIT', '2026-09-21T00:00:00Z')
        """
    )
    conn.execute(
        """
        INSERT INTO contracts (contract_hash, task_id, version, requirement_hashes, allowed_variation, unresolved_questions, evidence_digests, created_at)
        VALUES ('con1_hash', 'task1', 'v1', '[]', 'none', '[]', '[]', '2026-09-21T00:00:00Z')
        """
    )
    conn.execute(
        """
        INSERT INTO tasks (task_key, task_id, version, statement, adapter, contract_hash, snapshot_digest, environment_id, licence, provenance, eligibility, notes, created_at)
        VALUES ('tkey1', 'task1', 'v1', 'stat', 'fixture', 'con1_hash', 'snap1_hash', 'env1', 'MIT', 'prov', 'eligible', '', '2026-09-21T00:00:00Z')
        """
    )
    conn.execute(
        """
        INSERT INTO patch_cases (case_id, task_key, diff_digest, base_snapshot_digest, source, parent_case_ids, family_id, role, provenance_digest, licence, created_at)
        VALUES ('case1', 'tkey1', 'diff1_hash', 'snap1_hash', 'reference', '[]', 'fam1', 'challenge', 'prov1', 'MIT', '2026-09-21T00:00:00Z')
        """
    )
    conn.execute(
        """
        INSERT INTO patch_panels (panel_key, panel_id, version, split, membership_digest, sampling_policy)
        VALUES ('panel1', 'p1', 'v1', 'development', 'mem1', 'policy1')
        """
    )
    conn.execute(
        """
        INSERT INTO verifier_manifests (manifest_hash, mode, command, build_command, expected_collection, parser_id, report_path, payload_digest, allowed_edit_paths, required_pass_ids, permitted_skips, timeout_seconds)
        VALUES ('vman1', 'compatibility', '["pytest"]', '["true"]', '["test_1"]', 'pytest', 'report.json', 'pay1_hash', '["*"]', '[]', '[]', 30)
        """
    )
    conn.execute(
        """
        INSERT INTO verifier_versions (verifier_key, verifier_id, version, manifest_hash, payload_digest, compatible_contract_hashes, created_at)
        VALUES ('vkey1', 'verifier1', 'v1', 'vman1', 'pay1_hash', '["con1_hash"]', '2026-09-21T00:00:00Z')
        """
    )
    conn.execute(
        """
        INSERT INTO audit_manifests (manifest_hash, run_id, benchmark_version, task_pins, panel_key, adjudication_version, evaluation_harness_version, config_hash, policy_hash, timestamp, host_fingerprint, max_repetitions, max_attempts_per_job, timeout_seconds, resource_policy, expansion_digest)
        VALUES ('man1', 'run1', 'bench1', '[]', 'panel1', 'adj1', 'harn1', 'conf1', 'pol1', '2026-09-21T00:00:00Z', 'host1', 1, 3, 30, 'pol', 'exp1')
        """
    )
    conn.execute(
        """
        INSERT INTO audit_runs (run_id, manifest_hash, state, cancel_requested, created_at)
        VALUES ('run1', 'man1', 'RUNNING', 0, '2026-09-21T00:00:00Z')
        """
    )

    for i in range(num_jobs):
        conn.execute(
            """
            INSERT INTO jobs (job_id, run_id, task_key, case_id, verifier_key, repetition, state, fence, attempts_started)
            VALUES (?, 'run1', 'tkey1', 'case1', 'vkey1', ?, 'PENDING', 0, 0)
            """,
            (f"job_{i}", i),
        )

    return db


def test_atomic_claim_concurrency_no_double_assignment(tmp_path: Path) -> None:
    """Verify that concurrent worker threads claim each job exactly once without contention."""
    db_file = tmp_path / "concurrent_claims.db"
    num_jobs = 8
    num_workers = 8
    _setup_test_db(db_file, num_jobs=num_jobs)

    claimed_results: list[Job] = []
    now_ms = 1_000_000

    def worker_claim_task(worker_id: str) -> Job | None:
        worker_conn = connect(db_file)
        try:
            return claim(worker_conn, worker_id=worker_id, now_ms=now_ms)
        finally:
            worker_conn.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
        futures = [
            executor.submit(worker_claim_task, f"worker_{i}")
            for i in range(num_workers)
        ]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res is not None:
                claimed_results.append(res)

    # Every job claimed exactly once
    assert len(claimed_results) == num_jobs
    job_ids = [j.job_id for j in claimed_results]
    assert len(set(job_ids)) == num_jobs

    tokens = [j.lease_token for j in claimed_results]
    assert len(set(tokens)) == num_jobs
    assert all(j.fence == 1 for j in claimed_results)
    assert all(j.state == "CLAIMED" for j in claimed_results)

    # Database state verification
    verify_conn = connect(db_file)
    try:
        pending_count = verify_conn.execute(
            "SELECT COUNT(*) FROM jobs WHERE state = 'PENDING'"
        ).fetchone()[0]
        assert pending_count == 0

        attempt_count = verify_conn.execute(
            "SELECT COUNT(*) FROM evaluation_attempts WHERE disposition = 'active'"
        ).fetchone()[0]
        assert attempt_count == num_jobs
    finally:
        verify_conn.close()


def test_claim_transaction_rollback_does_not_launch(tmp_path: Path) -> None:
    """SDD 9.2: Assert that an error/rollback during claim leaves no orphaned attempts or mutated jobs."""
    db_file = tmp_path / "rollback_claim.db"
    db = _setup_test_db(db_file, num_jobs=1)
    conn = db.connection

    # Simulate an error inside a transactional claim block before completion
    with (
        pytest.raises(RuntimeError, match="Simulated crash during claim"),
        transaction(conn, immediate=True),
    ):
        # Claim job state manually
        conn.execute(
            """
            UPDATE jobs
            SET state = 'CLAIMED', fence = 1, attempt_id = 'orphan_attempt'
            WHERE job_id = 'job_0'
            """
        )
        # Insert attempt
        conn.execute(
            """
            INSERT INTO evaluation_attempts (
                attempt_id, job_id, fence, outcome, evaluation_validity,
                error_code, disposition, started_at, test_collection, resources,
                artifact_digests, capture_truncated
            ) VALUES (
                'orphan_attempt', 'job_0', 1, NULL, 'pending',
                NULL, 'active', '2026-09-21T00:00:00Z', '[]', '{}',
                '[]', 0
            )
            """
        )
        raise RuntimeError("Simulated crash during claim")

    # Transaction rolled back: job remains PENDING with fence 0, no attempt row
    job = get_job(conn, "job_0")
    assert job is not None
    assert job.state == "PENDING"
    assert job.fence == 0
    assert job.attempt_id is None
    assert job.attempts_started == 0

    attempt_count = conn.execute(
        "SELECT COUNT(*) FROM evaluation_attempts WHERE attempt_id = 'orphan_attempt'"
    ).fetchone()[0]
    assert attempt_count == 0


def test_heartbeat_lease_extension_and_fencing_checks(tmp_path: Path) -> None:
    """Verify heartbeat extends lease only under matching token, worker, and live fence."""
    db_file = tmp_path / "heartbeat_fencing.db"
    db = _setup_test_db(db_file, num_jobs=1)
    conn = db.connection

    now_ms = 1_000_000
    job = claim(conn, worker_id="worker_alpha", now_ms=now_ms)
    assert job is not None
    assert job.lease_expires_ms == now_ms + 30_000

    # 1. Mark running under live lease
    running_job = mark_running(conn, job, now_ms=now_ms + 1000)
    assert running_job.state == "RUNNING"

    # 2. Heartbeat extends lease by extension_ms (30,000 ms from now_ms)
    renewed_job = heartbeat(
        conn, running_job, now_ms=now_ms + 10_000, extension_ms=30_000
    )
    assert renewed_job.lease_expires_ms == now_ms + 40_000

    import dataclasses

    # 3. Token mismatch raises LeaseLost
    bad_token_job = dataclasses.replace(renewed_job, lease_token="wrong_token_secret")
    with pytest.raises(LeaseLost) as exc_tok:
        heartbeat(conn, bad_token_job, now_ms=now_ms + 15_000)
    assert exc_tok.value.code == ErrorCode.LEASE_LOST.value

    # 4. Worker ID mismatch raises LeaseLost
    bad_worker_job = dataclasses.replace(renewed_job, worker_id="imposter_worker")
    with pytest.raises(LeaseLost) as exc_work:
        heartbeat(conn, bad_worker_job, now_ms=now_ms + 15_000)
    assert exc_work.value.code == ErrorCode.LEASE_LOST.value

    # 5. Fence mismatch raises LeaseLost
    bad_fence_job = dataclasses.replace(renewed_job, fence=99)
    with pytest.raises(LeaseLost) as exc_fence:
        heartbeat(conn, bad_fence_job, now_ms=now_ms + 15_000)
    assert exc_fence.value.code == ErrorCode.LEASE_LOST.value

    # 6. Heartbeat after lease expired (now_ms > 1_040_000) raises LeaseLost
    with pytest.raises(LeaseLost) as exc_exp:
        heartbeat(conn, renewed_job, now_ms=now_ms + 45_000)
    assert exc_exp.value.code == ErrorCode.LEASE_LOST.value


def test_lease_expiry_requeues_job_with_incremented_fence(tmp_path: Path) -> None:
    """SDD 9.2: Assert lease expiry reaps ABANDONED -> PENDING with incremented fence on next claim."""
    db_file = tmp_path / "lease_expiry.db"
    db = _setup_test_db(db_file, num_jobs=1)
    conn = db.connection

    start_ms = 1_000_000

    # 1. Claim A at fence 1
    job_a = claim(conn, worker_id="worker_a", now_ms=start_ms)
    assert job_a is not None
    assert job_a.fence == 1
    assert job_a.attempts_started == 1

    mark_running(conn, job_a, now_ms=start_ms + 1000)

    # 2. Advance time past lease expiration (30s lease expires at 1_030_000)
    reaped = reap_expired(conn, now_ms=start_ms + 35_000, max_attempts=3)
    assert reaped == ("job_0",)

    # Attempt A marked abandoned in DB
    att_a_row = conn.execute(
        "SELECT disposition, evaluation_validity FROM evaluation_attempts WHERE attempt_id = ?",
        (job_a.attempt_id,),
    ).fetchone()
    assert att_a_row["disposition"] == "abandoned"
    assert att_a_row["evaluation_validity"] == "invalid"

    # Job is requeued to PENDING
    requeued_job = get_job(conn, "job_0")
    assert requeued_job is not None
    assert requeued_job.state == "PENDING"
    assert requeued_job.attempt_id is None
    assert requeued_job.lease_token is None
    assert requeued_job.fence == 1
    assert requeued_job.attempts_started == 1

    # 3. Next worker claims: fence increments to 2, attempts_started increments to 2
    job_b = claim(conn, worker_id="worker_b", now_ms=start_ms + 40_000)
    assert job_b is not None
    assert job_b.fence == 2
    assert job_b.attempts_started == 2
    assert job_b.attempt_id != job_a.attempt_id


def test_late_result_does_not_overwrite_successful_attempt(tmp_path: Path) -> None:
    """SDD 9.2: Claim A expires, B completes; A submits conflicting result.

    Asserts B remains authoritative, A is marked stale, and duplicate B is idempotent.
    """
    db_file = tmp_path / "late_result_fencing.db"
    db = _setup_test_db(db_file, num_jobs=1)
    conn = db.connection

    start_ms = 1_000_000

    # 1. Claim A at fence 1
    job_a = claim(conn, worker_id="worker_a", now_ms=start_ms)
    assert job_a is not None and job_a.fence == 1

    # 2. Lease expires for A; reaper requeues job
    reap_expired(conn, now_ms=start_ms + 35_000, max_attempts=3)

    # 3. Claim B at fence 2
    job_b = claim(conn, worker_id="worker_b", now_ms=start_ms + 40_000)
    assert job_b is not None and job_b.fence == 2

    # 4. Worker B completes successfully under live fence 2
    attempt_b = EvaluationAttempt(
        attempt_id=job_b.attempt_id,  # type: ignore[arg-type]
        job_id=job_b.job_id,
        fence=job_b.fence,
        outcome="accept",
        evaluation_validity="valid",
        error_code=None,
        disposition="authoritative",
        started_at=datetime.fromtimestamp((start_ms + 40_000) / 1000.0, UTC),
        finished_at=datetime.fromtimestamp((start_ms + 45_000) / 1000.0, UTC),
        exit_code=0,
        stdout_hash="out1_hash",
        stderr_hash="err1_hash",
        report_digest="rep1_hash",
        test_collection=("test_1",),
        tests_passed=1,
        tests_failed=0,
        resources=ResourceUsage(5.0, 1.0, 0.5, 1024, None, None, None, 100),
        artifact_digests=("out1_hash", "err1_hash", "rep1_hash"),
        capture_truncated=False,
    )

    status_b = complete(conn, job_b, attempt_b, now_ms=start_ms + 45_000)
    assert status_b == "committed"

    # Job is DONE with selected_attempt_id = attempt_b
    db_job = get_job(conn, "job_0")
    assert db_job is not None
    assert db_job.state == "DONE"
    assert db_job.selected_attempt_id == attempt_b.attempt_id

    # 5. Worker A (late, fence 1) now attempts to complete with conflicting outcome ("reject")
    attempt_a = EvaluationAttempt(
        attempt_id=job_a.attempt_id,  # type: ignore[arg-type]
        job_id=job_a.job_id,
        fence=job_a.fence,
        outcome="reject",
        evaluation_validity="valid",
        error_code=None,
        disposition="authoritative",
        started_at=datetime.fromtimestamp(start_ms / 1000.0, UTC),
        finished_at=datetime.fromtimestamp((start_ms + 50_000) / 1000.0, UTC),
        exit_code=1,
        stdout_hash="out1_hash",
        stderr_hash="err1_hash",
        report_digest="rep1_hash",
        test_collection=("test_1",),
        tests_passed=0,
        tests_failed=1,
        resources=ResourceUsage(50.0, 1.0, 1.0, 1024, None, None, None, 100),
        artifact_digests=("out1_hash",),
        capture_truncated=False,
    )

    status_a = complete(conn, job_a, attempt_a, now_ms=start_ms + 50_000)
    assert status_a == "stale"

    # Invariant: Job remains DONE with attempt_b selected
    db_job_after = get_job(conn, "job_0")
    assert db_job_after is not None
    assert db_job_after.state == "DONE"
    assert db_job_after.selected_attempt_id == attempt_b.attempt_id

    # Attempt A is marked stale (not authoritative)
    att_a_db = conn.execute(
        "SELECT disposition, evaluation_validity FROM evaluation_attempts WHERE attempt_id = ?",
        (attempt_a.attempt_id,),
    ).fetchone()
    assert att_a_db["disposition"] == "stale"
    assert att_a_db["evaluation_validity"] == "invalid"

    # Attempt B remains authoritative in DB
    att_b_db = conn.execute(
        "SELECT disposition, outcome FROM evaluation_attempts WHERE attempt_id = ?",
        (attempt_b.attempt_id,),
    ).fetchone()
    assert att_b_db["disposition"] == "authoritative"
    assert att_b_db["outcome"] == "accept"

    # 6. Repeated identical completion for B is idempotent duplicate
    status_dup = complete(conn, job_b, attempt_b, now_ms=start_ms + 52_000)
    assert status_dup == "duplicate"

    # 7. Repeated completion for B with conflicting data raises IdentityConflict
    import dataclasses

    conflicting_b = dataclasses.replace(attempt_b, tests_passed=999)
    with pytest.raises(IdentityConflict) as exc_conflict:
        complete(conn, job_b, conflicting_b, now_ms=start_ms + 53_000)
    assert exc_conflict.value.code == ErrorCode.IDENTITY_CONFLICT.value


def test_crash_between_artifact_and_db_commit(tmp_path: Path) -> None:
    """SDD 9.2: Assert that crash after artifact write before DB commit is safely reaped without false pass."""
    db_file = tmp_path / "crash_recovery.db"
    db = _setup_test_db(db_file, num_jobs=1)
    conn = db.connection
    store = ArtifactStore(tmp_path / "artifacts")

    now_ms = 1_000_000
    job = claim(conn, worker_id="worker_crasher", now_ms=now_ms)
    assert job is not None

    # Worker writes artifacts to disk
    art = store.put_bytes(
        b"worker partial test output",
        max_bytes=1000,
        kind="stdout",
        access_policy="public",
    )
    assert store.exists(art.digest)

    # Worker crashes before calling complete(); lease expires
    reaped = reap_expired(conn, now_ms=now_ms + 35_000, max_attempts=3)
    assert reaped == ("job_0",)

    # Job is safely requeued to PENDING, no false pass
    j = get_job(conn, "job_0")
    assert j is not None
    assert j.state == "PENDING"
    assert j.selected_attempt_id is None

    # Next worker completes
    job_next = claim(conn, worker_id="worker_recoverer", now_ms=now_ms + 40_000)
    assert job_next is not None and job_next.fence == 2


def test_cancel_is_idempotent_and_cooperative(tmp_path: Path) -> None:
    """SDD 9.2: Cancel twice while job runs.

    Asserts single cancellation state, no new claims, and cooperative cleanup.
    """
    db_file = tmp_path / "cancel_idempotency.db"
    db = _setup_test_db(db_file, num_jobs=2)
    conn = db.connection

    now_ms = 1_000_000

    # Claim job_0, leave job_1 PENDING
    running_job = claim(conn, worker_id="w1", now_ms=now_ms)
    assert running_job is not None and running_job.job_id == "job_0"

    # First cancel call
    request_cancel(conn, run_id="run1", now_ms=now_ms + 1000)

    # PENDING job_1 is immediately failed with CANCELLED
    j1 = get_job(conn, "job_1")
    assert j1 is not None
    assert j1.state == "FAILED"
    assert j1.terminal_reason == "CANCELLED"

    # Second cancel call is idempotent
    request_cancel(conn, run_id="run1", now_ms=now_ms + 2000)

    # No new claims can be made on cancelled run
    assert claim(conn, worker_id="w2", now_ms=now_ms + 3000, run_id="run1") is None

    # When running job_0 expires, reaper marks it FAILED with CANCELLED (not requeued)
    reaped = reap_expired(conn, now_ms=now_ms + 35_000, max_attempts=3)
    assert "job_0" in reaped

    j0 = get_job(conn, "job_0")
    assert j0 is not None
    assert j0.state == "FAILED"
    assert j0.terminal_reason == "CANCELLED"

    # Run state is CANCELLED
    run_row = conn.execute(
        "SELECT state FROM audit_runs WHERE run_id = 'run1'"
    ).fetchone()
    assert run_row["state"] == "CANCELLED"


def test_retry_budget_exhaustion_terminates_failed(tmp_path: Path) -> None:
    """Assert job transitions to FAILED when physical retry budget is exhausted."""
    db_file = tmp_path / "budget_exhaustion.db"
    db = _setup_test_db(db_file, num_jobs=1)
    conn = db.connection

    now_ms = 1_000_000

    # Attempt 1
    j1 = claim(conn, worker_id="w1", now_ms=now_ms)
    assert j1 is not None and j1.attempts_started == 1
    reap_expired(conn, now_ms=now_ms + 35_000, max_attempts=2)
    assert get_job(conn, "job_0").state == "PENDING"  # type: ignore[union-attr]

    # Attempt 2
    j2 = claim(conn, worker_id="w2", now_ms=now_ms + 40_000)
    assert j2 is not None and j2.attempts_started == 2

    # Expire attempt 2: max_attempts is 2, so transitions to terminal FAILED
    reap_expired(conn, now_ms=now_ms + 75_000, max_attempts=2)
    final_job = get_job(conn, "job_0")
    assert final_job is not None
    assert final_job.state == "FAILED"
    assert final_job.terminal_reason == "LEASE_EXPIRED"

    # Run state transitions to FAILED
    run_row = conn.execute(
        "SELECT state FROM audit_runs WHERE run_id = 'run1'"
    ).fetchone()
    assert run_row["state"] == "FAILED"
