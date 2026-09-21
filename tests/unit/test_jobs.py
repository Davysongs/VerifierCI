"""Unit tests for SQLite fenced queue operations.

SDD Section 7.1:
Tests atomic claim, running transition, heartbeat renewal, safe completion,
reaping of expired leases, and cancellation handling.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from verifierci.errors import (
    ErrorCode,
    IdentityConflict,
    InfrastructureError,
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
from verifierci.models.protocol import ResourceUsage
from verifierci.models.result import EvaluationAttempt
from verifierci.storage.db import Database


@pytest.fixture
def db() -> Database:
    database = Database(":memory:")
    database.migrate()
    conn = database.connection

    # Seed required relational hierarchy
    conn.execute(
        """
        INSERT INTO artifacts (digest, kind, size_bytes, storage_uri, media_type, access_policy, available, created_at)
        VALUES ('snap1', 'snapshot', 10, 'file:///s', 'text/plain', 'public', 1, '2026-09-21T00:00:00Z'),
               ('diff1', 'diff', 10, 'file:///d', 'text/x-diff', 'public', 1, '2026-09-21T00:00:00Z'),
               ('pay1', 'payload', 10, 'file:///p', 'application/zip', 'public', 1, '2026-09-21T00:00:00Z'),
               ('out1', 'stdout', 20, 'file:///o', 'text/plain', 'public', 1, '2026-09-21T00:00:00Z'),
               ('err1', 'stderr', 20, 'file:///e', 'text/plain', 'public', 1, '2026-09-21T00:00:00Z'),
               ('rep1', 'report', 20, 'file:///r', 'application/json', 'public', 1, '2026-09-21T00:00:00Z')
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
        VALUES ('snap1', 'repo1', 'oid1', 'file:///s', 'tree1', '[]', '[]', 'MIT', '2026-09-21T00:00:00Z')
        """
    )
    conn.execute(
        """
        INSERT INTO contracts (contract_hash, task_id, version, requirement_hashes, allowed_variation, unresolved_questions, evidence_digests, created_at)
        VALUES ('con1', 'task1', 'v1', '[]', 'none', '[]', '[]', '2026-09-21T00:00:00Z')
        """
    )
    conn.execute(
        """
        INSERT INTO tasks (task_key, task_id, version, statement, adapter, contract_hash, snapshot_digest, environment_id, licence, provenance, eligibility, notes, created_at)
        VALUES ('tkey1', 'task1', 'v1', 'stat', 'fixture', 'con1', 'snap1', 'env1', 'MIT', 'prov', 'eligible', '', '2026-09-21T00:00:00Z')
        """
    )
    conn.execute(
        """
        INSERT INTO verifier_manifests (manifest_hash, mode, command, build_command, expected_collection, parser_id, report_path, payload_digest, allowed_edit_paths, required_pass_ids, permitted_skips, timeout_seconds)
        VALUES ('vman1', 'compatibility', '["pytest"]', '["true"]', '["test_1"]', 'pytest', 'report.json', 'pay1', '["*"]', '[]', '[]', 30)
        """
    )
    conn.execute(
        """
        INSERT INTO verifier_versions (verifier_key, verifier_id, version, manifest_hash, payload_digest, compatible_contract_hashes, created_at)
        VALUES ('vkey1', 'verifier1', 'v1', 'vman1', 'pay1', '["con1"]', '2026-09-21T00:00:00Z')
        """
    )
    conn.execute(
        """
        INSERT INTO patch_cases (case_id, task_key, diff_digest, base_snapshot_digest, source, parent_case_ids, family_id, role, provenance_digest, licence, created_at)
        VALUES ('case1', 'tkey1', 'diff1', 'snap1', 'reference', '[]', 'fam1', 'challenge', 'prov1', 'MIT', '2026-09-21T00:00:00Z')
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
    conn.execute(
        """
        INSERT INTO jobs (job_id, run_id, task_key, case_id, verifier_key, repetition, state, fence, attempts_started)
        VALUES ('job1', 'run1', 'tkey1', 'case1', 'vkey1', 0, 'PENDING', 0, 0)
        """
    )
    return database


def test_claim_job_lifecycle(db: Database) -> None:
    conn = db.connection
    now_ms = 1_000_000

    job = claim(conn, worker_id="worker_1", now_ms=now_ms)
    assert job is not None
    assert job.job_id == "job1"
    assert job.state == "CLAIMED"
    assert job.fence == 1
    assert job.attempts_started == 1
    assert job.worker_id == "worker_1"
    assert job.lease_expires_ms == now_ms + 30_000
    assert job.attempt_id is not None
    assert job.lease_token is not None
    assert len(job.lease_token) == 32

    # Verify attempt recorded in database
    attempt_row = conn.execute(
        "SELECT fence, disposition, evaluation_validity, outcome FROM evaluation_attempts WHERE attempt_id = ?",
        (job.attempt_id,),
    ).fetchone()
    assert attempt_row is not None
    assert attempt_row["fence"] == 1
    assert attempt_row["disposition"] == "active"
    assert attempt_row["evaluation_validity"] == "pending"
    assert attempt_row["outcome"] is None

    # Claiming again returns None as queue is empty
    assert claim(conn, worker_id="worker_2", now_ms=now_ms) is None


def test_mark_running_and_heartbeat(db: Database) -> None:
    conn = db.connection
    now_ms = 1_000_000

    claimed_job = claim(conn, worker_id="worker_1", now_ms=now_ms)
    assert claimed_job is not None

    # 1. Mark running under valid lease
    running_job = mark_running(conn, claimed_job, now_ms=now_ms + 1000)
    assert running_job.state == "RUNNING"

    db_job = get_job(conn, claimed_job.job_id)
    assert db_job is not None
    assert db_job.state == "RUNNING"

    # 2. Heartbeat extends lease
    renewed_job = heartbeat(
        conn, running_job, now_ms=now_ms + 5000, extension_ms=30_000
    )
    assert renewed_job.lease_expires_ms == now_ms + 35_000

    # 3. Heartbeat after expiration fails
    with pytest.raises(LeaseLost) as exc_info:
        heartbeat(conn, renewed_job, now_ms=now_ms + 50_000)
    assert exc_info.value.code == ErrorCode.LEASE_LOST.value

    # 4. Token mismatch fails
    import dataclasses

    bad_token_job = dataclasses.replace(running_job, lease_token="wrong_token_hex")
    with pytest.raises(LeaseLost) as exc_info:
        mark_running(conn, bad_token_job, now_ms=now_ms + 2000)
    assert exc_info.value.code == ErrorCode.LEASE_LOST.value


def test_complete_authoritative(db: Database) -> None:
    conn = db.connection
    now_ms = 1_000_000

    job = claim(conn, worker_id="worker_1", now_ms=now_ms)
    assert job is not None

    attempt = EvaluationAttempt(
        attempt_id=job.attempt_id,  # type: ignore[arg-type]
        job_id=job.job_id,
        fence=job.fence,
        outcome="accept",
        evaluation_validity="valid",
        error_code=None,
        disposition="authoritative",
        started_at=datetime.fromtimestamp(now_ms / 1000.0, UTC),
        finished_at=datetime.fromtimestamp((now_ms + 5000) / 1000.0, UTC),
        exit_code=0,
        stdout_hash="out1",
        stderr_hash="err1",
        report_digest="rep1",
        test_collection=("test_1",),
        tests_passed=1,
        tests_failed=0,
        resources=ResourceUsage(
            duration=5.0,
            allocated_cpu=1.0,
            cpu_seconds=0.5,
            peak_memory=1024,
            model_usage=None,
            estimated_cost=None,
            pricing_version=None,
            bytes_written=100,
        ),
        artifact_digests=("out1", "err1", "rep1"),
        capture_truncated=False,
    )

    status = complete(conn, job, attempt, now_ms=now_ms + 5000)
    assert status == "committed"

    # Job is DONE, selected_attempt_id set, lease cleared
    updated_job = get_job(conn, job.job_id)
    assert updated_job is not None
    assert updated_job.state == "DONE"
    assert updated_job.selected_attempt_id == attempt.attempt_id
    assert updated_job.lease_token is None
    assert updated_job.lease_expires_ms is None

    # Attempt in DB is authoritative
    att_row = conn.execute(
        "SELECT disposition, outcome, evaluation_validity FROM evaluation_attempts WHERE attempt_id = ?",
        (attempt.attempt_id,),
    ).fetchone()
    assert att_row["disposition"] == "authoritative"
    assert att_row["outcome"] == "accept"
    assert att_row["evaluation_validity"] == "valid"


def test_complete_duplicate_and_conflict(db: Database) -> None:
    conn = db.connection
    now_ms = 1_000_000

    job = claim(conn, worker_id="worker_1", now_ms=now_ms)
    assert job is not None

    attempt = EvaluationAttempt(
        attempt_id=job.attempt_id,  # type: ignore[arg-type]
        job_id=job.job_id,
        fence=job.fence,
        outcome="accept",
        evaluation_validity="valid",
        error_code=None,
        disposition="authoritative",
        started_at=datetime.fromtimestamp(now_ms / 1000.0, UTC),
        finished_at=datetime.fromtimestamp((now_ms + 2000) / 1000.0, UTC),
        exit_code=0,
        stdout_hash="out1",
        stderr_hash="err1",
        report_digest="rep1",
        test_collection=("test_1",),
        tests_passed=1,
        tests_failed=0,
        resources=ResourceUsage(
            duration=2.0,
            allocated_cpu=1.0,
            cpu_seconds=0.2,
            peak_memory=1024,
            model_usage=None,
            estimated_cost=None,
            pricing_version=None,
            bytes_written=50,
        ),
        artifact_digests=("out1",),
        capture_truncated=False,
    )

    # First commit: committed
    assert complete(conn, job, attempt, now_ms=now_ms + 2000) == "committed"

    # Resubmitting identical attempt: duplicate
    assert complete(conn, job, attempt, now_ms=now_ms + 3000) == "duplicate"

    # Resubmitting conflicting attempt: IdentityConflict
    conflicting_attempt = EvaluationAttempt(
        attempt_id=attempt.attempt_id,
        job_id=attempt.job_id,
        fence=attempt.fence,
        outcome="reject",  # Changed!
        evaluation_validity="valid",
        error_code=None,
        disposition="authoritative",
        started_at=attempt.started_at,
        finished_at=attempt.finished_at,
        exit_code=1,
        stdout_hash=attempt.stdout_hash,
        stderr_hash=attempt.stderr_hash,
        report_digest=attempt.report_digest,
        test_collection=attempt.test_collection,
        tests_passed=0,
        tests_failed=1,
        resources=attempt.resources,
        artifact_digests=attempt.artifact_digests,
        capture_truncated=False,
    )
    with pytest.raises(IdentityConflict) as exc_info:
        complete(conn, job, conflicting_attempt, now_ms=now_ms + 3000)
    assert exc_info.value.code == ErrorCode.IDENTITY_CONFLICT.value


def test_complete_stale_on_expired_lease(db: Database) -> None:
    conn = db.connection
    now_ms = 1_000_000

    job = claim(conn, worker_id="worker_1", now_ms=now_ms)
    assert job is not None

    attempt = EvaluationAttempt(
        attempt_id=job.attempt_id,  # type: ignore[arg-type]
        job_id=job.job_id,
        fence=job.fence,
        outcome="accept",
        evaluation_validity="valid",
        error_code=None,
        disposition="authoritative",
        started_at=datetime.fromtimestamp(now_ms / 1000.0, UTC),
        finished_at=datetime.fromtimestamp((now_ms + 40_000) / 1000.0, UTC),
        exit_code=0,
        stdout_hash="out1",
        stderr_hash="err1",
        report_digest="rep1",
        test_collection=(),
        tests_passed=0,
        tests_failed=0,
        resources=ResourceUsage(
            duration=40.0,
            allocated_cpu=1.0,
            cpu_seconds=0.2,
            peak_memory=1024,
            model_usage=None,
            estimated_cost=None,
            pricing_version=None,
            bytes_written=0,
        ),
        artifact_digests=(),
        capture_truncated=False,
    )

    # Worker submits after lease expired (30s lease expired at now_ms + 30000)
    late_ms = now_ms + 40_000
    status = complete(conn, job, attempt, now_ms=late_ms)
    assert status == "stale"

    # Attempt marked stale, job not DONE
    att_row = conn.execute(
        "SELECT disposition, evaluation_validity FROM evaluation_attempts WHERE attempt_id = ?",
        (attempt.attempt_id,),
    ).fetchone()
    assert att_row["disposition"] == "stale"
    assert att_row["evaluation_validity"] == "invalid"

    updated_job = get_job(conn, job.job_id)
    assert updated_job is not None
    assert updated_job.state != "DONE"


def test_reap_expired_requeues_and_exhausts(db: Database) -> None:
    conn = db.connection
    now_ms = 1_000_000

    # Attempt 1
    job1 = claim(conn, worker_id="w1", now_ms=now_ms)
    assert job1 is not None and job1.attempts_started == 1

    # Lease expires, reap -> requeued to PENDING
    reaped = reap_expired(conn, now_ms=now_ms + 31_000, max_attempts=3)
    assert reaped == ("job1",)

    job_after_reap1 = get_job(conn, "job1")
    assert job_after_reap1 is not None
    assert job_after_reap1.state == "PENDING"
    assert job_after_reap1.attempt_id is None

    # Attempt 2
    job2 = claim(conn, worker_id="w2", now_ms=now_ms + 35_000)
    assert job2 is not None and job2.attempts_started == 2
    assert job2.fence == 2

    # Expire and reap again -> requeued to PENDING
    reap_expired(conn, now_ms=now_ms + 70_000, max_attempts=3)
    assert get_job(conn, "job1").state == "PENDING"  # type: ignore[union-attr]

    # Attempt 3
    job3 = claim(conn, worker_id="w3", now_ms=now_ms + 75_000)
    assert job3 is not None and job3.attempts_started == 3
    assert job3.fence == 3

    # Expire and reap third time -> attempts_started >= 3 -> transitions to FAILED
    reap_expired(conn, now_ms=now_ms + 110_000, max_attempts=3)
    final_job = get_job(conn, "job1")
    assert final_job is not None
    assert final_job.state == "FAILED"
    assert final_job.terminal_reason == "LEASE_EXPIRED"


def test_request_cancel(db: Database) -> None:
    conn = db.connection
    # Cancel the run
    request_cancel(conn, run_id="run1")

    # Audit run marked cancel_requested
    run_row = conn.execute(
        "SELECT cancel_requested FROM audit_runs WHERE run_id = 'run1'"
    ).fetchone()
    assert run_row[0] == 1

    # Pending job cancelled
    job = get_job(conn, "job1")
    assert job is not None
    assert job.state == "FAILED"
    assert job.terminal_reason == "CANCELLED"

    # Claim returns None
    assert claim(conn, worker_id="w1", now_ms=1000) is None


def test_claim_with_run_id_filtering(db: Database) -> None:
    conn = db.connection
    # Claim with matching run_id
    j1 = claim(conn, worker_id="w1", now_ms=1000, run_id="run1")
    assert j1 is not None and j1.job_id == "job1"

    # Claim with non-existent run_id
    assert claim(conn, worker_id="w2", now_ms=1000, run_id="no_run") is None


def test_get_job_nonexistent(db: Database) -> None:
    conn = db.connection
    assert get_job(conn, "no_such_job") is None


def test_mark_running_and_heartbeat_error_paths(db: Database) -> None:
    conn = db.connection
    job = claim(conn, worker_id="w1", now_ms=1000)
    assert job is not None

    import dataclasses

    # Non-existent job
    fake_job = dataclasses.replace(job, job_id="nonexistent")
    with pytest.raises(LeaseLost):
        mark_running(conn, fake_job, now_ms=2000)
    with pytest.raises(LeaseLost):
        heartbeat(conn, fake_job, now_ms=2000)

    # Transition job to terminal state
    conn.execute("UPDATE jobs SET state = 'DONE' WHERE job_id = 'job1'")
    with pytest.raises(LeaseLost):
        mark_running(conn, job, now_ms=2000)
    with pytest.raises(LeaseLost):
        heartbeat(conn, job, now_ms=2000)


def test_complete_error_outcome_and_terminal_scenarios(db: Database) -> None:
    conn = db.connection
    job = claim(conn, worker_id="w1", now_ms=1000)
    assert job is not None

    import dataclasses

    # Complete non-existent job
    fake_job = dataclasses.replace(job, job_id="nonexistent")
    att = EvaluationAttempt(
        attempt_id=job.attempt_id,  # type: ignore[arg-type]
        job_id="nonexistent",
        fence=job.fence,
        outcome="error",
        evaluation_validity="invalid",
        error_code="BUILD_ERROR",
        disposition="authoritative",
        started_at=datetime.fromtimestamp(1.0, UTC),
        finished_at=datetime.fromtimestamp(2.0, UTC),
        exit_code=1,
        stdout_hash=None,
        stderr_hash=None,
        report_digest=None,
        test_collection=(),
        tests_passed=0,
        tests_failed=0,
        resources=ResourceUsage(None, None, None, None, None, None, None, None),
        artifact_digests=(),
        capture_truncated=False,
    )
    with pytest.raises(InfrastructureError):
        complete(conn, fake_job, att, now_ms=2000)

    # Complete real job with error outcome -> transitions to FAILED
    att = dataclasses.replace(att, job_id=job.job_id)
    status = complete(conn, job, att, now_ms=2000)
    assert status == "committed"
    j = get_job(conn, "job1")
    assert j is not None and j.state == "FAILED"
    assert j.terminal_reason == "BUILD_ERROR"

    # Now job is terminal. Another worker submits a DIFFERENT attempt -> stale
    diff_att = dataclasses.replace(att, attempt_id="diff_attempt_id")
    status_diff = complete(conn, job, diff_att, now_ms=3000)
    assert status_diff == "stale"

    # Same attempt_id with identical content -> duplicate
    status_dup = complete(conn, job, att, now_ms=3000)
    assert status_dup == "duplicate"

    # Same attempt_id with conflicting payload -> IdentityConflict
    conflict_att = dataclasses.replace(att, tests_passed=99)
    with pytest.raises(IdentityConflict):
        complete(conn, job, conflict_att, now_ms=3000)


def test_complete_mismatched_attempt_ownership(db: Database) -> None:
    conn = db.connection
    job = claim(conn, worker_id="w1", now_ms=1000)
    assert job is not None

    # Attempt with wrong fence in DB or wrong job_id
    att = EvaluationAttempt(
        attempt_id=job.attempt_id,  # type: ignore[arg-type]
        job_id="wrong_job_id",
        fence=999,
        outcome="accept",
        evaluation_validity="valid",
        error_code=None,
        disposition="authoritative",
        started_at=datetime.fromtimestamp(1.0, UTC),
        finished_at=datetime.fromtimestamp(2.0, UTC),
        exit_code=0,
        stdout_hash=None,
        stderr_hash=None,
        report_digest=None,
        test_collection=(),
        tests_passed=1,
        tests_failed=0,
        resources=ResourceUsage(None, None, None, None, None, None, None, None),
        artifact_digests=(),
        capture_truncated=False,
    )
    with pytest.raises(IdentityConflict):
        complete(conn, job, att, now_ms=2000)
