"""Execution job primitives and SQLite fenced queue operations.

SDD Section 7.1:
Implements deterministic, lease-fenced queue transitions:
- Atomic claims with fence generation increment and secret lease tokens.
- Transition to RUNNING state under live lease.
- Heartbeat renewal extending lease_expires_ms by 30,000 ms.
- Safe completion:
    * Committed as authoritative if fence, token, and unexpired lease match.
    * Stale if lease expired or fence mismatched.
    * Duplicate if identical completed attempt already selected.
    * IdentityConflict if conflicting attempt content for already-selected attempt.
- Reaper transitioning expired claims to abandoned and requeuing up to max_attempts.
- Run cancellation marking pending jobs as FAILED.
"""

from __future__ import annotations

import json
import secrets
import sqlite3
import time
import uuid
from datetime import UTC, datetime
from typing import Literal

from verifierci.errors import (
    ErrorCode,
    IdentityConflict,
    InfrastructureError,
    LeaseLost,
)
from verifierci.models.protocol import Job
from verifierci.models.result import EvaluationAttempt
from verifierci.storage.db import transaction

DEFAULT_LEASE_MS = 30_000  # 30 seconds default lease per SDD Section 7.1
MAX_ATTEMPTS = 3  # Maximum physical attempts before terminal failure


def _row_to_job(row: sqlite3.Row) -> Job:
    return Job(
        job_id=row["job_id"],
        run_id=row["run_id"],
        task_key=row["task_key"],
        case_id=row["case_id"],
        verifier_key=row["verifier_key"],
        repetition=row["repetition"],
        state=row["state"],
        fence=row["fence"],
        attempt_id=row["attempt_id"],
        lease_token=row["lease_token"],
        worker_id=row["worker_id"],
        lease_expires_ms=row["lease_expires_ms"],
        attempts_started=row["attempts_started"],
        selected_attempt_id=row["selected_attempt_id"],
        terminal_reason=row["terminal_reason"],
    )


def _mark_attempt_stale(
    conn: sqlite3.Connection,
    attempt_id: str | None,
    now_ms: int,
) -> None:
    if not attempt_id:
        return
    now_iso = datetime.fromtimestamp(now_ms / 1000.0, UTC).isoformat()
    conn.execute(
        """
        UPDATE evaluation_attempts
        SET disposition = 'stale',
            evaluation_validity = 'invalid',
            outcome = NULL,
            finished_at = ?
        WHERE attempt_id = ? AND disposition = 'active'
        """,
        (now_iso, attempt_id),
    )


def get_job(conn: sqlite3.Connection, job_id: str) -> Job | None:
    """Query a Job by its job_id."""
    row = conn.execute(
        """
        SELECT job_id, run_id, task_key, case_id, verifier_key, repetition,
               state, fence, attempt_id, lease_token, worker_id,
               lease_expires_ms, attempts_started, selected_attempt_id,
               terminal_reason
        FROM jobs
        WHERE job_id = ?
        """,
        (job_id,),
    ).fetchone()
    if row is None:
        return None
    return _row_to_job(row)


def _update_run_state(conn: sqlite3.Connection, run_id: str, now_ms: int) -> None:
    """Update parent audit_run state atomically based on jobs completion."""
    run_row = conn.execute(
        "SELECT state, cancel_requested FROM audit_runs WHERE run_id = ?", (run_id,)
    ).fetchone()
    if not run_row or run_row["state"] in ("COMPLETE", "CANCELLED", "FAILED"):
        return

    stats = conn.execute(
        """
        SELECT 
            COUNT(CASE WHEN state NOT IN ('DONE', 'FAILED', 'ABANDONED') THEN 1 END) as active_count,
            COUNT(CASE WHEN state = 'FAILED' THEN 1 END) as fail_count
        FROM jobs WHERE run_id = ?
        """,
        (run_id,),
    ).fetchone()

    active_count = stats["active_count"] or 0
    fail_count = stats["fail_count"] or 0

    if active_count > 0:
        if run_row["state"] == "PLANNED":
            conn.execute(
                "UPDATE audit_runs SET state = 'RUNNING' WHERE run_id = ?", (run_id,)
            )
        return

    finished_at_iso = datetime.fromtimestamp(now_ms / 1000.0, UTC).isoformat()
    if run_row["cancel_requested"]:
        new_state = "CANCELLED"
    elif fail_count > 0:
        new_state = "FAILED"
    else:
        new_state = "COMPLETE"

    conn.execute(
        "UPDATE audit_runs SET state = ?, finished_at = ? WHERE run_id = ?",
        (new_state, finished_at_iso, run_id),
    )


def claim(
    conn: sqlite3.Connection,
    worker_id: str,
    now_ms: int,
    *,
    run_id: str | None = None,
    lease_duration_ms: int = DEFAULT_LEASE_MS,
) -> Job | None:
    """Atomically claim the next eligible PENDING job using BEGIN IMMEDIATE.

    Increments the fence, generates a private random lease token, records an
    active pending evaluation attempt, and returns the claimed Job.
    """
    with transaction(conn, immediate=True):
        while True:
            if run_id is not None:
                query = """
                    SELECT job_id, run_id, task_key, case_id, verifier_key, repetition,
                           state, fence, attempts_started
                    FROM jobs
                    WHERE state = 'PENDING' AND run_id = ?
                    ORDER BY job_id ASC
                    LIMIT 1
                """
                row = conn.execute(query, (run_id,)).fetchone()
            else:
                query = """
                    SELECT job_id, run_id, task_key, case_id, verifier_key, repetition,
                           state, fence, attempts_started
                    FROM jobs
                    WHERE state = 'PENDING'
                    ORDER BY job_id ASC
                    LIMIT 1
                """
                row = conn.execute(query).fetchone()

            if row is None:
                return None

            job_id = row["job_id"]
            parent_run_id = row["run_id"]

            # Check if parent run has cancellation requested
            run_row = conn.execute(
                "SELECT cancel_requested FROM audit_runs WHERE run_id = ?",
                (parent_run_id,),
            ).fetchone()
            if run_row and run_row["cancel_requested"]:
                conn.execute(
                    """
                    UPDATE jobs
                    SET state = 'FAILED',
                        terminal_reason = 'CANCELLED'
                    WHERE run_id = ? AND state = 'PENDING'
                    """,
                    (parent_run_id,),
                )
                continue

            new_attempt_id = str(uuid.uuid4())
            new_fence = row["fence"] + 1
            new_lease_token = secrets.token_hex(16)
            new_lease_expires_ms = now_ms + lease_duration_ms
            new_attempts_started = row["attempts_started"] + 1

            cursor = conn.execute(
                """
                UPDATE jobs
                SET state = 'CLAIMED',
                    fence = ?,
                    attempt_id = ?,
                    lease_token = ?,
                    worker_id = ?,
                    lease_expires_ms = ?,
                    attempts_started = ?
                WHERE job_id = ? AND state = 'PENDING'
                """,
                (
                    new_fence,
                    new_attempt_id,
                    new_lease_token,
                    worker_id,
                    new_lease_expires_ms,
                    new_attempts_started,
                    job_id,
                ),
            )
            if cursor.rowcount == 0:
                # Another worker raced and claimed this job
                continue

            started_at_iso = datetime.fromtimestamp(now_ms / 1000.0, UTC).isoformat()
            conn.execute(
                """
                INSERT INTO evaluation_attempts (
                    attempt_id, job_id, fence, outcome, evaluation_validity,
                    error_code, disposition, started_at, finished_at,
                    exit_code, stdout_hash, stderr_hash, report_digest,
                    test_collection, tests_passed, tests_failed, resources,
                    artifact_digests, capture_truncated
                ) VALUES (
                    ?, ?, ?, NULL, 'pending',
                    NULL, 'active', ?, NULL,
                    NULL, NULL, NULL, NULL,
                    '[]', NULL, NULL, '{}',
                    '[]', 0
                )
                """,
                (new_attempt_id, job_id, new_fence, started_at_iso),
            )

            _update_run_state(conn, parent_run_id, now_ms)

            return Job(
                job_id=job_id,
                run_id=parent_run_id,
                task_key=row["task_key"],
                case_id=row["case_id"],
                verifier_key=row["verifier_key"],
                repetition=row["repetition"],
                state="CLAIMED",
                fence=new_fence,
                attempt_id=new_attempt_id,
                lease_token=new_lease_token,
                worker_id=worker_id,
                lease_expires_ms=new_lease_expires_ms,
                attempts_started=new_attempts_started,
                selected_attempt_id=None,
                terminal_reason=None,
            )


def mark_running(conn: sqlite3.Connection, job: Job, now_ms: int) -> Job:
    """Transition a CLAIMED job to RUNNING under live lease and matching fence."""
    with transaction(conn, immediate=True):
        row = conn.execute(
            """
            SELECT state, fence, lease_token, worker_id, lease_expires_ms,
                   attempt_id, attempts_started, selected_attempt_id, terminal_reason
            FROM jobs WHERE job_id = ?
            """,
            (job.job_id,),
        ).fetchone()

        if row is None:
            raise LeaseLost(
                f"Job '{job.job_id}' not found.",
                code=ErrorCode.LEASE_LOST.value,
            )

        if row["fence"] != job.fence or row["lease_token"] != job.lease_token:
            raise LeaseLost(
                f"Fence or lease token mismatch for job '{job.job_id}'.",
                code=ErrorCode.LEASE_LOST.value,
            )

        if row["lease_expires_ms"] is None or row["lease_expires_ms"] <= now_ms:
            raise LeaseLost(
                f"Lease expired for job '{job.job_id}' ({row['lease_expires_ms']} <= {now_ms}).",
                code=ErrorCode.LEASE_LOST.value,
            )

        if row["state"] not in ("CLAIMED", "RUNNING"):
            raise LeaseLost(
                f"Job '{job.job_id}' is in unexpected state '{row['state']}'.",
                code=ErrorCode.LEASE_LOST.value,
            )

        if row["state"] == "CLAIMED":
            conn.execute(
                "UPDATE jobs SET state = 'RUNNING' WHERE job_id = ?",
                (job.job_id,),
            )

        return Job(
            job_id=job.job_id,
            run_id=job.run_id,
            task_key=job.task_key,
            case_id=job.case_id,
            verifier_key=job.verifier_key,
            repetition=job.repetition,
            state="RUNNING",
            fence=job.fence,
            attempt_id=job.attempt_id,
            lease_token=job.lease_token,
            worker_id=job.worker_id,
            lease_expires_ms=row["lease_expires_ms"],
            attempts_started=row["attempts_started"],
            selected_attempt_id=row["selected_attempt_id"],
            terminal_reason=row["terminal_reason"],
        )


def heartbeat(
    conn: sqlite3.Connection,
    job: Job,
    now_ms: int,
    *,
    extension_ms: int = DEFAULT_LEASE_MS,
) -> Job:
    """Extend lease of a CLAIMED or RUNNING job by extension_ms if lease is currently valid."""
    with transaction(conn, immediate=True):
        row = conn.execute(
            """
            SELECT state, fence, lease_token, lease_expires_ms, worker_id,
                   attempts_started, selected_attempt_id, terminal_reason
            FROM jobs WHERE job_id = ?
            """,
            (job.job_id,),
        ).fetchone()

        if row is None:
            raise LeaseLost(
                f"Job '{job.job_id}' not found.",
                code=ErrorCode.LEASE_LOST.value,
            )

        if row["fence"] != job.fence or row["lease_token"] != job.lease_token:
            raise LeaseLost(
                f"Fence or lease token mismatch for job '{job.job_id}'.",
                code=ErrorCode.LEASE_LOST.value,
            )

        if row["lease_expires_ms"] is None or row["lease_expires_ms"] <= now_ms:
            raise LeaseLost(
                f"Lease expired for job '{job.job_id}' ({row['lease_expires_ms']} <= {now_ms}).",
                code=ErrorCode.LEASE_LOST.value,
            )

        if row["state"] not in ("CLAIMED", "RUNNING"):
            raise LeaseLost(
                f"Cannot heartbeat non-active job '{job.job_id}' in state '{row['state']}'.",
                code=ErrorCode.LEASE_LOST.value,
            )

        new_expires_ms = now_ms + extension_ms
        conn.execute(
            "UPDATE jobs SET lease_expires_ms = ? WHERE job_id = ?",
            (new_expires_ms, job.job_id),
        )

        return Job(
            job_id=job.job_id,
            run_id=job.run_id,
            task_key=job.task_key,
            case_id=job.case_id,
            verifier_key=job.verifier_key,
            repetition=job.repetition,
            state=row["state"],
            fence=job.fence,
            attempt_id=job.attempt_id,
            lease_token=job.lease_token,
            worker_id=row["worker_id"],
            lease_expires_ms=new_expires_ms,
            attempts_started=row["attempts_started"],
            selected_attempt_id=row["selected_attempt_id"],
            terminal_reason=row["terminal_reason"],
        )


def complete(
    conn: sqlite3.Connection,
    job: Job,
    attempt: EvaluationAttempt,
    now_ms: int,
) -> Literal["committed", "duplicate", "stale"]:
    """Attempt to commit an evaluation attempt as authoritative for a job.

    Returns:
      - 'committed': Attempt accepted as authoritative; job marked terminal.
      - 'duplicate': Job already terminal with this identical attempt.
      - 'stale': Job already terminal with different attempt, or worker lost lease/fence.
    Raises:
      - IdentityConflict: Job already terminal with this attempt_id but conflicting data.
      - InfrastructureError: Job not found or database failure.
    """
    with transaction(conn, immediate=True):
        row = conn.execute(
            """
            SELECT state, fence, lease_token, lease_expires_ms, selected_attempt_id, terminal_reason
            FROM jobs WHERE job_id = ?
            """,
            (job.job_id,),
        ).fetchone()

        if row is None:
            raise InfrastructureError(
                f"Job '{job.job_id}' not found.",
                code=ErrorCode.INFRASTRUCTURE_ERROR.value,
            )

        # Case 1: Job is already terminal
        if row["state"] in ("DONE", "FAILED", "ABANDONED"):
            if row["selected_attempt_id"] == attempt.attempt_id:
                att_row = conn.execute(
                    """
                    SELECT outcome, evaluation_validity, error_code, exit_code, stdout_hash,
                           stderr_hash, report_digest, test_collection, tests_passed, tests_failed,
                           resources, artifact_digests, capture_truncated
                    FROM evaluation_attempts WHERE attempt_id = ?
                    """,
                    (attempt.attempt_id,),
                ).fetchone()
                if att_row is not None:
                    db_test_coll = (
                        tuple(json.loads(att_row["test_collection"]))
                        if att_row["test_collection"]
                        else ()
                    )
                    db_artifacts = (
                        tuple(json.loads(att_row["artifact_digests"]))
                        if att_row["artifact_digests"]
                        else ()
                    )
                    db_resources = (
                        json.loads(att_row["resources"]) if att_row["resources"] else {}
                    )

                    att_resources = {
                        "duration": attempt.resources.duration,
                        "allocated_cpu": attempt.resources.allocated_cpu,
                        "cpu_seconds": attempt.resources.cpu_seconds,
                        "peak_memory": attempt.resources.peak_memory,
                        "model_usage": dict(attempt.resources.model_usage)
                        if attempt.resources.model_usage
                        else None,
                        "estimated_cost": attempt.resources.estimated_cost,
                        "pricing_version": attempt.resources.pricing_version,
                        "bytes_written": attempt.resources.bytes_written,
                    }

                    matches = (
                        att_row["outcome"] == attempt.outcome
                        and att_row["evaluation_validity"]
                        == attempt.evaluation_validity
                        and att_row["error_code"] == attempt.error_code
                        and att_row["exit_code"] == attempt.exit_code
                        and att_row["stdout_hash"] == attempt.stdout_hash
                        and att_row["stderr_hash"] == attempt.stderr_hash
                        and att_row["report_digest"] == attempt.report_digest
                        and db_test_coll == tuple(attempt.test_collection)
                        and att_row["tests_passed"] == attempt.tests_passed
                        and att_row["tests_failed"] == attempt.tests_failed
                        and db_resources == att_resources
                        and db_artifacts == tuple(attempt.artifact_digests)
                        and bool(att_row["capture_truncated"])
                        == bool(attempt.capture_truncated)
                    )
                    if matches:
                        return "duplicate"
                    else:
                        raise IdentityConflict(
                            f"Conflicting attempt content for already-selected attempt '{attempt.attempt_id}'.",
                            code=ErrorCode.IDENTITY_CONFLICT.value,
                        )
                return "duplicate"
            else:
                _mark_attempt_stale(conn, attempt.attempt_id, now_ms)
                return "stale"

        # Case 2: Lease expired or fence/token mismatch
        lease_expired = (
            row["lease_expires_ms"] is None or row["lease_expires_ms"] <= now_ms
        )
        fence_mismatch = (
            row["fence"] != job.fence or row["lease_token"] != job.lease_token
        )

        if lease_expired or fence_mismatch:
            _mark_attempt_stale(conn, attempt.attempt_id, now_ms)
            return "stale"

        # Case 3: Live lease, fence & token match -> commit as authoritative
        att_check = conn.execute(
            "SELECT job_id, fence FROM evaluation_attempts WHERE attempt_id = ?",
            (attempt.attempt_id,),
        ).fetchone()
        if (
            att_check is None
            or att_check["job_id"] != job.job_id
            or att_check["fence"] != job.fence
            or attempt.job_id != job.job_id
            or attempt.fence != job.fence
        ):
            raise IdentityConflict(
                f"Attempt '{attempt.attempt_id}' does not match job '{job.job_id}' with fence {job.fence}.",
                code=ErrorCode.IDENTITY_CONFLICT.value,
            )
        finished_at_iso = (
            attempt.finished_at.isoformat()
            if attempt.finished_at is not None
            else datetime.fromtimestamp(now_ms / 1000.0, UTC).isoformat()
        )

        test_coll_json = json.dumps(list(attempt.test_collection))
        resources_json = json.dumps(
            {
                "duration": attempt.resources.duration,
                "allocated_cpu": attempt.resources.allocated_cpu,
                "cpu_seconds": attempt.resources.cpu_seconds,
                "peak_memory": attempt.resources.peak_memory,
                "model_usage": dict(attempt.resources.model_usage)
                if attempt.resources.model_usage
                else None,
                "estimated_cost": attempt.resources.estimated_cost,
                "pricing_version": attempt.resources.pricing_version,
                "bytes_written": attempt.resources.bytes_written,
            }
        )
        artifact_digests_json = json.dumps(list(attempt.artifact_digests))
        capture_truncated_int = 1 if attempt.capture_truncated else 0

        conn.execute(
            """
            UPDATE evaluation_attempts SET
                outcome = ?,
                evaluation_validity = ?,
                error_code = ?,
                disposition = 'authoritative',
                finished_at = ?,
                exit_code = ?,
                stdout_hash = ?,
                stderr_hash = ?,
                report_digest = ?,
                test_collection = ?,
                tests_passed = ?,
                tests_failed = ?,
                resources = ?,
                artifact_digests = ?,
                capture_truncated = ?
            WHERE attempt_id = ?
            """,
            (
                attempt.outcome,
                attempt.evaluation_validity,
                attempt.error_code,
                finished_at_iso,
                attempt.exit_code,
                attempt.stdout_hash,
                attempt.stderr_hash,
                attempt.report_digest,
                test_coll_json,
                attempt.tests_passed,
                attempt.tests_failed,
                resources_json,
                artifact_digests_json,
                capture_truncated_int,
                attempt.attempt_id,
            ),
        )

        if attempt.outcome == "error":
            terminal_state = "FAILED"
            terminal_reason = attempt.error_code or "EVALUATION_ERROR"
        else:
            terminal_state = "DONE"
            terminal_reason = None

        conn.execute(
            """
            UPDATE jobs SET
                state = ?,
                selected_attempt_id = ?,
                lease_token = NULL,
                worker_id = NULL,
                lease_expires_ms = NULL,
                terminal_reason = ?
            WHERE job_id = ?
            """,
            (terminal_state, attempt.attempt_id, terminal_reason, job.job_id),
        )

        _update_run_state(conn, job.run_id, now_ms)

        return "committed"


def reap_expired(
    conn: sqlite3.Connection,
    now_ms: int,
    *,
    max_attempts: int = MAX_ATTEMPTS,
) -> tuple[str, ...]:
    """Reap active jobs whose lease has expired.

    Marks the active attempt as abandoned.
    If attempts_started < max_attempts, requeues job to PENDING.
    Else, transitions job to FAILED with terminal_reason='LEASE_EXPIRED'.

    Returns tuple of reaped job_ids.
    """
    with transaction(conn, immediate=True):
        rows = conn.execute(
            """
            SELECT job_id, attempt_id, attempts_started
            SELECT job_id, run_id, attempt_id, attempts_started
            FROM jobs
            WHERE state IN ('CLAIMED', 'RUNNING')
              AND lease_expires_ms IS NOT NULL
              AND lease_expires_ms <= ?
            ORDER BY job_id ASC
            """,
            (now_ms,),
        ).fetchall()

        now_iso = datetime.fromtimestamp(now_ms / 1000.0, UTC).isoformat()
        reaped: list[str] = []
        affected_runs: set[str] = set()

        for row in rows:
            job_id = row["job_id"]
            run_id = row["run_id"]
            attempt_id = row["attempt_id"]
            attempts_started = row["attempts_started"]

            affected_runs.add(run_id)

            if attempt_id:
                conn.execute(
                    """
                    UPDATE evaluation_attempts
                    SET disposition = 'abandoned',
                        evaluation_validity = 'invalid',
                        outcome = NULL,
                        finished_at = ?
                    WHERE attempt_id = ? AND disposition = 'active'
                    """,
                    (now_iso, attempt_id),
                )

            if attempts_started < max_attempts:
                conn.execute(
                    """
                    UPDATE jobs SET
                        state = 'PENDING',
                        attempt_id = NULL,
                        lease_token = NULL,
                        worker_id = NULL,
                        lease_expires_ms = NULL,
                        terminal_reason = NULL
                    WHERE job_id = ?
                    """,
                    (job_id,),
                )
            else:
                conn.execute(
                    """
                    UPDATE jobs SET
                        state = 'FAILED',
                        attempt_id = NULL,
                        lease_token = NULL,
                        worker_id = NULL,
                        lease_expires_ms = NULL,
                        terminal_reason = 'LEASE_EXPIRED'
                    WHERE job_id = ?
                    """,
                    (job_id,),
                )

            reaped.append(job_id)

        for run_id in affected_runs:
            _update_run_state(conn, run_id, now_ms)

        return tuple(reaped)


def request_cancel(conn: sqlite3.Connection, run_id: str) -> None:
    """Request cancellation for an audit run and fail any pending jobs."""
    with transaction(conn, immediate=True):
        conn.execute(
            "UPDATE audit_runs SET cancel_requested = 1 WHERE run_id = ?",
            (run_id,),
        )
        conn.execute(
            """
            UPDATE jobs SET
                state = 'FAILED',
                terminal_reason = 'CANCELLED'
            WHERE run_id = ? AND state = 'PENDING'
            """,
            (run_id,),
        )

        _update_run_state(conn, run_id, int(time.time() * 1000))
