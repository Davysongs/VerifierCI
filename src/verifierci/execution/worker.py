"""verifierci.execution.worker — Python execution worker (Phase 1).

SDD Section 7.1 and 7.5.
A single worker process claims one job, renews its lease on a background timer,
supervises subprocesses inside the sandbox, captures outputs into the artifact
store, parses outcomes according to Section 7.5 precedence, and commits the
attempt through the fenced queue.

Responsibilities:
- Claim one job with BEGIN IMMEDIATE.
- Renew the lease on a background timer.
- Supervise execution subprocesses inside the sandbox.
- Own cleanup in finally; a controller-side reaper handles worker death.
- After lease loss: terminate execution and submit only stale diagnostic
  evidence, never an authoritative result.
"""

from __future__ import annotations

import dataclasses
import json
import sqlite3
import tempfile
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from verifierci.errors import (
    ErrorCode,
    InfrastructureError,
    LeaseLost,
    ValidationError,
    VerifierCIError,
)
from verifierci.execution import jobs
from verifierci.execution.outcomes import parse_capture
from verifierci.execution.sandbox import cleanup_attempt, execute, prepare_workspace
from verifierci.models.protocol import ExecutionCapture, ResourceUsage
from verifierci.models.result import Artifact, EvaluationAttempt
from verifierci.models.verifier import VerifierManifest, resolve_command
from verifierci.storage.artifacts import ArtifactStore

DEFAULT_LEASE_MS = 30_000


def _register_artifact(conn: sqlite3.Connection, art: Artifact) -> None:
    """Register artifact in SQLite artifacts table if not already present."""
    conn.execute(
        """
        INSERT INTO artifacts (
            digest, kind, size_bytes, storage_uri, media_type, access_policy, available, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, 1, ?)
        ON CONFLICT(digest) DO UPDATE SET available = 1
        """,
        (
            art.digest,
            art.kind,
            art.size_bytes,
            art.storage_uri,
            art.media_type,
            art.access_policy,
            art.created_at.isoformat(),
        ),
    )


class Worker:
    """Single-job execution worker.

    Claims one job, executes it inside the declared sandbox, collects
    bounded artifacts and commits the attempt result through the lease fence.
    """

    def __init__(
        self,
        *,
        worker_id: str | None = None,
        artifact_store: ArtifactStore | None = None,
        work_dir: Path | str | None = None,
        snapshot_resolver: Callable[[str], Path] | Mapping[str, Path] | None = None,
        diff_resolver: (Callable[[str], bytes] | Mapping[str, bytes] | None) = None,
        manifest_resolver: (
            Callable[[str], VerifierManifest] | Mapping[str, VerifierManifest] | None
        ) = None,
        lease_duration_ms: int = DEFAULT_LEASE_MS,
        heartbeat_interval_seconds: float = 5.0,
    ) -> None:
        self.worker_id = worker_id or str(uuid.uuid4())
        self.work_dir = (
            Path(work_dir)
            if work_dir
            else Path(tempfile.gettempdir()) / "verifierci_worker"
        )
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.artifact_store = artifact_store or ArtifactStore(
            self.work_dir / "artifacts"
        )
        self.snapshot_resolver = snapshot_resolver
        self.diff_resolver = diff_resolver
        self.manifest_resolver = manifest_resolver
        self.lease_duration_ms = lease_duration_ms
        self.heartbeat_interval_seconds = heartbeat_interval_seconds

    def _resolve_snapshot(self, task_key: str, conn: sqlite3.Connection) -> Path:
        p: Path
        if callable(self.snapshot_resolver):
            p = self.snapshot_resolver(task_key)
        elif (
            isinstance(self.snapshot_resolver, Mapping)
            and task_key in self.snapshot_resolver
        ):
            p = Path(self.snapshot_resolver[task_key])
        else:
            row = conn.execute(
                """
                SELECT s.archive_uri
                FROM repository_snapshots s
                JOIN tasks t ON t.snapshot_digest = s.snapshot_digest
                WHERE t.task_key = ?
                """,
                (task_key,),
            ).fetchone()
            if row and row["archive_uri"]:
                uri = str(row["archive_uri"])
                p = Path(uri[7:]) if uri.startswith("file://") else Path(uri)
            else:
                p = self.work_dir / "snapshots" / task_key

        if not p.is_dir():
            raise ValidationError(
                f"Resolved snapshot directory does not exist: {p}",
                code=ErrorCode.VALIDATION_ERROR.value,
            )
        return p

    def _resolve_diff(self, case_id: str, conn: sqlite3.Connection) -> bytes:
        if callable(self.diff_resolver):
            return self.diff_resolver(case_id)
        if isinstance(self.diff_resolver, Mapping) and case_id in self.diff_resolver:
            val = self.diff_resolver[case_id]
            return val if isinstance(val, bytes) else str(val).encode("utf-8")
        row = conn.execute(
            "SELECT diff_digest FROM patch_cases WHERE case_id = ?",
            (case_id,),
        ).fetchone()
        if row and row["diff_digest"]:
            digest = str(row["diff_digest"])
            if self.artifact_store.exists(digest):
                return self.artifact_store.read_bytes(digest)
            raise ValidationError(
                f"Diff artifact not found in store for digest: {digest}",
                code=ErrorCode.VALIDATION_ERROR.value,
            )
        return b""

    def _resolve_manifest(
        self, verifier_key: str, conn: sqlite3.Connection
    ) -> VerifierManifest:
        manifest: VerifierManifest
        if callable(self.manifest_resolver):
            manifest = self.manifest_resolver(verifier_key)
        elif (
            isinstance(self.manifest_resolver, Mapping)
            and verifier_key in self.manifest_resolver
        ):
            manifest = self.manifest_resolver[verifier_key]
        else:
            row = conn.execute(
                """
                SELECT vm.manifest_hash, vm.mode, vm.command, vm.build_command,
                       vm.expected_collection, vm.parser_id, vm.report_path,
                       vm.payload_digest, vm.allowed_edit_paths, vm.required_pass_ids,
                       vm.permitted_skips, vm.timeout_seconds
                FROM verifier_manifests vm
                JOIN verifier_versions vv ON vv.manifest_hash = vm.manifest_hash
                WHERE vv.verifier_key = ?
                """,
                (verifier_key,),
            ).fetchone()
            if not row:
                raise InfrastructureError(
                    f"Cannot resolve VerifierManifest for verifier_key '{verifier_key}'"
                )
            manifest = VerifierManifest(
                manifest_hash=row["manifest_hash"],
                mode=row["mode"],
                command=tuple(json.loads(row["command"])),
                build_command=tuple(json.loads(row["build_command"]))
                if row["build_command"]
                else (),
                expected_collection=tuple(json.loads(row["expected_collection"]))
                if row["expected_collection"]
                else (),
                parser_id=row["parser_id"],
                report_path=row["report_path"],
                payload_digest=row["payload_digest"],
                allowed_edit_paths=tuple(json.loads(row["allowed_edit_paths"]))
                if row["allowed_edit_paths"]
                else (),
                required_pass_ids=tuple(json.loads(row["required_pass_ids"]))
                if row["required_pass_ids"]
                else (),
                permitted_skips=tuple(json.loads(row["permitted_skips"]))
                if row["permitted_skips"]
                else (),
                timeout_seconds=row["timeout_seconds"],
            )

        rep_p = Path(manifest.report_path)
        if rep_p.is_absolute() or ".." in rep_p.parts:
            raise ValidationError(
                f"Report path in verifier manifest must be relative and cannot escape: {manifest.report_path}",
                code=ErrorCode.VALIDATION_ERROR.value,
            )
        return manifest

    def run_one(
        self,
        conn: sqlite3.Connection,
        *,
        run_id: str | None = None,
        now_ms: int | None = None,
    ) -> bool:
        """Claim, execute, and commit a single job from the queue.

        Returns True if a job was claimed and executed, False if the queue was empty.
        """
        current_time_ms = now_ms if now_ms is not None else int(time.time() * 1000)
        job = jobs.claim(
            conn,
            worker_id=self.worker_id,
            now_ms=current_time_ms,
            run_id=run_id,
            lease_duration_ms=self.lease_duration_ms,
        )
        if job is None:
            return False

        attempt_id = job.attempt_id or str(uuid.uuid4())
        current_job = job

        conn_lock = threading.Lock()
        stop_heartbeat = threading.Event()
        lease_lost = threading.Event()
        hb_thread: threading.Thread | None = None

        def _heartbeat_worker() -> None:
            nonlocal current_job
            while not stop_heartbeat.wait(self.heartbeat_interval_seconds):
                try:
                    hb_time = int(time.time() * 1000)
                    with conn_lock:
                        current_job = jobs.heartbeat(
                            conn,
                            current_job,
                            hb_time,
                            extension_ms=self.lease_duration_ms,
                        )
                except LeaseLost:
                    lease_lost.set()
                    break
                except Exception:  # noqa: BLE001
                    break

        try:
            # 1. Transition job to RUNNING
            with conn_lock:
                current_job = jobs.mark_running(
                    conn, current_job, int(time.time() * 1000)
                )

            # 3. Prepare workspace
            workspace_ready = False
            source_dir = self.work_dir / "attempts" / attempt_id / "source"
            out_dir = self.work_dir / "attempts" / attempt_id / "out"
            capture_dir = self.work_dir / "attempts" / attempt_id / "capture"

            try:
                # 2. Resolve parameters under conn_lock inside preparation try block
                with conn_lock:
                    snapshot_dir = self._resolve_snapshot(current_job.task_key, conn)
                    diff_bytes = self._resolve_diff(current_job.case_id, conn)
                    manifest = self._resolve_manifest(current_job.verifier_key, conn)

                # Start lease heartbeat thread only after transitioning to RUNNING and resolving parameters
                hb_thread = threading.Thread(target=_heartbeat_worker, daemon=True)
                hb_thread.start()

                attempt_dir = prepare_workspace(
                    job=current_job,
                    snapshot_dir=snapshot_dir,
                    diff_bytes=diff_bytes,
                    allowed_paths=manifest.allowed_edit_paths,
                    root=self.work_dir,
                )
                source_dir = attempt_dir / "source"
                out_dir = attempt_dir / "out"
                capture_dir = attempt_dir / "capture"
                workspace_ready = True
            except (ValidationError, VerifierCIError) as val_err:
                err_code = val_err.code or ErrorCode.PATCH_ERROR.value
                capture = ExecutionCapture(
                    attempt_id=attempt_id,
                    exit_code=1,
                    timed_out=False,
                    oom_killed=False,
                    cancelled=False,
                    build_exit_code=None,
                    stdout_hash=None,
                    stderr_hash=None,
                    report_digest=None,
                    truncated=False,
                    resources=ResourceUsage(
                        duration=0.0,
                        allocated_cpu=None,
                        cpu_seconds=None,
                        peak_memory=None,
                        model_usage=None,
                        estimated_cost=None,
                        pricing_version=None,
                        bytes_written=None,
                    ),
                    runtime_error=err_code,
                )
            except Exception as prep_err:  # noqa: BLE001
                capture = ExecutionCapture(
                    attempt_id=attempt_id,
                    exit_code=1,
                    timed_out=False,
                    oom_killed=False,
                    cancelled=False,
                    build_exit_code=None,
                    stdout_hash=None,
                    stderr_hash=None,
                    report_digest=None,
                    truncated=False,
                    resources=ResourceUsage(
                        duration=0.0,
                        allocated_cpu=None,
                        cpu_seconds=None,
                        peak_memory=None,
                        model_usage=None,
                        estimated_cost=None,
                        pricing_version=None,
                        bytes_written=None,
                    ),
                    runtime_error=str(prep_err),
                )

            # 4. If workspace was prepared, execute build and verification
            if workspace_ready:
                paths = {
                    "workspace": str(source_dir),
                    "verifier": str(source_dir),
                    "out": str(out_dir),
                    "seed": "0",
                }

                build_exit_code = None
                if manifest.build_command:
                    build_spec = resolve_command(
                        manifest.build_command,
                        paths,
                        cwd=str(source_dir),
                        timeout_seconds=manifest.timeout_seconds,
                    )
                    b_capture = execute(
                        job=current_job,
                        command=build_spec.argv,
                        workspace=source_dir,
                        out_dir=out_dir,
                        timeout_seconds=manifest.timeout_seconds,
                        env=dict(build_spec.env),
                    )
                    build_exit_code = b_capture.exit_code

                if build_exit_code is not None and build_exit_code != 0:
                    capture = ExecutionCapture(
                        attempt_id=attempt_id,
                        exit_code=build_exit_code,
                        timed_out=False,
                        oom_killed=False,
                        cancelled=False,
                        build_exit_code=build_exit_code,
                        stdout_hash=None,
                        stderr_hash=None,
                        report_digest=None,
                        truncated=False,
                        resources=ResourceUsage(
                            duration=0.0,
                            allocated_cpu=1.0,
                            cpu_seconds=0.0,
                            peak_memory=None,
                            model_usage=None,
                            estimated_cost=None,
                            pricing_version=None,
                            bytes_written=0,
                        ),
                        runtime_error=None,
                    )
                else:
                    cmd_spec = resolve_command(
                        manifest.command,
                        paths,
                        cwd=str(source_dir),
                        timeout_seconds=manifest.timeout_seconds,
                    )
                    capture = execute(
                        job=current_job,
                        command=cmd_spec.argv,
                        workspace=source_dir,
                        out_dir=out_dir,
                        timeout_seconds=manifest.timeout_seconds,
                        env=dict(cmd_spec.env),
                        report_path=manifest.report_path,
                    )

            # Stop heartbeat thread as execution has concluded
            stop_heartbeat.set()
            if hb_thread is not None:
                hb_thread.join(timeout=2.0)

            # 5. Collect outputs & persist artifacts
            stdout_hash = None
            stderr_hash = None
            report_digest = None
            evidence_digests: list[str] = []

            stdout_file = capture_dir / "stdout.log"
            if stdout_file.is_file():
                s_bytes = stdout_file.read_bytes()
                if s_bytes:
                    art = self.artifact_store.put_bytes(
                        s_bytes,
                        max_bytes=16 * 1024 * 1024,
                        kind="stdout",
                        access_policy="restricted",
                    )
                    with conn_lock:
                        _register_artifact(conn, art)
                    stdout_hash = art.digest
                    evidence_digests.append(art.digest)

            stderr_file = capture_dir / "stderr.log"
            if stderr_file.is_file():
                e_bytes = stderr_file.read_bytes()
                if e_bytes:
                    art = self.artifact_store.put_bytes(
                        e_bytes,
                        max_bytes=16 * 1024 * 1024,
                        kind="stderr",
                        access_policy="restricted",
                    )
                    with conn_lock:
                        _register_artifact(conn, art)
                    stderr_hash = art.digest
                    evidence_digests.append(art.digest)

            report_file = out_dir / manifest.report_path
            report_bytes = None
            if report_file.is_file():
                max_report_bytes = 16 * 1024 * 1024
                with report_file.open("rb") as f:
                    report_bytes = f.read(max_report_bytes)
                art = self.artifact_store.put_bytes(
                    report_bytes,
                    max_bytes=16 * 1024 * 1024,
                    kind="report",
                    access_policy="restricted",
                    media_type="application/json",
                )
                with conn_lock:
                    _register_artifact(conn, art)
                report_digest = art.digest
                evidence_digests.append(art.digest)

            # 6. Parse outcome
            capture = dataclasses.replace(
                capture,
                stdout_hash=stdout_hash,
                stderr_hash=stderr_hash,
                report_digest=report_digest,
            )
            parsed_outcome = parse_capture(capture, manifest, report_bytes)

            test_collection: tuple[str, ...] = ()
            tests_passed: int | None = None
            tests_failed: int | None = None
            if parsed_outcome.report is not None:
                test_collection = parsed_outcome.report.collected_ids
                tests_passed = len(
                    [r for r in parsed_outcome.report.results if r.status == "passed"]
                )
                tests_failed = len(
                    [r for r in parsed_outcome.report.results if r.status == "failed"]
                )

            disposition: Literal["active", "authoritative", "stale", "abandoned"] = (
                "stale" if lease_lost.is_set() else "authoritative"
            )

            attempt = EvaluationAttempt(
                attempt_id=attempt_id,
                job_id=current_job.job_id,
                fence=current_job.fence,
                outcome=parsed_outcome.outcome,
                evaluation_validity=parsed_outcome.evaluation_validity,
                error_code=parsed_outcome.error_code,
                disposition=disposition,
                started_at=datetime.now(UTC),
                finished_at=datetime.now(UTC),
                exit_code=capture.exit_code,
                stdout_hash=capture.stdout_hash,
                stderr_hash=capture.stderr_hash,
                report_digest=capture.report_digest,
                test_collection=test_collection,
                tests_passed=tests_passed,
                tests_failed=tests_failed,
                resources=capture.resources,
                artifact_digests=tuple(evidence_digests),
                capture_truncated=capture.truncated,
            )

            # 7. Complete job via fenced queue
            with conn_lock:
                jobs.complete(
                    conn, current_job, attempt, now_ms=int(time.time() * 1000)
                )
            return True

        finally:
            stop_heartbeat.set()
            if hb_thread is not None:
                hb_thread.join(timeout=1.0)
            cleanup_attempt(attempt_id, self.work_dir)

    def run_until_terminal(
        self,
        conn: sqlite3.Connection,
        run_id: str | None = None,
        max_iterations: int = 1000,
    ) -> int:
        """Continuously process jobs until no pending jobs remain."""
        count = 0
        for _ in range(max_iterations):
            claimed = self.run_one(conn, run_id=run_id)
            if not claimed:
                break
            count += 1
        return count
