"""verifierci.execution.service — Phase 1 orchestration for task import and audit execution.

Keeps database persistence, adapter loading, planning, worker execution,
matrix reduction, and report writing cleanly separated from the Click CLI layer
(SDD Section 5: verifierci.cli must contain no SQL or subprocess construction).
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from verifierci.adapters.local import (
    LocalAdapter,
    load_local_verifier_with_bytes,
)
from verifierci.errors import (
    ErrorCode,
    IdentityConflict,
    InfrastructureError,
    ProtectionError,
    ValidationError,
)
from verifierci.execution.matrix import build_matrix
from verifierci.execution.planner import plan_audit
from verifierci.execution.worker import Worker
from verifierci.models.protocol import (
    AuditOptions,
    AuditResult,
    ImportBundle,
    ImportRequest,
    Job,
    ResourceUsage,
    TaskPin,
)
from verifierci.models.result import Artifact, EvaluationAttempt
from verifierci.models.task import canonical_repr
from verifierci.models.verifier import VerifierManifest
from verifierci.panels.registry import PanelValidationResult, load_and_validate_panel
from verifierci.reports.render import render_json, render_summary
from verifierci.snapshots.registry import SnapshotRegistry
from verifierci.storage.artifacts import ArtifactStore, register_artifact
from verifierci.storage.db import connect, migrate, transaction


def _atomic_write_text(destination: Path, text: str) -> None:
    if destination.is_symlink() or os.path.islink(destination):
        raise ProtectionError(
            f"Refusing to write through symlink destination: {destination}",
            code=ErrorCode.PROTECTION_ERROR.value,
        )
    tmp_path: Path | None = None
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_str = tempfile.mkstemp(
            dir=destination.parent, prefix=f".{destination.name}.", suffix=".tmp"
        )
        tmp_path = Path(tmp_str)
        try:
            f = os.fdopen(fd, "w", encoding="utf-8")
        except Exception:
            os.close(fd)
            raise
        with f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, destination)
    except OSError as exc:
        raise InfrastructureError(
            f"Failed to write output file {destination}: {exc}",
            code=ErrorCode.INFRASTRUCTURE_ERROR.value,
        ) from exc
    finally:
        if tmp_path is not None and tmp_path.exists():
            tmp_path.unlink(missing_ok=True)


def _persist_bundle_records(
    conn: sqlite3.Connection,
    artifact_store: ArtifactStore,
    bundle: ImportBundle,
    verifier_payload_bytes: bytes | None = None,
) -> None:
    """Persist an ImportBundle and its immutable records transactionally."""
    # Register upstream artifact & snapshot artifact
    register_artifact(conn, bundle.upstream_artifact)

    snap_art = Artifact(
        digest=bundle.snapshot.snapshot_digest,
        kind="snapshot",
        size_bytes=0,
        storage_uri=bundle.snapshot.archive_uri,
        media_type="inode/directory",
        access_policy="public",
        retention_until=None,
        available=True,
        created_at=bundle.snapshot.created_at,
    )
    register_artifact(conn, snap_art)

    if verifier_payload_bytes is not None:
        ver_art = artifact_store.put_bytes(
            verifier_payload_bytes,
            max_bytes=2 * 1024 * 1024,
            kind="manifest",
            access_policy="public",
            media_type="application/yaml",
            conn=conn,
        )
        if ver_art.digest != bundle.verifier_manifest.payload_digest:
            raise IdentityConflict(
                "Verifier payload bytes digest mismatch against VerifierManifest.",
                code=ErrorCode.IDENTITY_CONFLICT.value,
            )
    else:
        existing_ver_art = conn.execute(
            "SELECT digest, size_bytes FROM artifacts WHERE digest = ?",
            (bundle.verifier_manifest.payload_digest,),
        ).fetchone()
        if existing_ver_art is None:
            raise InfrastructureError(
                f"Verifier payload bytes not supplied and artifact '{bundle.verifier_manifest.payload_digest}' "
                "is missing from store.",
                code=ErrorCode.INFRASTRUCTURE_ERROR.value,
            )

    env = bundle.environment
    existing_env = conn.execute(
        """
        SELECT backend, image_digest, platform, recipe_digest, lock_digests,
               service_manifests, resource_policy_hash, runtime_fingerprint, mirror_uris
        FROM environments WHERE environment_id = ?
        """,
        (env.environment_id,),
    ).fetchone()
    if existing_env is None:
        conn.execute(
            """
            INSERT INTO environments (
                environment_id, backend, image_digest, platform, recipe_digest,
                lock_digests, service_manifests, resource_policy_hash,
                runtime_fingerprint, mirror_uris
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                env.environment_id,
                env.backend,
                env.image_digest,
                env.platform,
                env.recipe_digest,
                json.dumps(list(env.lock_digests)),
                json.dumps(list(env.service_manifests)),
                env.resource_policy_hash,
                env.runtime_fingerprint,
                json.dumps(list(env.mirror_uris)),
            ),
        )
    elif (
        existing_env["backend"] != env.backend
        or existing_env["image_digest"] != env.image_digest
        or existing_env["platform"] != env.platform
        or existing_env["recipe_digest"] != env.recipe_digest
        or json.loads(existing_env["lock_digests"]) != list(env.lock_digests)
        or json.loads(existing_env["service_manifests"]) != list(env.service_manifests)
        or existing_env["resource_policy_hash"] != env.resource_policy_hash
        or existing_env["runtime_fingerprint"] != env.runtime_fingerprint
        or json.loads(existing_env["mirror_uris"]) != list(env.mirror_uris)
    ):
        raise IdentityConflict(
            f"Environment '{env.environment_id}' already exists with conflicting definition.",
            code=ErrorCode.IDENTITY_CONFLICT.value,
        )

    for req in bundle.requirements:
        existing_req = conn.execute(
            "SELECT text FROM requirements WHERE requirement_hash = ?",
            (req.requirement_hash,),
        ).fetchone()
        if existing_req is None:
            conn.execute(
                """
                INSERT INTO requirements (
                    requirement_hash, requirement_id, text, source_kind,
                    evidence_digests, source_locator, allowed_variation
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    req.requirement_hash,
                    req.requirement_id,
                    req.text,
                    req.source_kind,
                    json.dumps(list(req.evidence_digests)),
                    req.source_locator,
                    req.allowed_variation,
                ),
            )
        elif existing_req["text"] != req.text:
            raise IdentityConflict(
                f"Requirement '{req.requirement_hash}' already exists with conflicting text.",
                code=ErrorCode.IDENTITY_CONFLICT.value,
            )

    con = bundle.contract
    existing_con = conn.execute(
        "SELECT contract_hash FROM contracts WHERE contract_hash = ?",
        (con.contract_hash,),
    ).fetchone()
    if existing_con is None:
        conn.execute(
            """
            INSERT INTO contracts (
                contract_hash, task_id, version, requirement_hashes,
                allowed_variation, unresolved_questions, evidence_digests, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                con.contract_hash,
                con.task_id,
                con.version,
                json.dumps(list(con.requirement_hashes)),
                con.allowed_variation,
                json.dumps(list(con.unresolved_questions)),
                json.dumps(list(con.evidence_digests)),
                con.created_at.isoformat(),
            ),
        )
        for req_hash in con.requirement_hashes:
            conn.execute(
                "INSERT OR IGNORE INTO contract_requirements (contract_hash, requirement_hash) VALUES (?, ?)",
                (con.contract_hash, req_hash),
            )

    snap = bundle.snapshot
    existing_snap = conn.execute(
        "SELECT snapshot_digest FROM repository_snapshots WHERE snapshot_digest = ?",
        (snap.snapshot_digest,),
    ).fetchone()
    if existing_snap is None:
        conn.execute(
            """
            INSERT INTO repository_snapshots (
                snapshot_digest, repository_id, commit_oid, archive_uri, tree_digest,
                submodule_digests, lock_digests, licence, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                snap.snapshot_digest,
                snap.repository_id,
                snap.commit_oid,
                snap.archive_uri,
                snap.tree_digest,
                json.dumps(list(snap.submodule_digests)),
                json.dumps(list(snap.lock_digests)),
                snap.licence,
                snap.created_at.isoformat(),
            ),
        )

    task = bundle.task
    existing_task = conn.execute(
        """
        SELECT statement, adapter, contract_hash, snapshot_digest,
               environment_id, licence, provenance, eligibility, notes
        FROM tasks WHERE task_key = ?
        """,
        (task.task_key,),
    ).fetchone()
    if existing_task is None:
        conn.execute(
            """
            INSERT INTO tasks (
                task_key, task_id, version, statement, adapter, contract_hash,
                snapshot_digest, environment_id, licence, provenance, eligibility,
                notes, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                task.task_key,
                task.task_id,
                task.version,
                task.statement,
                task.adapter,
                task.contract_hash,
                task.snapshot_digest,
                task.environment_id,
                task.licence,
                task.provenance,
                task.eligibility,
                task.notes,
                task.created_at.isoformat(),
            ),
        )
    elif (
        existing_task["contract_hash"] != task.contract_hash
        or existing_task["snapshot_digest"] != task.snapshot_digest
        or existing_task["environment_id"] != task.environment_id
        or existing_task["statement"] != task.statement
        or existing_task["adapter"] != task.adapter
        or existing_task["licence"] != task.licence
        or existing_task["provenance"] != task.provenance
        or existing_task["eligibility"] != task.eligibility
    ):
        raise IdentityConflict(
            f"Task '{task.task_key}' already exists with conflicting immutable definition or eligibility.",
            code=ErrorCode.IDENTITY_CONFLICT.value,
        )

    _persist_verifier(conn, bundle.verifier, bundle.verifier_manifest)


def _persist_verifier(
    conn: sqlite3.Connection,
    verifier_version: Any,
    verifier_manifest: VerifierManifest,
) -> None:
    existing_vm = conn.execute(
        "SELECT manifest_hash FROM verifier_manifests WHERE manifest_hash = ?",
        (verifier_manifest.manifest_hash,),
    ).fetchone()
    if existing_vm is None:
        conn.execute(
            """
            INSERT INTO verifier_manifests (
                manifest_hash, mode, command, build_command, expected_collection,
                parser_id, report_path, payload_digest, allowed_edit_paths,
                required_pass_ids, permitted_skips, timeout_seconds
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                verifier_manifest.manifest_hash,
                verifier_manifest.mode,
                json.dumps(list(verifier_manifest.command)),
                json.dumps(list(verifier_manifest.build_command)),
                json.dumps(list(verifier_manifest.expected_collection)),
                verifier_manifest.parser_id,
                verifier_manifest.report_path,
                verifier_manifest.payload_digest,
                json.dumps(list(verifier_manifest.allowed_edit_paths)),
                json.dumps(list(verifier_manifest.required_pass_ids)),
                json.dumps(list(verifier_manifest.permitted_skips)),
                verifier_manifest.timeout_seconds,
            ),
        )

    existing_vv = conn.execute(
        """
        SELECT manifest_hash, payload_digest, parent_key, compatible_contract_hashes
        FROM verifier_versions WHERE verifier_key = ?
        """,
        (verifier_version.verifier_key,),
    ).fetchone()
    if existing_vv is None:
        conn.execute(
            """
            INSERT INTO verifier_versions (
                verifier_key, verifier_id, version, parent_key, manifest_hash,
                payload_digest, compatible_contract_hashes, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                verifier_version.verifier_key,
                verifier_version.verifier_id,
                verifier_version.version,
                verifier_version.parent_key,
                verifier_version.manifest_hash,
                verifier_version.payload_digest,
                json.dumps(list(verifier_version.compatible_contract_hashes)),
                verifier_version.created_at.isoformat(),
            ),
        )
    else:
        existing_compat = set(json.loads(existing_vv["compatible_contract_hashes"]))
        requested_compat = set(verifier_version.compatible_contract_hashes)
        if (
            existing_vv["manifest_hash"] != verifier_version.manifest_hash
            or existing_vv["payload_digest"] != verifier_version.payload_digest
            or existing_vv["parent_key"] != verifier_version.parent_key
            or not requested_compat.issubset(existing_compat)
        ):
            raise IdentityConflict(
                f"Verifier '{verifier_version.verifier_key}' already exists with conflicting manifest or "
                "incompatible contract hashes (verifier_versions is immutable).",
                code=ErrorCode.IDENTITY_CONFLICT.value,
            )


def import_task_command(
    request: ImportRequest,
    *,
    db_path: Path,
    artifact_dir: Path,
) -> ImportBundle:
    """Import and normalize a task manifest, persisting files & DB state unless dry_run."""
    if request.adapter != "local":
        raise ValidationError(
            f"Adapter '{request.adapter}' is not implemented in Phase 1 (only 'local' is supported).",
            code=ErrorCode.VALIDATION_ERROR.value,
        )

    adapter = LocalAdapter()
    bundle, verifier_bytes = adapter.import_task_with_bytes(request)
    if bundle.task.task_id != request.instance:
        raise ValidationError(
            f"Requested instance '{request.instance}' does not match manifest task_id '{bundle.task.task_id}'.",
            code=ErrorCode.VALIDATION_ERROR.value,
        )

    if request.dry_run:
        return bundle

    # Prepare validated output target path and payloads before persisting to DB
    out_root = Path(request.output_dir)
    if (
        "/" in bundle.task.task_id
        or "\\" in bundle.task.task_id
        or ".." in bundle.task.task_id
        or "/" in bundle.task.version
        or "\\" in bundle.task.version
        or ".." in bundle.task.version
    ):
        raise ProtectionError(
            "Invalid task_id or version path component.",
            code=ErrorCode.PROTECTION_ERROR.value,
        )
    target_dir = out_root / bundle.task.task_id / bundle.task.version
    if not target_dir.resolve().is_relative_to(out_root.resolve()):
        raise ProtectionError(
            "Task output path escapes output directory.",
            code=ErrorCode.PROTECTION_ERROR.value,
        )

    staged_outputs: list[tuple[str, str]] = [
        (
            "task.yaml",
            json.dumps(
                {
                    "schema_version": "1.0.0",
                    "kind": "Task",
                    "data": canonical_repr(bundle.task),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
        ),
        (
            "contract.json",
            json.dumps(
                {
                    "schema_version": "1.0.0",
                    "kind": "Contract",
                    "data": canonical_repr(bundle.contract),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
        ),
        (
            "snapshot-manifest.json",
            json.dumps(
                {
                    "schema_version": "1.0.0",
                    "kind": "RepositorySnapshot",
                    "data": canonical_repr(bundle.snapshot),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
        ),
        (
            "environment.json",
            json.dumps(
                {
                    "schema_version": "1.0.0",
                    "kind": "Environment",
                    "data": canonical_repr(bundle.environment),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
        ),
    ]

    # Persist to SQLite FIRST so conflicts never overwrite accepted outputs
    conn = connect(db_path)
    try:
        migrate(conn, backup=False)
        artifact_store = ArtifactStore(artifact_dir)
        with transaction(conn, immediate=True):
            _persist_bundle_records(
                conn, artifact_store, bundle, verifier_payload_bytes=verifier_bytes
            )
    finally:
        conn.close()

    # Publish normalized outputs atomically only after DB transaction committed
    for filename, content in staged_outputs:
        _atomic_write_text(target_dir / filename, content)

    return bundle


def _load_jobs_and_attempts(
    conn: sqlite3.Connection, run_id: str
) -> tuple[tuple[Job, ...], tuple[EvaluationAttempt, ...]]:
    with transaction(conn, immediate=False):
        job_rows = conn.execute(
            """
            SELECT job_id, run_id, task_key, case_id, verifier_key, repetition,
                   state, fence, attempt_id, lease_token, worker_id, lease_expires_ms,
                   attempts_started, selected_attempt_id, terminal_reason
            FROM jobs WHERE run_id = ? ORDER BY job_id ASC
            """,
            (run_id,),
        ).fetchall()
        att_rows = conn.execute(
            """
            SELECT a.*
            FROM evaluation_attempts a
            JOIN jobs j ON a.job_id = j.job_id
            WHERE j.run_id = ?
            ORDER BY a.attempt_id ASC
            """,
            (run_id,),
        ).fetchall()
    jobs = tuple(
        Job(
            job_id=r["job_id"],
            run_id=r["run_id"],
            task_key=r["task_key"],
            case_id=r["case_id"],
            verifier_key=r["verifier_key"],
            repetition=r["repetition"],
            state=r["state"],
            fence=r["fence"],
            attempt_id=r["attempt_id"],
            lease_token=r["lease_token"],
            worker_id=r["worker_id"],
            lease_expires_ms=r["lease_expires_ms"],
            attempts_started=r["attempts_started"],
            selected_attempt_id=r["selected_attempt_id"],
            terminal_reason=r["terminal_reason"],
        )
        for r in job_rows
    )
    attempts: list[EvaluationAttempt] = []
    for r in att_rows:
        res_data = json.loads(r["resources"])
        attempts.append(
            EvaluationAttempt(
                attempt_id=r["attempt_id"],
                job_id=r["job_id"],
                fence=r["fence"],
                outcome=r["outcome"],
                evaluation_validity=r["evaluation_validity"],
                error_code=r["error_code"],
                disposition=r["disposition"],
                started_at=datetime.fromisoformat(r["started_at"]),
                finished_at=datetime.fromisoformat(r["finished_at"])
                if r["finished_at"]
                else None,
                exit_code=r["exit_code"],
                stdout_hash=r["stdout_hash"],
                stderr_hash=r["stderr_hash"],
                report_digest=r["report_digest"],
                test_collection=tuple(json.loads(r["test_collection"])),
                tests_passed=r["tests_passed"],
                tests_failed=r["tests_failed"],
                resources=ResourceUsage(
                    duration=res_data.get("duration"),
                    allocated_cpu=res_data.get("allocated_cpu"),
                    cpu_seconds=res_data.get("cpu_seconds"),
                    peak_memory=res_data.get("peak_memory"),
                    model_usage=res_data.get("model_usage"),
                    estimated_cost=res_data.get("estimated_cost"),
                    pricing_version=res_data.get("pricing_version"),
                    bytes_written=res_data.get("bytes_written"),
                ),
                artifact_digests=tuple(json.loads(r["artifact_digests"])),
                capture_truncated=bool(r["capture_truncated"]),
            )
        )
    return jobs, tuple(attempts)


def execute_audit_pipeline(
    options: AuditOptions,
    *,
    db_path: Path,
    artifact_dir: Path,
) -> AuditResult:
    """Validate audit options, plan jobs, execute via fixture Worker, and build AuditResult."""
    # Mutual exclusivity & boundary checks (SDD §6.9)
    if options.resume_run_id is not None:
        if options.task_files or options.benchmark_file:
            raise ValidationError(
                "--resume cannot be combined with --task or --benchmark.",
                code=ErrorCode.VALIDATION_ERROR.value,
            )
        raise ValidationError(
            "Resuming stored runs via --resume is not yet supported for standalone execution.",
            code=ErrorCode.VALIDATION_ERROR.value,
        )

    if options.task_files and options.benchmark_file:
        raise ValidationError(
            "--task and --benchmark are mutually exclusive.",
            code=ErrorCode.VALIDATION_ERROR.value,
        )
    if not options.task_files and not options.benchmark_file:
        raise ValidationError(
            "Either --task or --benchmark is required.",
            code=ErrorCode.VALIDATION_ERROR.value,
        )
    if options.benchmark_file:
        raise ValidationError(
            "--benchmark is not yet supported in Phase 1 (use --task).",
            code=ErrorCode.VALIDATION_ERROR.value,
        )

    if len(options.task_files) > 1:
        raise ValidationError(
            "Multiple --task inputs are not supported in a single audit; supply one --task.",
            code=ErrorCode.VALIDATION_ERROR.value,
        )

    if (
        not options.panel_file
        or not options.baseline_file
        or not options.candidate_file
    ):
        raise ValidationError(
            "--panel, --baseline, and --candidate are required for a new audit.",
            code=ErrorCode.VALIDATION_ERROR.value,
        )

    if options.backend not in ("fixture", "docker"):
        raise ValidationError(
            f"Unsupported execution backend: '{options.backend}'. Expected 'fixture' or 'docker'.",
            code=ErrorCode.VALIDATION_ERROR.value,
        )
    if options.backend == "docker":
        raise ValidationError(
            "Docker sandbox backend arrives in Phase 4; pass --backend fixture --trusted-fixture for Phase 1.",
            code=ErrorCode.VALIDATION_ERROR.value,
        )
    if options.backend == "fixture" and not options.trusted_fixture:
        raise ProtectionError(
            "Fixture backend requires explicit --trusted-fixture opt-in.",
            code=ErrorCode.PROTECTION_ERROR.value,
        )

    if not (1 <= options.repetitions <= 30):
        raise ValidationError(
            f"--repetitions must be between 1 and 30, got {options.repetitions}.",
            code=ErrorCode.VALIDATION_ERROR.value,
        )
    if options.repetitions < 3 and not options.diagnostic:
        raise ValidationError(
            "--repetitions < 3 requires --diagnostic mode.",
            code=ErrorCode.VALIDATION_ERROR.value,
        )

    if not options.collect_only and not options.dry_run:
        raise ValidationError(
            "Release gate evaluation arrives in Phase 3; pass --collect-only (or --dry-run) in Phase 1.",
            code=ErrorCode.VALIDATION_ERROR.value,
        )

    # Load tasks, baseline/candidate verifiers, and panel
    adapter = LocalAdapter()
    task_bundle_pairs: list[tuple[ImportBundle, bytes]] = []
    for tf in options.task_files:
        tf_path = Path(tf)
        req = ImportRequest(
            adapter="local",
            instance=tf_path.stem,
            source=str(tf_path),
            source_revision="local-fixture",
            environment_manifest=None,
            output_dir="tasks",
            dry_run=True,
        )
        task_bundle_pairs.append(adapter.import_task_with_bytes(req))

    task_bundles = [b for b, _ in task_bundle_pairs]
    primary_bundle = task_bundles[0]
    baseline_path = Path(options.baseline_file)
    candidate_path = Path(options.candidate_file)
    baseline_ver, baseline_manifest, baseline_bytes = load_local_verifier_with_bytes(
        baseline_path,
        compatible_contract_hashes=(primary_bundle.contract.contract_hash,),
    )
    candidate_ver, candidate_manifest, candidate_bytes = load_local_verifier_with_bytes(
        candidate_path,
        compatible_contract_hashes=(primary_bundle.contract.contract_hash,),
    )

    panel_res: PanelValidationResult = load_and_validate_panel(
        Path(options.panel_file),
        task_key=primary_bundle.task.task_key,
        contract_hash=primary_bundle.contract.contract_hash,
        base_snapshot_digest=primary_bundle.snapshot.snapshot_digest,
        verify_artifacts=not options.dry_run,
    )

    registry = SnapshotRegistry.from_manifests_dir()
    fixture_diagnostics = registry.verify_fixture(
        task_key=primary_bundle.task.task_key,
        contract_hash=primary_bundle.contract.contract_hash,
        snapshot_digest=primary_bundle.snapshot.snapshot_digest,
        panel_key=panel_res.panel.panel_key,
        verifier_digests={
            baseline_ver.verifier_key: (
                baseline_manifest.payload_digest,
                baseline_manifest.manifest_hash,
            ),
            candidate_ver.verifier_key: (
                candidate_manifest.payload_digest,
                candidate_manifest.manifest_hash,
            ),
        },
        case_diff_digests={c.case_id: c.diff_digest for c in panel_res.cases},
    )

    has_provisional = any(
        adj.review_status == "provisional" for adj in panel_res.adjudications
    )
    if has_provisional and not options.diagnostic:
        raise ProtectionError(
            "Provisional panel adjudications require --diagnostic mode.",
            code=ErrorCode.PROTECTION_ERROR.value,
        )

    case_ids = tuple(c.case_id for c in panel_res.cases)
    task_pins = tuple(
        TaskPin(
            task_key=b.task.task_key,
            task_version=b.task.version,
            contract_hash=b.contract.contract_hash,
            repository_snapshot_digest=b.snapshot.snapshot_digest,
            environment_id=b.environment.environment_id,
            environment_image_digest=b.environment.image_digest,
            verifier_baseline_version=baseline_ver.verifier_key,
            verifier_candidate_version=candidate_ver.verifier_key,
            baseline_manifest_hash=baseline_manifest.manifest_hash,
            candidate_manifest_hash=candidate_manifest.manifest_hash,
            case_ids=case_ids,
        )
        for b in task_bundles
    )

    manifest, planned_jobs = plan_audit(
        task_pins=task_pins,
        options=options,
        panel=panel_res.panel,
    )

    diagnostics: list[str] = list(panel_res.findings) + fixture_diagnostics
    if options.diagnostic:
        diagnostics.append(
            "Diagnostic fixture run: provisional or synthetic scope; not a release gate pass."
        )

    if options.dry_run:
        diagnostics.append(f"Dry run validated {len(planned_jobs)} planned job(s).")
        return AuditResult(
            manifest=manifest,
            matrix=None,
            metrics=(),
            gate=None,
            diagnostics=tuple(diagnostics),
            artifacts=(),
        )

    out_dir = Path(options.output_dir or f"runs/{manifest.run_id}")
    conn = connect(db_path)
    try:
        migrate(conn, backup=False)
        artifact_store = ArtifactStore(artifact_dir)

        with transaction(conn, immediate=True):
            for b, b_ver_bytes in task_bundle_pairs:
                _persist_bundle_records(
                    conn, artifact_store, b, verifier_payload_bytes=b_ver_bytes
                )

            # Register baseline and candidate verifiers using captured verified bytes
            for v_bytes, v_ver, v_man in (
                (baseline_bytes, baseline_ver, baseline_manifest),
                (candidate_bytes, candidate_ver, candidate_manifest),
            ):
                artifact_store.put_bytes(
                    v_bytes,
                    max_bytes=2 * 1024 * 1024,
                    kind="manifest",
                    access_policy="public",
                    media_type="application/yaml",
                    conn=conn,
                )
                _persist_verifier(conn, v_ver, v_man)

            # Register patch cases & diffs (reject conflicting case_id definitions)
            for case in panel_res.cases:
                diff_bytes = panel_res.case_diffs.get(case.case_id, b"")
                diff_art = artifact_store.put_bytes(
                    diff_bytes,
                    max_bytes=2 * 1024 * 1024,
                    kind="diff",
                    access_policy="restricted",
                    media_type="text/x-diff",
                    conn=conn,
                )
                existing_case = conn.execute(
                    """
                    SELECT task_key, diff_digest, base_snapshot_digest, source,
                           source_run_id, parent_case_ids, family_id, role,
                           provenance_digest, licence
                    FROM patch_cases WHERE case_id = ?
                    """,
                    (case.case_id,),
                ).fetchone()
                if existing_case is None:
                    conn.execute(
                        """
                        INSERT INTO patch_cases (
                            case_id, task_key, diff_digest, base_snapshot_digest,
                            source, source_run_id, parent_case_ids, family_id,
                            role, provenance_digest, licence, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            case.case_id,
                            case.task_key,
                            diff_art.digest,
                            case.base_snapshot_digest,
                            case.source,
                            case.source_run_id,
                            json.dumps(list(case.parent_case_ids)),
                            case.family_id,
                            case.role,
                            case.provenance_digest,
                            case.licence,
                            case.created_at.isoformat(),
                        ),
                    )
                elif (
                    existing_case["task_key"] != case.task_key
                    or existing_case["diff_digest"] != diff_art.digest
                    or existing_case["base_snapshot_digest"]
                    != case.base_snapshot_digest
                    or existing_case["source"] != case.source
                    or existing_case["source_run_id"] != case.source_run_id
                    or json.loads(existing_case["parent_case_ids"])
                    != list(case.parent_case_ids)
                    or existing_case["family_id"] != case.family_id
                    or existing_case["role"] != case.role
                    or existing_case["provenance_digest"] != case.provenance_digest
                    or existing_case["licence"] != case.licence
                ):
                    raise IdentityConflict(
                        f"Patch case '{case.case_id}' already exists with conflicting immutable fields.",
                        code=ErrorCode.IDENTITY_CONFLICT.value,
                    )

            for adj in panel_res.adjudications:
                existing_adj = conn.execute(
                    """
                    SELECT case_id, contract_hash, version, label, review_status,
                           rationale, requirement_hashes, witness_ids, uncertainty, supersedes_id
                    FROM adjudications WHERE adjudication_id = ?
                    """,
                    (adj.adjudication_id,),
                ).fetchone()
                if existing_adj is None:
                    conn.execute(
                        """
                        INSERT INTO adjudications (
                            adjudication_id, case_id, contract_hash, version, label,
                            review_status, votes, rationale, requirement_hashes,
                            witness_ids, uncertainty, supersedes_id, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            adj.adjudication_id,
                            adj.case_id,
                            adj.contract_hash,
                            adj.version,
                            adj.label,
                            adj.review_status,
                            json.dumps([]),
                            adj.rationale,
                            json.dumps(list(adj.requirement_hashes)),
                            json.dumps(list(adj.witness_ids)),
                            adj.uncertainty,
                            adj.supersedes_id,
                            adj.created_at.isoformat(),
                        ),
                    )
                elif (
                    existing_adj["case_id"] != adj.case_id
                    or existing_adj["contract_hash"] != adj.contract_hash
                    or existing_adj["version"] != adj.version
                    or existing_adj["label"] != adj.label
                    or existing_adj["review_status"] != adj.review_status
                    or existing_adj["rationale"] != adj.rationale
                    or json.loads(existing_adj["requirement_hashes"])
                    != list(adj.requirement_hashes)
                    or json.loads(existing_adj["witness_ids"]) != list(adj.witness_ids)
                    or existing_adj["uncertainty"] != adj.uncertainty
                    or existing_adj["supersedes_id"] != adj.supersedes_id
                ):
                    raise IdentityConflict(
                        f"Adjudication '{adj.adjudication_id}' already exists with conflicting content.",
                        code=ErrorCode.IDENTITY_CONFLICT.value,
                    )

            panel = panel_res.panel
            existing_panel = conn.execute(
                """
                SELECT panel_id, version, split, membership_digest, sampling_policy, parent_panel_key
                FROM patch_panels WHERE panel_key = ?
                """,
                (panel.panel_key,),
            ).fetchone()
            if existing_panel is None:
                conn.execute(
                    """
                    INSERT INTO patch_panels (
                        panel_key, panel_id, version, split, membership_digest,
                        sampling_policy, exposed_at, development_used_at,
                        sealed_at, retired_at, parent_panel_key
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        panel.panel_key,
                        panel.panel_id,
                        panel.version,
                        panel.split,
                        panel.membership_digest,
                        panel.sampling_policy,
                        None,
                        None,
                        None,
                        None,
                        panel.parent_panel_key,
                    ),
                )
            elif (
                existing_panel["panel_id"] != panel.panel_id
                or existing_panel["version"] != panel.version
                or existing_panel["split"] != panel.split
                or existing_panel["membership_digest"] != panel.membership_digest
                or existing_panel["sampling_policy"] != panel.sampling_policy
                or existing_panel["parent_panel_key"] != panel.parent_panel_key
            ):
                raise IdentityConflict(
                    f"Panel '{panel.panel_key}' already exists with conflicting definition or membership digest.",
                    code=ErrorCode.IDENTITY_CONFLICT.value,
                )

            existing_members_rows = conn.execute(
                """
                SELECT case_id, adjudication_id, ordinal, expected_control_outcomes
                FROM panel_memberships WHERE panel_key = ?
                """,
                (panel.panel_key,),
            ).fetchall()
            if existing_members_rows:
                existing_members_map = {
                    r["case_id"]: (
                        r["adjudication_id"],
                        r["ordinal"],
                        json.loads(r["expected_control_outcomes"]),
                    )
                    for r in existing_members_rows
                }
                incoming_members_map = {
                    m.case_id: (
                        m.adjudication_id,
                        m.ordinal,
                        dict(m.expected_control_outcomes),
                    )
                    for m in panel_res.memberships
                }
                if existing_members_map != incoming_members_map:
                    raise IdentityConflict(
                        f"Panel '{panel.panel_key}' memberships conflict with previously persisted memberships.",
                        code=ErrorCode.IDENTITY_CONFLICT.value,
                    )
            else:
                for m in panel_res.memberships:
                    conn.execute(
                        """
                        INSERT INTO panel_memberships (
                            panel_key, case_id, adjudication_id, ordinal, expected_control_outcomes
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            m.panel_key,
                            m.case_id,
                            m.adjudication_id,
                            m.ordinal,
                            json.dumps(dict(m.expected_control_outcomes)),
                        ),
                    )

            # Register AuditManifest, AuditRun, and planned Jobs
            conn.execute(
                """
                INSERT INTO audit_manifests (
                    manifest_hash, run_id, benchmark_version, task_pins, panel_key,
                    adjudication_version, evaluation_harness_version, config_hash,
                    policy_hash, analysis_plan_hash, timestamp, host_fingerprint,
                    seed, agent_version, model_identifier, max_repetitions,
                    max_attempts_per_job, timeout_seconds, resource_policy,
                    expansion_digest, parent_run_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    manifest.manifest_hash,
                    manifest.run_id,
                    manifest.benchmark_version,
                    json.dumps(canonical_repr(manifest.task_pins)),
                    manifest.panel_key,
                    manifest.adjudication_version,
                    manifest.evaluation_harness_version,
                    manifest.config_hash,
                    manifest.policy_hash,
                    manifest.analysis_plan_hash,
                    manifest.timestamp.isoformat(),
                    manifest.host_fingerprint,
                    manifest.seed,
                    manifest.agent_version,
                    manifest.model_identifier,
                    manifest.max_repetitions,
                    manifest.max_attempts_per_job,
                    manifest.timeout_seconds,
                    manifest.resource_policy,
                    manifest.expansion_digest,
                    manifest.parent_run_id,
                ),
            )
            conn.execute(
                """
                INSERT INTO audit_runs (
                    run_id, manifest_hash, state, cancel_requested, created_at,
                    finished_at, diagnostic_code
                ) VALUES (?, ?, 'PLANNED', 0, ?, NULL, NULL)
                """,
                (
                    manifest.run_id,
                    manifest.manifest_hash,
                    datetime.now(UTC).isoformat(),
                ),
            )
            for j in planned_jobs:
                conn.execute(
                    """
                    INSERT INTO jobs (
                        job_id, run_id, task_key, case_id, verifier_key,
                        repetition, state, fence, attempts_started
                    ) VALUES (?, ?, ?, ?, ?, ?, 'PENDING', 0, 0)
                    """,
                    (
                        j.job_id,
                        j.run_id,
                        j.task_key,
                        j.case_id,
                        j.verifier_key,
                        j.repetition,
                    ),
                )

        snapshot_resolver = {
            b.task.task_key: Path(b.snapshot.archive_uri) for b in task_bundles
        }
        expected_snapshot_digests = {
            b.task.task_key: b.snapshot.snapshot_digest for b in task_bundles
        }
        manifest_resolver = {
            baseline_ver.verifier_key: baseline_manifest,
            candidate_ver.verifier_key: candidate_manifest,
        }
        worker = Worker(
            artifact_store=artifact_store,
            work_dir=out_dir / ".work",
            snapshot_resolver=snapshot_resolver,
            diff_resolver=panel_res.case_diffs,
            manifest_resolver=manifest_resolver,
            expected_snapshot_digests=expected_snapshot_digests,
        )
        worker.run_until_terminal(
            conn,
            run_id=manifest.run_id,
            max_iterations=max(
                len(planned_jobs) * manifest.max_attempts_per_job + 10, 1
            ),
        )

        db_jobs, db_attempts = _load_jobs_and_attempts(conn, manifest.run_id)
        adjs_map = {a.case_id: a for a in panel_res.adjudications}
        cases_map = {c.case_id: c for c in panel_res.cases}
        repository_map = {
            b.task.task_key: b.snapshot.repository_id for b in task_bundles
        }

        matrix = build_matrix(
            manifest,
            db_jobs,
            db_attempts,
            adjs_map,
            cases_map,
            repository_map,
        )

        # Collect only artifacts referenced by this run
        run_artifact_digests: set[str] = {
            baseline_manifest.payload_digest,
            candidate_manifest.payload_digest,
        }
        for b in task_bundles:
            run_artifact_digests.add(b.upstream_artifact.digest)
            run_artifact_digests.add(b.snapshot.snapshot_digest)
            run_artifact_digests.add(b.verifier_manifest.payload_digest)
        for case in panel_res.cases:
            run_artifact_digests.add(case.diff_digest)
        for att in db_attempts:
            if att.stdout_hash:
                run_artifact_digests.add(att.stdout_hash)
            if att.stderr_hash:
                run_artifact_digests.add(att.stderr_hash)
            if att.report_digest:
                run_artifact_digests.add(att.report_digest)
            for ad in att.artifact_digests:
                if ad:
                    run_artifact_digests.add(ad)

        sorted_digests = sorted(run_artifact_digests)
        if sorted_digests:
            placeholders = ",".join("?" for _ in sorted_digests)
            art_rows = conn.execute(
                f"SELECT * FROM artifacts WHERE digest IN ({placeholders}) ORDER BY digest ASC",
                tuple(sorted_digests),
            ).fetchall()
        else:
            art_rows = []
        artifacts = tuple(
            Artifact(
                digest=r["digest"],
                kind=r["kind"],
                size_bytes=r["size_bytes"],
                storage_uri=r["storage_uri"],
                media_type=r["media_type"],
                access_policy=r["access_policy"],
                retention_until=datetime.fromisoformat(r["retention_until"])
                if r["retention_until"]
                else None,
                available=bool(r["available"]),
                created_at=datetime.fromisoformat(r["created_at"]),
            )
            for r in art_rows
        )

        result = AuditResult(
            manifest=manifest,
            matrix=matrix,
            metrics=(),
            gate=None,
            diagnostics=tuple(diagnostics),
            artifacts=artifacts,
        )

        # Stage all three run outputs in a run-specific staging directory first,
        # promote them atomically, and publish COMPLETE.json boundary last.
        stage_dir = out_dir / ".staging" / manifest.run_id
        stage_dir.mkdir(parents=True, exist_ok=True)
        staged_report = stage_dir / "report.json"
        staged_summary = stage_dir / "summary.txt"
        staged_manifest = stage_dir / "manifest.json"

        render_json(result, staged_report)
        summary_text = render_summary(result) + "\n"
        _atomic_write_text(staged_summary, summary_text)
        manifest_text = (
            json.dumps(
                {
                    "schema_version": "1.0.0",
                    "kind": "AuditManifest",
                    "data": canonical_repr(manifest),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
        _atomic_write_text(staged_manifest, manifest_text)

        report_bytes = staged_report.read_bytes()
        summary_bytes = staged_summary.read_bytes()
        manifest_bytes = staged_manifest.read_bytes()

        render_json(result, out_dir / "report.json")
        _atomic_write_text(out_dir / "summary.txt", summary_text)
        _atomic_write_text(out_dir / "manifest.json", manifest_text)

        boundary = {
            "schema_version": "1.0.0",
            "kind": "AuditOutputComplete",
            "run_id": manifest.run_id,
            "matrix_id": matrix.matrix_id,
            "files": {
                "report.json": hashlib.sha256(report_bytes).hexdigest(),
                "summary.txt": hashlib.sha256(summary_bytes).hexdigest(),
                "manifest.json": hashlib.sha256(manifest_bytes).hexdigest(),
            },
        }
        _atomic_write_text(
            out_dir / "COMPLETE.json",
            json.dumps(boundary, indent=2, sort_keys=True) + "\n",
        )
        return result
    finally:
        conn.close()


def _hash_optional_file(path: Path) -> str:
    if path.is_file() and not path.is_symlink():
        return hashlib.sha256(path.read_bytes()).hexdigest()
    return hashlib.sha256(str(path).encode("utf-8")).hexdigest()


__all__ = [
    "execute_audit_pipeline",
    "import_task_command",
]
