"""Execution planning and job expansion primitives (Phase 1).

SDD Section 5: verifierci.execution.planner.
Expands a validated immutable audit into a bounded deterministic job set.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime

from verifierci.errors import ErrorCode, ValidationError
from verifierci.models.panel import PatchPanel
from verifierci.models.protocol import AuditOptions, Job, TaskPin
from verifierci.models.result import AuditManifest
from verifierci.models.task import canonical_bytes


def job_id(
    run_id: str,
    task_key: str,
    case_id: str,
    verifier_key: str,
    repetition: int,
) -> str:
    """Compute a deterministic job identifier from execution coordinates.

    SDD Section 5: SHA-256 hex digest of the canonical ordered coordinate tuple.
    """
    coord_bytes = canonical_bytes((run_id, task_key, case_id, verifier_key, repetition))
    return hashlib.sha256(coord_bytes).hexdigest()


def compute_expansion_digest(
    jobs: tuple[Job, ...] | list[Job] | list[str] | tuple[str, ...],
) -> str:
    """Compute deterministic digest of sorted job identities."""
    sorted_ids = sorted(j.job_id if hasattr(j, "job_id") else str(j) for j in jobs)
    return hashlib.sha256(json.dumps(sorted_ids).encode("utf-8")).hexdigest()


def expand(
    manifest: AuditManifest,
    panel: PatchPanel | None = None,
) -> tuple[Job, ...]:
    """Expand an audit manifest into its planned execution job sequence.

    Deterministic expansion cross-products pinned cases, verifiers (baseline
    and candidate), and repetition indices.
    """
    expanded: list[Job] = []

    for pin in manifest.task_pins:
        verifiers = (pin.verifier_baseline_version, pin.verifier_candidate_version)
        case_ids = pin.case_ids
        if not case_ids and panel is not None and hasattr(panel, "memberships"):
            # Fallback to panel memberships if case_ids not directly populated
            case_ids = tuple(
                m.case_id
                for m in getattr(panel, "memberships")  # noqa: B009
            )

        for case_id in case_ids:
            for v_key in verifiers:
                for rep in range(manifest.max_repetitions):
                    jid = job_id(manifest.run_id, pin.task_key, case_id, v_key, rep)
                    job = Job(
                        job_id=jid,
                        run_id=manifest.run_id,
                        task_key=pin.task_key,
                        case_id=case_id,
                        verifier_key=v_key,
                        repetition=rep,
                        state="PENDING",
                        fence=0,
                        attempt_id=None,
                        lease_token=None,
                        worker_id=None,
                        lease_expires_ms=None,
                        attempts_started=0,
                        selected_attempt_id=None,
                        terminal_reason=None,
                    )
                    expanded.append(job)

    # Sort deterministically
    sorted_jobs = tuple(
        sorted(
            expanded,
            key=lambda j: (j.task_key, j.case_id, j.verifier_key, j.repetition),
        )
    )
    return sorted_jobs


def build_manifest(
    options: AuditOptions | None = None,
    pins: tuple[TaskPin, ...] = (),
    panel: PatchPanel | None = None,
    *,
    run_id: str | None = None,
    task_pins: tuple[TaskPin, ...] = (),
    panel_key: str | None = None,
    adjudication_version: str | None = None,
    policy_hash: str | None = None,
    repetitions: int | None = None,
    benchmark_version: str = "local-1.0.0",
    timeout_seconds: int = 120,
    max_attempts: int = 3,
    resource_policy: str | None = None,
    seed: int | None = None,
) -> AuditManifest:
    """Construct and hash an immutable AuditManifest."""
    effective_pins = task_pins or pins
    if not effective_pins:
        raise ValidationError(
            "Audit manifest requires at least one TaskPin.",
            code=ErrorCode.VALIDATION_ERROR.value,
        )

    actual_run_id = run_id or str(uuid.uuid4())
    now = datetime.now(UTC)

    eff_benchmark = (
        options.benchmark_file
        if options and options.benchmark_file
        else benchmark_version
    )
    eff_panel_key = panel.panel_key if panel else (panel_key or "panel-1")
    eff_adjudication = (
        panel.membership_digest if panel else (adjudication_version or "adj-1")
    )
    eff_repetitions = options.repetitions if options else (repetitions or 3)
    eff_timeout = options.timeout_seconds if options else timeout_seconds
    eff_max_attempts = options.max_attempts if options else max_attempts
    eff_policy_hash = policy_hash or (hashlib.sha256(b"default_policy").hexdigest())
    eff_seed = options.seed if options else seed

    # Temporary manifest to compute expansion
    temp_manifest = AuditManifest(
        manifest_hash="temp",
        run_id=actual_run_id,
        benchmark_version=eff_benchmark,
        task_pins=effective_pins,
        panel_key=eff_panel_key,
        adjudication_version=eff_adjudication,
        evaluation_harness_version="verifierci-0.1.0",
        config_hash=hashlib.sha256(b"default_config").hexdigest(),
        policy_hash=eff_policy_hash,
        analysis_plan_hash=None,
        timestamp=now,
        host_fingerprint="local-runner",
        seed=eff_seed,
        agent_version=None,
        model_identifier=None,
        max_repetitions=eff_repetitions,
        max_attempts_per_job=eff_max_attempts,
        timeout_seconds=eff_timeout,
        resource_policy=resource_policy
        or hashlib.sha256(b"sandbox_policy").hexdigest(),
        expansion_digest="temp",
        parent_run_id=options.parent_run_id if options else None,
    )

    planned_jobs = expand(temp_manifest, panel)
    if options and options.max_jobs and len(planned_jobs) > options.max_jobs:
        raise ValidationError(
            f"Planned job count ({len(planned_jobs)}) exceeds max_jobs ceiling ({options.max_jobs}).",
            code=ErrorCode.RESOURCE_EXHAUSTED.value,
        )

    exp_digest = compute_expansion_digest(planned_jobs)

    # Manifest dictionary without manifest_hash for canonical hashing
    manifest_dict = {
        "run_id": actual_run_id,
        "benchmark_version": temp_manifest.benchmark_version,
        "task_pins": [
            {
                "task_key": p.task_key,
                "task_version": p.task_version,
                "contract_hash": p.contract_hash,
                "repository_snapshot_digest": p.repository_snapshot_digest,
                "environment_id": p.environment_id,
                "environment_image_digest": p.environment_image_digest,
                "verifier_baseline_version": p.verifier_baseline_version,
                "verifier_candidate_version": p.verifier_candidate_version,
                "baseline_manifest_hash": p.baseline_manifest_hash,
                "candidate_manifest_hash": p.candidate_manifest_hash,
                "case_ids": list(p.case_ids),
            }
            for p in effective_pins
        ],
        "panel_key": eff_panel_key,
        "adjudication_version": eff_adjudication,
        "evaluation_harness_version": temp_manifest.evaluation_harness_version,
        "config_hash": temp_manifest.config_hash,
        "policy_hash": temp_manifest.policy_hash,
        "analysis_plan_hash": temp_manifest.analysis_plan_hash,
        "timestamp": now.isoformat(),
        "host_fingerprint": temp_manifest.host_fingerprint,
        "seed": temp_manifest.seed,
        "agent_version": temp_manifest.agent_version,
        "model_identifier": temp_manifest.model_identifier,
        "max_repetitions": temp_manifest.max_repetitions,
        "max_attempts_per_job": temp_manifest.max_attempts_per_job,
        "timeout_seconds": temp_manifest.timeout_seconds,
        "resource_policy": temp_manifest.resource_policy,
        "expansion_digest": exp_digest,
        "parent_run_id": temp_manifest.parent_run_id,
    }
    m_hash = hashlib.sha256(canonical_bytes(manifest_dict)).hexdigest()

    return AuditManifest(
        manifest_hash=m_hash,
        run_id=actual_run_id,
        benchmark_version=temp_manifest.benchmark_version,
        task_pins=effective_pins,
        panel_key=eff_panel_key,
        adjudication_version=eff_adjudication,
        evaluation_harness_version=temp_manifest.evaluation_harness_version,
        config_hash=temp_manifest.config_hash,
        policy_hash=temp_manifest.policy_hash,
        analysis_plan_hash=temp_manifest.analysis_plan_hash,
        timestamp=now,
        host_fingerprint=temp_manifest.host_fingerprint,
        seed=temp_manifest.seed,
        agent_version=temp_manifest.agent_version,
        model_identifier=temp_manifest.model_identifier,
        max_repetitions=temp_manifest.max_repetitions,
        max_attempts_per_job=temp_manifest.max_attempts_per_job,
        timeout_seconds=temp_manifest.timeout_seconds,
        resource_policy=temp_manifest.resource_policy,
        expansion_digest=exp_digest,
        parent_run_id=temp_manifest.parent_run_id,
    )


def plan_jobs(task_ids: list[str]) -> list[Job]:
    """Compatibility helper returning stub jobs for given task IDs."""
    run_id = "stub_run"
    return [
        Job(
            job_id=job_id(run_id, tid, "case_0", "verifier_0", 0),
            run_id=run_id,
            task_key=tid,
            case_id="case_0",
            verifier_key="verifier_0",
            repetition=0,
            state="PENDING",
            fence=0,
            attempt_id=None,
            lease_token=None,
            worker_id=None,
            lease_expires_ms=None,
            attempts_started=0,
            selected_attempt_id=None,
            terminal_reason=None,
        )
        for tid in task_ids
    ]
