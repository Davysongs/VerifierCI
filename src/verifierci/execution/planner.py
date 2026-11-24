"""Execution planning and job expansion primitives (Phase 1).

SDD Section 5: verifierci.execution.planner.
Expands a validated immutable audit into a bounded deterministic job set.
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime

from verifierci.errors import ErrorCode, ValidationError
from verifierci.models.panel import PatchPanel
from verifierci.models.protocol import AuditOptions, Job, SandboxPolicy, TaskPin
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
    if not run_id:
        raise ValidationError("run_id cannot be empty for job_id computation.")
    if not task_key:
        raise ValidationError("task_key cannot be empty for job_id computation.")
    if not case_id:
        raise ValidationError("case_id cannot be empty for job_id computation.")
    if not verifier_key:
        raise ValidationError("verifier_key cannot be empty for job_id computation.")
    if repetition < 0:
        raise ValidationError(
            f"repetition index must be non-negative, got {repetition}."
        )

    coord_bytes = canonical_bytes((run_id, task_key, case_id, verifier_key, repetition))
    return hashlib.sha256(coord_bytes).hexdigest()


def compute_expansion_digest(
    jobs: Sequence[Job | str],
) -> str:
    """Compute deterministic digest of sorted job identities."""
    sorted_ids = sorted(j.job_id if hasattr(j, "job_id") else str(j) for j in jobs)
    return hashlib.sha256(canonical_bytes(sorted_ids)).hexdigest()


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
        raw_verifiers = (pin.verifier_baseline_version, pin.verifier_candidate_version)
        seen_verifiers: set[str] = set()
        verifiers: list[str] = []
        for v in raw_verifiers:
            if v and v not in seen_verifiers:
                seen_verifiers.add(v)
                verifiers.append(v)

        case_ids: Sequence[str] = pin.case_ids
        if not case_ids and panel is not None:
            if hasattr(panel, "memberships"):
                case_ids = tuple(
                    m.case_id
                    for m in getattr(panel, "memberships")  # noqa: B009
                )
            elif hasattr(panel, "cases"):
                case_ids = tuple(
                    c.case_id
                    for c in getattr(panel, "cases")  # noqa: B009
                )
            elif hasattr(panel, "case_ids"):
                case_ids = tuple(getattr(panel, "case_ids"))  # noqa: B009

        seen_cases: set[str] = set()
        unique_case_ids: list[str] = []
        for cid in case_ids:
            if cid and cid not in seen_cases:
                seen_cases.add(cid)
                unique_case_ids.append(cid)

        for case_id in unique_case_ids:
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
    policy: SandboxPolicy | None = None,
    repetitions: int | None = None,
    benchmark_version: str = "local-1.0.0",
    timeout_seconds: int = 120,
    max_attempts: int = 3,
    resource_policy: str | None = None,
    seed: int | None = None,
    max_jobs: int | None = None,
    timestamp: datetime | None = None,
    config_hash: str | None = None,
    analysis_plan_hash: str | None = None,
    host_fingerprint: str = "local-runner",
    evaluation_harness_version: str = "verifierci-0.1.0",
    agent_version: str | None = None,
    model_identifier: str | None = None,
    parent_run_id: str | None = None,
) -> AuditManifest:
    """Construct and hash an immutable AuditManifest."""
    effective_pins = task_pins or pins
    if not effective_pins:
        raise ValidationError(
            "Audit manifest requires at least one TaskPin.",
            code=ErrorCode.VALIDATION_ERROR.value,
        )

    # Check for duplicate task pins
    seen_tasks: set[str] = set()
    for p in effective_pins:
        if p.task_key in seen_tasks:
            raise ValidationError(
                f"Duplicate task pin for task '{p.task_key}'.",
                code=ErrorCode.VALIDATION_ERROR.value,
            )
        seen_tasks.add(p.task_key)

    sorted_pins = tuple(sorted(effective_pins, key=lambda p: p.task_key))

    actual_run_id = run_id or (
        options.resume_run_id
        if options and options.resume_run_id
        else str(uuid.uuid4())
    )
    now = timestamp or datetime.now(UTC)
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)

    eff_benchmark = (
        options.benchmark_file
        if options and options.benchmark_file
        else benchmark_version
    )
    eff_panel_key = (
        panel.panel_key
        if panel
        else (
            panel_key
            or (options.panel_file if options and options.panel_file else "panel-1")
        )
    )
    eff_adjudication = (
        panel.membership_digest if panel else (adjudication_version or "adj-1")
    )
    eff_repetitions = (
        options.repetitions
        if options and options.repetitions is not None
        else (repetitions if repetitions is not None else 3)
    )
    if eff_repetitions < 1:
        raise ValidationError(
            f"max_repetitions must be >= 1, got {eff_repetitions}.",
            code=ErrorCode.VALIDATION_ERROR.value,
        )

    eff_timeout = (
        options.timeout_seconds
        if options and options.timeout_seconds is not None
        else timeout_seconds
    )
    if eff_timeout <= 0:
        raise ValidationError(
            f"timeout_seconds must be > 0, got {eff_timeout}.",
            code=ErrorCode.VALIDATION_ERROR.value,
        )

    eff_max_attempts = (
        options.max_attempts
        if options and options.max_attempts is not None
        else max_attempts
    )
    if not (1 <= eff_max_attempts <= 3):
        raise ValidationError(
            f"max_attempts_per_job must be between 1 and 3, got {eff_max_attempts}.",
            code=ErrorCode.VALIDATION_ERROR.value,
        )

    eff_policy_hash = (
        policy_hash
        or (policy.policy_hash if policy else None)
        or (
            hashlib.sha256(options.policy_file.encode("utf-8")).hexdigest()
            if options and options.policy_file
            else hashlib.sha256(b"default_policy").hexdigest()
        )
    )
    eff_resource_policy = (
        resource_policy
        or (policy.policy_hash if policy else None)
        or (
            hashlib.sha256(options.sandbox_policy_file.encode("utf-8")).hexdigest()
            if options and options.sandbox_policy_file
            else hashlib.sha256(b"sandbox_policy").hexdigest()
        )
    )
    eff_analysis_plan_hash = analysis_plan_hash or (
        hashlib.sha256(options.analysis_plan_file.encode("utf-8")).hexdigest()
        if options and options.analysis_plan_file
        else None
    )
    eff_config_hash = config_hash or hashlib.sha256(b"default_config").hexdigest()
    eff_seed = options.seed if options and options.seed is not None else seed
    eff_parent_run_id = (
        parent_run_id
        if parent_run_id is not None
        else (options.parent_run_id if options else None)
    )

    # Temporary manifest to compute expansion
    temp_manifest = AuditManifest(
        manifest_hash="temp",
        run_id=actual_run_id,
        benchmark_version=eff_benchmark,
        task_pins=sorted_pins,
        panel_key=eff_panel_key,
        adjudication_version=eff_adjudication,
        evaluation_harness_version=evaluation_harness_version,
        config_hash=eff_config_hash,
        policy_hash=eff_policy_hash,
        analysis_plan_hash=eff_analysis_plan_hash,
        timestamp=now,
        host_fingerprint=host_fingerprint,
        seed=eff_seed,
        agent_version=agent_version,
        model_identifier=model_identifier,
        max_repetitions=eff_repetitions,
        max_attempts_per_job=eff_max_attempts,
        timeout_seconds=eff_timeout,
        resource_policy=eff_resource_policy,
        expansion_digest="temp",
        parent_run_id=eff_parent_run_id,
    )

    planned_jobs = expand(temp_manifest, panel)

    # Check job limits from options, policy, or explicit ceiling
    job_limits: list[int] = []
    if options and options.max_jobs:
        job_limits.append(options.max_jobs)
    if policy and policy.max_jobs:
        job_limits.append(policy.max_jobs)
    if max_jobs is not None:
        job_limits.append(max_jobs)

    if job_limits:
        ceiling = min(job_limits)
        if len(planned_jobs) > ceiling:
            raise ValidationError(
                f"Planned job count ({len(planned_jobs)}) exceeds max_jobs ceiling ({ceiling}).",
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
            for p in sorted_pins
        ],
        "panel_key": eff_panel_key,
        "adjudication_version": eff_adjudication,
        "evaluation_harness_version": temp_manifest.evaluation_harness_version,
        "config_hash": temp_manifest.config_hash,
        "policy_hash": temp_manifest.policy_hash,
        "analysis_plan_hash": temp_manifest.analysis_plan_hash,
        "timestamp": now,
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
        task_pins=sorted_pins,
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


def plan_audit(
    options: AuditOptions | None = None,
    task_pins: tuple[TaskPin, ...] = (),
    panel: PatchPanel | None = None,
    *,
    policy: SandboxPolicy | None = None,
    run_id: str | None = None,
    repetitions: int | None = None,
    benchmark_version: str = "local-1.0.0",
    timeout_seconds: int = 120,
    max_attempts: int = 3,
    resource_policy: str | None = None,
    seed: int | None = None,
    max_jobs: int | None = None,
    timestamp: datetime | None = None,
    config_hash: str | None = None,
    policy_hash: str | None = None,
    analysis_plan_hash: str | None = None,
    host_fingerprint: str = "local-runner",
    evaluation_harness_version: str = "verifierci-0.1.0",
    agent_version: str | None = None,
    model_identifier: str | None = None,
    parent_run_id: str | None = None,
) -> tuple[AuditManifest, tuple[Job, ...]]:
    """Plan an audit from options, task pins, and optional patch panel.

    Returns the immutable AuditManifest and the deterministic sorted Job sequence.
    """
    manifest = build_manifest(
        options=options,
        pins=task_pins,
        panel=panel,
        run_id=run_id,
        task_pins=task_pins,
        policy=policy,
        repetitions=repetitions,
        benchmark_version=benchmark_version,
        timeout_seconds=timeout_seconds,
        max_attempts=max_attempts,
        resource_policy=resource_policy,
        seed=seed,
        max_jobs=max_jobs,
        timestamp=timestamp,
        config_hash=config_hash,
        policy_hash=policy_hash,
        analysis_plan_hash=analysis_plan_hash,
        host_fingerprint=host_fingerprint,
        evaluation_harness_version=evaluation_harness_version,
        agent_version=agent_version,
        model_identifier=model_identifier,
        parent_run_id=parent_run_id,
    )
    jobs = expand(manifest, panel)
    return manifest, jobs


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


__all__ = [
    "build_manifest",
    "compute_expansion_digest",
    "expand",
    "job_id",
    "plan_audit",
    "plan_jobs",
]
