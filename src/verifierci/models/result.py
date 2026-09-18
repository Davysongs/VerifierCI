"""Verification result model."""
"""Result, attempt, matrix, metric, decision, and artifact domain models.

SDD Section 4.1 and Section 5.
All domain entities are immutable (@dataclass(frozen=True, slots=True)).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any
from datetime import datetime
from typing import TYPE_CHECKING, Literal

from verifierci.errors import ValidationError
from verifierci.models.task import canonical_bytes

@dataclass(frozen=True)
class VerificationResult:
    """Outcome of running one verifier against a patch candidate."""
if TYPE_CHECKING:
    from verifierci.models.protocol import (
        AcceptanceCell,
        AuditResult,
        GateEvidence,
        MetricTerm,
        ResourceUsage,
        TaskPin,
    )

    task_id: str
    verdict: str
    details: dict[str, Any] | None = None

@dataclass(frozen=True, slots=True)
class EvaluationAttempt:
    """A physical execution of one planned evaluation repetition."""

    attempt_id: str  # UUID for this physical attempt.
    job_id: str  # Planned task/case/verifier/repetition identity.
    fence: int  # Lease generation that authorised this attempt.
    outcome: (
        Literal["accept", "reject", "invalid_evaluation", "error"] | None
    )  # Raw completed observation.
    evaluation_validity: Literal[
        "pending", "valid", "invalid"
    ]  # Whether usable as a grading decision.
    error_code: str | None  # Typed diagnostic such as PATCH_ERROR or TIMEOUT.
    disposition: Literal[
        "active", "authoritative", "stale", "abandoned"
    ]  # Authority status.
    started_at: datetime  # Start time of physical execution.
    finished_at: datetime | None  # Completion or abandonment time.
    exit_code: int | None  # Observed verifier process code.
    stdout_hash: str | None  # Digest of captured stdout.
    stderr_hash: str | None  # Digest of captured stderr.
    report_digest: str | None  # Raw structured test report artifact.
    test_collection: tuple[str, ...]  # Observed test IDs.
    tests_passed: int | None  # Observed passes.
    tests_failed: int | None  # Observed failures.
    resources: ResourceUsage  # Measured resource usage.
    artifact_digests: tuple[str, ...]  # Captured artifacts.
    capture_truncated: bool  # Whether any stream was truncated.


def validate_attempt(attempt: EvaluationAttempt) -> None:
    """Validate execution attempt invariants per SDD Section 4.1 SQL check constraints.

    flaky is an aggregate-cell outcome, not an attempt outcome.
    """
    if attempt.fence <= 0:
        raise ValidationError(
            f"Evaluation attempt fence must be positive, got {attempt.fence}."
        )

    # flaky is prohibited on an individual attempt
    if getattr(attempt, "outcome", None) == "flaky":
        raise ValidationError(
            "Individual attempts cannot have outcome 'flaky'; flaky is an aggregate-cell outcome."
        )

    if attempt.evaluation_validity == "pending":
        if attempt.outcome is not None or attempt.disposition != "active":
            raise ValidationError(
                "Pending evaluation attempt must have outcome=None and disposition='active', "
                f"got outcome={attempt.outcome}, disposition={attempt.disposition}."
            )
    elif attempt.evaluation_validity == "valid":
        if attempt.outcome not in ("accept", "reject"):
            raise ValidationError(
                f"Valid evaluation attempt must have outcome 'accept' or 'reject', got '{attempt.outcome}'."
            )
    elif attempt.evaluation_validity == "invalid":
        valid_invalid = attempt.outcome in ("invalid_evaluation", "error") or (
            attempt.outcome is None and attempt.disposition in ("abandoned", "stale")
        )
        if not valid_invalid:
            raise ValidationError(
                "Invalid evaluation attempt must have outcome in ('invalid_evaluation','error') "
                f"or (outcome=None and disposition in ('abandoned','stale')); got outcome={attempt.outcome}, "
                f"disposition={attempt.disposition}."
            )
    else:
        raise ValidationError(
            f"Unknown evaluation_validity: {attempt.evaluation_validity}"
        )


@dataclass(frozen=True, slots=True)
class AcceptanceMatrix:
    """Cell-aggregated acceptance matrix for an audit run."""

    matrix_id: str  # Immutable derived matrix identity.
    run_id: str  # Parent audit.
    reducer_version: str  # Version of selection and repetition aggregation rules.
    cells: tuple[AcceptanceCell, ...]  # One entry per task/case/verifier.
    complete: bool  # True only when all planned jobs are terminal.
    source_attempts_digest: (
        str  # Identity of selected and excluded attempt dispositions.
    )
    created_at: datetime  # Finalisation timestamp.


def validate_matrix(matrix: AcceptanceMatrix, manifest: AuditManifest) -> None:
    """Validate matrix consistency with parent audit manifest."""
    if matrix.run_id != manifest.run_id:
        raise ValidationError(
            f"Matrix run_id '{matrix.run_id}' does not match manifest run_id '{manifest.run_id}'."
        )


@dataclass(frozen=True, slots=True)
class MetricResult:
    """Evaluated metric outcome (IAR, VRR, delta) over an acceptance matrix."""

    metric_id: str  # Immutable metric identity.
    matrix_id: str  # Source observation matrix.
    name: str  # IAR, VRR, paired delta or diagnostic name.
    definition_version: str  # Exact filtering and aggregation specification version.
    verifier_key: str | None  # Single verifier or null for paired summaries.
    cohort: Literal["challenge", "controls", "all"]  # Explicit eligible case scope.
    value: float | None  # Computed rate/delta or null if undefined.
    numerator: int | None  # Single-task count; null for a macro-average.
    denominator: int | None  # Single-task denominator; null for macro-average.
    task_terms: tuple[
        MetricTerm, ...
    ]  # Per-task counts and exclusions supporting the result.
    ci_low: float | None  # Lower interval endpoint, null when not estimable.
    ci_high: float | None  # Upper interval endpoint, null when not estimable.
    analysis_plan_hash: str | None  # Plan controlling inference and multiplicity.
    coverage: dict[str, int]  # Scheduled, usable, missing, flaky and unresolved counts.


@dataclass(frozen=True, slots=True)
class GateDecision:
    """Authoritative CI gate release decision."""

    decision_id: str  # Content-derived decision identity.
    run_id: str  # Audit being evaluated.
    matrix_id: str | None  # Null only for pre-execution infrastructure failure.
    policy_hash: str  # Exact release policy used.
    state: Literal[
        "PASSED",
        "BLOCKED",
        "INCONCLUSIVE",
        "INSUFFICIENT_EVIDENCE",
        "INFRASTRUCTURE_ERROR",
    ]
    exit_code: int  # Canonical CLI exit category.
    reasons: tuple[str, ...]  # Ordered rule identifiers and explanations.
    evidence: tuple[
        GateEvidence, ...
    ]  # Cases, witnesses and paired observations backing the decision.
    reliability_flags: tuple[
        str, ...
    ]  # Additional warnings retained even when BLOCKED.
    created_at: datetime  # Decision evaluation timestamp.


@dataclass(frozen=True, slots=True)
class Artifact:
    """Metadata for an immutable stored byte payload."""

    digest: str  # Lowercase SHA-256 hex digest of stored bytes.
    kind: str  # Snapshot, diff, report, stdout, evidence or manifest.
    size_bytes: int  # Exact retained byte count.
    storage_uri: str  # Content-addressed local path or approved remote locator.
    media_type: str  # Validated content type, never trusted from filename alone.
    access_policy: Literal[
        "public", "restricted", "sealed"
    ]  # Disclosure boundary for this artifact.
    retention_until: (
        datetime | None
    )  # Earliest permitted deletion time, null for retained evidence.
    available: bool  # Whether bytes are presently retrievable.
    created_at: datetime  # First successful registration.


@dataclass(frozen=True, slots=True)
class AuditManifest:
    """Immutable audit configuration and planned execution inventory."""

    manifest_hash: str  # Canonical manifest hash excluding this field only.
    run_id: str  # UUID fixed for retries and resume.
    benchmark_version: str  # Frozen task membership release identity.
    task_pins: tuple[
        TaskPin, ...
    ]  # Per-task contract, snapshot, environment and verifier pair.
    panel_key: str  # Exact panel version.
    adjudication_version: str  # Digest of sorted case-to-decision mapping.
    evaluation_harness_version: str  # Controller and upstream harness lock identity.
    config_hash: str  # Digest of effective merged configuration.
    policy_hash: str  # Frozen release gate policy.
    analysis_plan_hash: str | None  # Pre-registration required for unseen assessment.
    timestamp: datetime  # Run plan creation time.
    host_fingerprint: (
        str  # Kernel, architecture, runtime and cgroup capability identity.
    )
    seed: (
        int | None
    )  # Controlled randomness seed, null with explicit deterministic policy.
    agent_version: (
        str | None
    )  # Optional generator cohort identifier; per-case details in AgentRun.
    model_identifier: (
        str | None
    )  # Optional generator snapshot; null for saved mixed-source patches.
    max_repetitions: int  # Planned repetitions per cell, normally three.
    max_attempts_per_job: int  # Bounded infrastructure retry allowance.
    timeout_seconds: int  # Maximum allowed wall limit, including build.
    resource_policy: str  # Hash of sandbox policy bytes.
    expansion_digest: str  # Digest of sorted deterministic job identities.
    parent_run_id: str | None  # Prior audit for explicit diagnostic reruns.


@dataclass(frozen=True, slots=True)
class AuditRun:
    """Operational lifecycle record for an audit execution."""

    run_id: str  # Audit UUID.
    manifest_hash: str  # Frozen audit configuration.
    state: Literal[
        "PLANNED", "RUNNING", "COMPLETE", "CANCELLED", "FAILED"
    ]  # Operational run lifecycle.
    cancel_requested: bool  # Cooperative cancellation intent.
    created_at: datetime  # Registration time.
    finished_at: datetime | None  # Terminal timestamp.
    diagnostic_code: str | None  # Run-level infrastructure failure, if any.


def result_digest(result: AuditResult) -> str:
    """Compute 64-char lowercase SHA-256 digest of AuditResult."""
    return hashlib.sha256(canonical_bytes(result)).hexdigest()
