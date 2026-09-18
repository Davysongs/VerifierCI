"""Auxiliary protocol models and versioned serialization adapters.

SDD Section 4.4 and Section 5.
Cross-boundary records are strictly immutable (@dataclass(frozen=True, slots=True))
or schema-validated TypedDicts. No pickle or dynamic code execution is permitted.
"""

from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
from datetime import datetime, timezone
import json
from typing import Any, Literal, TypedDict, get_type_hints

from verifierci.errors import ValidationError
from verifierci.models.panel import PatchCase
from verifierci.models.result import (
    AcceptanceMatrix,
    Artifact,
    GateDecision,
    MetricResult,
)
from verifierci.models.task import (
    Contract,
    Environment,
    RepositorySnapshot,
    Requirement,
    Task,
    canonical_bytes,
)
from verifierci.models.verifier import CommandSpec, VerifierManifest, VerifierVersion

SUPPORTED_WIRE_VERSIONS = {"1.0"}


@dataclass(frozen=True, slots=True)
class ReviewVote:
    """Individual human review vote on patch validity."""

    reviewer_id: str  # Stable pseudonymous reviewer identity.
    label: Literal["valid", "invalid", "unresolved"]  # Original independent vote.
    rationale: str  # Requirement-linked reasoning supplied by the reviewer.
    minutes: float | None  # Observed review time, null if unknown.
    blinded_to_verifier: bool  # Whether grading decisions were hidden during review.
    independent_of_author: bool  # Whether the reviewer authored or generated the patch.
    recorded_at: datetime  # Time this review was recorded.


@dataclass(frozen=True, slots=True)
class TaskPin:
    """Task version and execution pins for an audit run."""

    task_key: str  # Immutable task version reference.
    task_version: str  # Explicit human-readable version for reproduction.
    contract_hash: str  # Normative contract identity.
    repository_snapshot_digest: str  # Source bytes used for all cases of this task.
    environment_id: str  # Immutable environment manifest identity.
    environment_image_digest: str | None  # OCI digest, null for synthetic fixtures only.
    verifier_baseline_version: str  # Exact baseline verifier key.
    verifier_candidate_version: str  # Exact proposed verifier key.
    baseline_manifest_hash: str  # Baseline argv, tests and parser identity.
    candidate_manifest_hash: str  # Candidate argv, tests and parser identity.
    case_ids: tuple[str, ...]  # Cases joined to this task, never a global cross-product.


@dataclass(frozen=True, slots=True)
class ResourceUsage:
    """Measured and allocated execution resources."""

    duration: float | None  # Monotonic elapsed seconds.
    allocated_cpu: float | None  # Declared CPU capacity, not measured utilisation.
    cpu_seconds: float | None  # Measured cgroup or process CPU usage.
    peak_memory: int | None  # Peak resident/cgroup bytes when available.
    model_usage: dict[str, int] | None  # Observed input/output token counts.
    estimated_cost: str | None  # Decimal monetary estimate, not a binary float.
    pricing_version: str | None  # Price-source identity or null.
    bytes_written: int | None  # Measured output bytes within the attempt quota.


@dataclass(frozen=True, slots=True)
class Job:
    """Scheduled repetition job in the execution queue."""

    job_id: str  # Deterministic plan identity including run_id and repetition.
    run_id: str  # Parent audit UUID.
    task_key: str  # Frozen task version.
    case_id: str  # Patch case executed by this job.
    verifier_key: str  # Frozen verifier version.
    repetition: int  # Zero-based planned repetition index.
    state: Literal["PENDING", "CLAIMED", "RUNNING", "DONE", "FAILED", "ABANDONED"]  # Operational state.
    fence: int  # Monotonically increasing claim generation.
    attempt_id: str | None  # Current physical attempt UUID.
    lease_token: str | None  # Private random fencing secret, omitted from reports.
    worker_id: str | None  # Current worker identity.
    lease_expires_ms: int | None  # Controller UTC epoch deadline in milliseconds.
    attempts_started: int  # Physical attempts already consumed for this job.
    selected_attempt_id: str | None  # Authoritative terminal result, regardless of pass/fail.
    terminal_reason: str | None  # Failure, cancellation or exhaustion diagnostic.


@dataclass(frozen=True, slots=True)
class AcceptanceCell:
    """Aggregated outcome of all planned repetitions for a (task, case, verifier) cell."""

    task_key: str  # Task owning the case.
    repository_id: str  # Repository cluster for uncertainty estimates.
    case_id: str  # Case counted at most once per verifier.
    verifier_key: str  # Verifier represented by this row.
    adjudication_id: str  # Decision selected before execution.
    label: Literal["valid", "invalid", "unresolved"]  # Frozen adjudicated label.
    role: Literal["challenge", "reference", "noop"]  # Whether it belongs in primary rates.
    outcome: Literal["accept", "reject", "invalid_evaluation", "flaky", "error"]  # Aggregated observation.
    evaluation_validity: Literal["valid", "invalid"]  # Hard-rate denominator eligibility.
    planned_repetitions: int  # Required number from the manifest.
    selected_attempt_ids: tuple[str, ...]  # One terminal selection per repetition where available.
    excluded_attempt_ids: tuple[str, ...]  # Abandoned, stale and failed infrastructure retries.
    repetition_outcomes: tuple[str, ...]  # All planned repetition states in fixed order.
    diagnostic_codes: tuple[str, ...]  # Reasons the cell was unusable or unstable.


@dataclass(frozen=True, slots=True)
class MetricTerm:
    """Single-task terms contributing to a macro-averaged metric."""

    task_key: str  # Task receiving one macro-average weight.
    numerator: int  # Eligible errors of the requested kind.
    denominator: int  # Eligible cases for this task and label.
    excluded: dict[str, int]  # Counts by unresolved, control, flaky or execution reason.


@dataclass(frozen=True, slots=True)
class GateEvidence:
    """Specific case, witness, and execution evidence backing a CI gate decision."""

    rule_id: str  # Policy rule producing this finding.
    case_id: str  # Patch providing case-level evidence.
    adjudication_id: str  # Independent label identity.
    contract_hash: str  # Shared contract supporting the comparison.
    baseline_outcome: str  # Aggregated baseline observation.
    candidate_outcome: str  # Aggregated proposed-verifier observation.
    witness_ids: tuple[str, ...]  # Contract-linked counterexamples where relevant.
    artifact_digests: tuple[str, ...]  # Reproduction report and test-failure evidence.
    explanation: str  # Plain-language reason for the decision.


@dataclass(frozen=True, slots=True)
class ImportRequest:
    """CLI task import request parameters."""

    adapter: str  # local, swebench or supported harbor format.
    instance: str  # Exact source instance identifier.
    source: str  # Local manifest, pinned JSONL or frozen task directory.
    source_revision: str  # Dataset or repository revision identity.
    environment_manifest: str | None  # Required resolved harness metadata for SWE-bench.
    output_dir: str  # Destination for normalised manifests.
    dry_run: bool  # Validate without registry or output mutation.


@dataclass(frozen=True, slots=True)
class ImportBundle:
    """In-memory normalized bundle returned by a task adapter."""

    task: Task  # Normalised task record.
    contract: Contract  # Frozen requirements and unresolved questions.
    requirements: tuple[Requirement, ...]  # Explicit requirement records.
    snapshot: RepositorySnapshot  # Source archive identity.
    environment: Environment  # Execution environment identity.
    verifier: VerifierVersion  # Imported original grading logic.
    verifier_manifest: VerifierManifest  # Exact invocation and collection policy.
    controls: tuple[PatchCase, ...]  # Reference and no-op inputs without inferred labels.
    upstream_artifact: Artifact  # Preserved raw source record.
    diagnostics: tuple[str, ...]  # Nonfatal eligibility notes and unsupported features.


@dataclass(frozen=True, slots=True)
class LocalImportManifest:
    """Structure of a local task import manifest."""

    schema_version: str  # Native import format version.
    task: Task  # Task envelope data after local paths are resolved.
    contract_file: str  # Relative contract envelope path.
    snapshot_file: str  # Relative snapshot manifest path.
    environment_file: str  # Relative environment envelope path.
    requirement_files: tuple[str, ...]  # Relative requirement envelope paths.
    verifier_file: str  # Relative original verifier manifest path.
    control_files: tuple[str, ...]  # Explicit control case records.


@dataclass(frozen=True, slots=True)
class SandboxPolicy:
    """Resource constraints and security policies for candidate execution."""

    policy_hash: str  # Digest of canonical sandbox configuration.
    cpus: float  # Default 2.0 allocated CPUs.
    memory_bytes: int  # Default 2147483648 bytes; equal memory+swap limit.
    pids: int  # Default maximum 128 processes.
    wall_seconds: int  # Default 120 seconds including build and verification.
    cleanup_grace_seconds: int  # Default 5 seconds before forced termination.
    workspace_bytes: int  # Default 2147483648 bytes of attempt filesystem quota.
    workspace_inodes: int  # Default 100000 attempt inode cap.
    tmp_bytes: int  # Default 134217728 bytes of bounded tmpfs.
    artifact_bytes: int  # Default 16777216 aggregate retained artifact bytes.
    stream_bytes: int  # Default 4194304 bytes per stdout/stderr stream.
    artifact_files: int  # Default maximum 64 allowlisted regular output files.
    network: Literal["none"]  # MVP supports offline evaluation only.
    seccomp_digest: str  # Approved seccomp profile identity.
    max_jobs: int  # Default 1000 scheduled evaluations per audit.
    max_concurrency: int  # Default 1 in the Python worker.


@dataclass(frozen=True, slots=True)
class GatePolicy:
    """Configurable thresholds for CI release gating."""

    policy_hash: str  # Hash of the frozen full policy.
    scope: Literal["diagnostic", "panel_release", "research"]  # Strength of allowed conclusion.
    max_flaky_rate: float  # Default 0.0 for strict release.
    max_invalid_evaluation_rate: float  # Default 0.0 for strict release.
    max_error_rate: float  # Default 0.0 for strict release.
    min_valid_per_task: int  # Default 2 valid challenge alternatives.
    min_invalid_per_task: int  # Default 2 independently invalid challenges.
    min_paired_tasks: int  # Default 1 for a bounded local release decision.
    min_pair_coverage: float  # Default 1.0 of declared eligible cases.
    min_caught_invalid: int  # Default 1 newly rejected invalid case.
    min_iar_improvement: float  # Default 0.0 with a strictly negative paired delta.
    max_vrr_increase: float  # Default 0.0 on paired support.
    require_independent_review: bool  # True outside synthetic/provisional diagnostics.
    require_no_new_invalid_acceptance: bool  # True for initial release policy.
    require_controls_match: bool  # True; anomalous controls need an explanation/new policy.


@dataclass(frozen=True, slots=True)
class AnalysisPlan:
    """Pre-registered statistical analysis plan for assessment cohorts."""

    plan_hash: str  # Digest registered before assessment access.
    registered_at: datetime  # UTC timestamp in append-only registry.
    cohort_digest: str  # Sealed task/case/lineage assignment identity.
    verifier_candidates: tuple[str, ...]  # Fixed set of compared verifier versions.
    primary_outcomes: tuple[str, ...]  # IAR and VRR with definition versions.
    min_iar_improvement: float  # Chosen effect threshold before held-out execution.
    vrr_noninferiority_margin: float  # Maximum tolerated paired VRR increase.
    alpha: float  # Family-wise significance level, normally 0.05.
    bootstrap_draws: int  # Default 10000 paired hierarchical draws.
    seed: int  # Random generator seed fixed before analysis.
    budgets: dict[str, float]  # Test runtime, generation and review budgets by method.
    exclusions: tuple[str, ...]  # Prespecified missingness and admission rules.
    secondary_hypotheses: tuple[str, ...]  # Confirmatory family for Holm correction.
    stopping_rule: str  # Sample size/rerun criteria fixed before outcome inspection.


@dataclass(frozen=True, slots=True)
class TestResult:
    """Result of executing an individual collected test item."""

    test_id: str  # Canonical node ID including parameter identity.
    status: Literal["passed", "failed", "skipped", "error"]  # One result for each declared test.
    duration: float | None  # Observed test seconds.
    failure_digest: str | None  # Captured failure evidence artifact.


@dataclass(frozen=True, slots=True)
class TestReport:
    """Structured test outcome report from a test runner."""

    schema_version: str  # Report format version.
    collected_ids: tuple[str, ...]  # Full collection, even when execution fails.
    results: tuple[TestResult, ...]  # Results keyed uniquely by test ID.
    completed: bool  # Runner reports all required execution completed.
    runner_error: str | None  # Collection, setup or runner diagnostic.


@dataclass(frozen=True, slots=True)
class ExecutionCapture:
    """Low-level process execution capture recorded by a worker."""

    attempt_id: str  # Attempt that emitted these bytes.
    exit_code: int | None  # Worker-observed process status.
    timed_out: bool  # Worker monotonic deadline exceeded.
    oom_killed: bool | None  # Docker/cgroup observation, null if unavailable.
    cancelled: bool  # Controller cancellation observed.
    build_exit_code: int | None  # Isolated build result when a build ran.
    stdout_hash: str | None  # Captured stdout artifact identity.
    stderr_hash: str | None  # Captured stderr artifact identity.
    report_digest: str | None  # Structured raw report artifact identity.
    truncated: bool  # Output/stream cap was reached.
    resources: ResourceUsage  # Worker-measured resource use.
    runtime_error: str | None  # Launch/daemon/collection infrastructure failure.


@dataclass(frozen=True, slots=True)
class ParsedOutcome:
    """Classified evaluation outcome derived by parsing execution capture."""

    outcome: Literal["accept", "reject", "invalid_evaluation", "error"]  # Raw decision class.
    evaluation_validity: Literal["valid", "invalid"]  # Inclusion eligibility before repeats.
    error_code: str | None  # Machine-readable failure detail.
    report: TestReport | None  # Validated report or null.
    evidence_digests: tuple[str, ...]  # Bytes used in the classification.


@dataclass(frozen=True, slots=True)
class AuditOptions:
    """Parsed CLI options for verifierci audit."""

    task_files: tuple[str, ...]  # Explicit task manifests or resolved benchmark entries.
    benchmark_file: str | None  # Frozen benchmark input, exclusive with explicit tasks.
    panel_file: str  # Frozen panel file.
    baseline_file: str  # Verifier manifest or per-task mapping file.
    candidate_file: str  # Proposed verifier manifest or mapping file.
    repetitions: int  # Planned repeated executions, default 3.
    backend: Literal["fixture", "docker"]  # Explicit fixture opt-in or Docker default.
    trusted_fixture: bool  # Require installed reviewed fixture digest allowlist.
    sandbox_policy_file: str  # Resource/trust policy path.
    max_attempts: int  # Frozen infrastructure retry allowance.
    offline: bool  # Disable controller input fetch; candidates are always offline.
    output_dir: str | None  # Output location, derived from run ID if omitted.
    dry_run: bool  # Validate without mutation or execution.
    resume_run_id: str | None  # Existing immutable plan; excludes new-plan flags.
    parent_run_id: str | None  # Link a new diagnostic or reproduction run.
    policy_file: str  # Gate policy path.
    analysis_plan_file: str | None  # Mandatory for protected assessment.
    max_jobs: int  # Requested bound capped by sandbox policy.
    concurrency: int  # Requested concurrency capped by sandbox policy.
    timeout_seconds: int  # Attempt deadline capped by sandbox policy.
    seed: int | None  # Recorded controlled randomness.
    collect_only: bool  # Produce matrix without asserting a gate pass.
    diagnostic: bool  # Restrict conclusion when review or repetitions are insufficient.


@dataclass(frozen=True, slots=True)
class AuditResult:
    """Complete audit output artifact containing matrix, metrics, and gate decision."""

    manifest: Any  # AuditManifest
    matrix: AcceptanceMatrix | None  # Complete or explicitly provisional matrix.
    metrics: tuple[MetricResult, ...]  # Counts, rates, intervals and coverage.
    gate: GateDecision | None  # Null only before gating or in collect-only output.
    diagnostics: tuple[str, ...]  # Outstanding technical and methodological issues.
    artifacts: tuple[Artifact, ...]  # Reviewed artifact index without credentials.


@dataclass(frozen=True, slots=True)
class TelemetryEvent:
    """Structured audit observability event."""

    run_id: str  # Parent audit.
    attempt_id: str  # Physical execution identifier.
    task_id: str  # Stable task name.
    patch_digest: str  # Exact candidate patch bytes.
    verifier_version: str  # Pinned grader version.
    action_type: str  # claim, build, verify, collect, cleanup or observed tool action.
    duration: float | None  # Observed event elapsed time.
    exit_code: int | None  # Process status when applicable.
    stdout_hash: str | None  # Captured stream identity.
    stderr_hash: str | None  # Captured stream identity.
    test_collection: tuple[str, ...]  # Collected test IDs when known.
    tests_passed: int | None  # Observed count, null if unavailable.
    tests_failed: int | None  # Observed count, null if unavailable.
    allocated_cpu: float | None  # CPU allocation.
    cpu_seconds: float | None  # Actual measured CPU time.
    peak_memory: int | None  # Peak memory bytes.
    model_usage: dict[str, int] | None  # Actual usage only.
    estimated_cost: str | None  # Decimal estimated cost.
    pricing_version: str | None  # Identity of price assumptions.


@dataclass(frozen=True, slots=True)
class BootstrapResult:
    """Paired bootstrap confidence interval calculation results."""

    estimate: float | None  # Paired task-macro point estimate.
    low: float | None  # Lower interval endpoint.
    high: float | None  # Upper interval endpoint.
    seed: int  # Recorded random seed.
    valid_draws: int  # Number of defined bootstrap replicates.
    total_draws: int  # Number attempted under the plan.
    method: str  # Exact task/repository resampling definition.
    warnings: tuple[str, ...]  # Few clusters, undefined draws or zero observed variance.


@dataclass(frozen=True, slots=True)
class ReviewAgreement:
    """Inter-reviewer agreement metrics on patch cases."""

    paired_cases: int  # Cases with two eligible independent pre-consensus votes.
    raw_agreement: float | None  # Exact matching label proportion.
    cohens_kappa: float | None  # Two-reviewer chance-adjusted agreement when defined.
    unresolved_cases: int  # Original unresolved/disputed case count.
    warnings: tuple[str, ...]  # Degenerate prevalence or insufficient reviewer pairs.


@dataclass(frozen=True, slots=True)
class TrainingExample:
    """Reviewed training patch export record."""

    case_id: str  # Reviewed training patch.
    task_key: str  # Frozen task version.
    contract_hash: str  # Contract supporting the exported label.
    label: Literal["valid", "invalid"]  # Resolved independently reviewed label.
    adjudication_id: str  # Exact decision revision.
    patch_digest: str  # Exported patch artifact.
    witness_ids: tuple[str, ...]  # Invalidity evidence when relevant.
    family_id: str  # Split-protection lineage.
    parent_case_ids: tuple[str, ...]  # Derivation provenance.
    agent_run_id: str | None  # Generation identity where applicable.
    licence: str  # Explicit redistribution licence.
    exposure_digest: str  # Disclosure and split history.
    source_panel_key: str  # Must belong to a train-only panel.


@dataclass(frozen=True, slots=True)
class BenchmarkVersion:
    """Release manifest for a frozen benchmark cohort."""

    benchmark_key: str  # Human-readable benchmark name and version.
    task_keys: tuple[str, ...]  # Frozen task membership.
    panel_keys: tuple[str, ...]  # Frozen cohorts and case memberships.
    analysis_plan_hash: str | None  # Plan for published confirmatory results.
    release_digest: str  # Hash of canonical release inventory.
    created_at: datetime  # Release creation time.


class WorkerRequest(TypedDict):
    """Transport wire request for worker local Unix socket."""

    version: str  # Wire protocol version, initially 1.0.
    request_id: str  # UUID for idempotent transport handling.
    operation: str  # claim, heartbeat, started, complete, cancel-status or health.
    payload: dict[str, Any]  # Operation-specific schema-validated object.


class WorkerResponse(TypedDict):
    """Transport wire response for worker local Unix socket."""

    version: str  # Negotiated wire protocol version.
    request_id: str  # Echoed request UUID.
    ok: bool  # Transport operation success, not patch acceptance.
    payload: dict[str, Any]  # Job, lease, completion acknowledgement or health.
    diagnostic: str | None  # Machine-readable operation failure.


def validate_wire_version(version: str) -> None:
    """Validate that incoming wire request uses a supported protocol version."""
    if version not in SUPPORTED_WIRE_VERSIONS:
        raise ValidationError(
            f"Unsupported wire version '{version}'. Supported versions: {sorted(SUPPORTED_WIRE_VERSIONS)}."
        )


def encode_record(record: object) -> bytes:
    """Encode any domain dataclass or typed record into canonical JSON bytes."""
    return canonical_bytes(record)


_KIND_REGISTRY: dict[str, type] = {
    "ReviewVote": ReviewVote,
    "TaskPin": TaskPin,
    "ResourceUsage": ResourceUsage,
    "Job": Job,
    "AcceptanceCell": AcceptanceCell,
    "MetricTerm": MetricTerm,
    "GateEvidence": GateEvidence,
    "ImportRequest": ImportRequest,
    "ImportBundle": ImportBundle,
    "LocalImportManifest": LocalImportManifest,
    "SandboxPolicy": SandboxPolicy,
    "GatePolicy": GatePolicy,
    "AnalysisPlan": AnalysisPlan,
    "TestResult": TestResult,
    "TestReport": TestReport,
    "ExecutionCapture": ExecutionCapture,
    "ParsedOutcome": ParsedOutcome,
    "CommandSpec": CommandSpec,
    "AuditOptions": AuditOptions,
    "AuditResult": AuditResult,
    "TelemetryEvent": TelemetryEvent,
    "BootstrapResult": BootstrapResult,
    "ReviewAgreement": ReviewAgreement,
    "TrainingExample": TrainingExample,
    "BenchmarkVersion": BenchmarkVersion,
    "Task": Task,
    "Requirement": Requirement,
    "Contract": Contract,
    "RepositorySnapshot": RepositorySnapshot,
    "Environment": Environment,
    "PatchCase": PatchCase,
    "VerifierVersion": VerifierVersion,
    "VerifierManifest": VerifierManifest,
    "AcceptanceMatrix": AcceptanceMatrix,
    "MetricResult": MetricResult,
    "GateDecision": GateDecision,
    "Artifact": Artifact,
}


def _json_no_duplicates(ordered_pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    res: dict[str, Any] = {}
    for k, v in ordered_pairs:
        if k in res:
            raise ValidationError(f"Duplicate JSON key detected: '{k}'.")
        res[k] = v
    return res


def decode_record(kind: str, payload: bytes, *, max_bytes: int = 10 * 1024 * 1024) -> object:
    """Decode a canonical byte stream into a validated domain record."""
    if len(payload) > max_bytes:
        raise ValidationError(f"Payload size {len(payload)} bytes exceeds maximum {max_bytes} bytes.")

    if kind not in _KIND_REGISTRY:
        raise ValidationError(f"Unknown record kind: '{kind}'.")

    try:
        data = json.loads(payload.decode("utf-8"), object_pairs_hook=_json_no_duplicates)
    except Exception as exc:
        raise ValidationError(f"Invalid JSON payload: {exc}") from exc

    cls = _KIND_REGISTRY[kind]
    if not is_dataclass(cls):
        raise ValidationError(f"Target class {kind} is not a dataclass.")

    return _instantiate_dataclass(cls, data)


def _instantiate_dataclass(cls: type, data: Any) -> Any:
    if not isinstance(data, dict):
        raise ValidationError(f"Expected dict for dataclass {cls.__name__}, got {type(data).__name__}.")

    field_types = get_type_hints(cls)
    kwargs: dict[str, Any] = {}
    for f in fields(cls):
        if f.name not in data:
            raise ValidationError(f"Missing required field '{f.name}' for {cls.__name__}.")
        raw_val = data[f.name]
        target_type = field_types.get(f.name, Any)
        kwargs[f.name] = _convert_field(target_type, raw_val)
    return cls(**kwargs)


def _convert_field(target_type: Any, val: Any) -> Any:
    if val is None:
        return None
    if target_type is datetime:
        if isinstance(val, str):
            try:
                # Handle RFC 3339 format, e.g. 2026-09-18T16:00:00Z
                clean_str = val.replace("Z", "+00:00")
                dt = datetime.fromisoformat(clean_str)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except Exception as exc:
                raise ValidationError(f"Cannot parse datetime '{val}': {exc}") from exc
        return val

    # If target_type is a tuple
    origin = getattr(target_type, "__origin__", None)
    if origin is tuple:
        args = getattr(target_type, "__args__", ())
        if not isinstance(val, (list, tuple)):
            raise ValidationError(f"Expected tuple/list, got {type(val).__name__}.")
        if args and args[-1] is Ellipsis:
            elem_type = args[0]
            return tuple(_convert_field(elem_type, x) for x in val)
        return tuple(val)

    if is_dataclass(target_type):
        return _instantiate_dataclass(target_type, val)

    return val
