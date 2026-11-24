"""Unit tests for acceptance matrix builder and cell reducer.

SDD Section 8.4 and Section 4.1.
Tests repetition aggregation protocol:
- All accept -> accept (valid)
- All reject -> reject (valid)
- Mixed accept/reject -> flaky (invalid) without majority voting
- All invalid -> invalid_evaluation
- All error -> error
- Mixed valid and non-valid -> invalid_evaluation with instability_detected
- Duplicate job or attempt identity rejection
- Matrix completeness and hashing
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from verifierci.errors import ErrorCode, IdentityConflict, ValidationError
from verifierci.execution.matrix import (
    AcceptanceMatrixBuilder,
    aggregate_cell,
    build_matrix,
)
from verifierci.models.panel import Adjudication, PatchCase
from verifierci.models.protocol import Job, ResourceUsage, TaskPin
from verifierci.models.result import AcceptanceMatrix, AuditManifest, EvaluationAttempt


def _make_attempt(
    attempt_id: str,
    job_id: str,
    outcome: str | None,
    validity: str,
    error_code: str | None = None,
    disposition: str = "authoritative",
) -> EvaluationAttempt:
    return EvaluationAttempt(
        attempt_id=attempt_id,
        job_id=job_id,
        fence=1,
        outcome=outcome,  # type: ignore[arg-type]
        evaluation_validity=validity,  # type: ignore[arg-type]
        error_code=error_code,
        disposition=disposition,  # type: ignore[arg-type]
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        exit_code=0 if outcome == "accept" else 1,
        stdout_hash=None,
        stderr_hash=None,
        report_digest=None,
        test_collection=("t1",),
        tests_passed=1 if outcome == "accept" else 0,
        tests_failed=0 if outcome == "accept" else 1,
        resources=ResourceUsage(
            duration=1.0,
            allocated_cpu=1.0,
            cpu_seconds=1.0,
            peak_memory=None,
            model_usage=None,
            estimated_cost=None,
            pricing_version=None,
            bytes_written=0,
        ),
        artifact_digests=(),
        capture_truncated=False,
    )


def _make_manifest(
    run_id: str = "run-1",
    max_repetitions: int = 1,
) -> AuditManifest:
    return AuditManifest(
        manifest_hash="mhash" + "0" * 59,
        run_id=run_id,
        benchmark_version="v1",
        task_pins=(),
        panel_key="panel@1.0",
        adjudication_version="adj-v1",
        evaluation_harness_version="harn-v1",
        config_hash="conf1" + "0" * 59,
        policy_hash="pol1" + "0" * 60,
        analysis_plan_hash=None,
        timestamp=datetime.now(UTC),
        host_fingerprint="arm64",
        seed=42,
        agent_version=None,
        model_identifier=None,
        max_repetitions=max_repetitions,
        max_attempts_per_job=3,
        timeout_seconds=120,
        resource_policy="res1" + "0" * 60,
        expansion_digest="exp1" + "0" * 60,
        parent_run_id=None,
    )


def test_aggregate_cell_all_accept() -> None:
    attempts = [
        _make_attempt("a1", "j0", "accept", "valid"),
        _make_attempt("a2", "j1", "accept", "valid"),
        _make_attempt("a3", "j2", "accept", "valid"),
    ]
    job_rep = {"j0": 0, "j1": 1, "j2": 2}
    cell = aggregate_cell(
        task_key="task-1",
        repository_id="repo-1",
        case_id="case-1",
        verifier_key="v-1",
        adjudication_id="adj-1",
        label="valid",
        role="challenge",
        planned_repetitions=3,
        attempts=attempts,
        job_repetition_map=job_rep,
    )
    assert cell.outcome == "accept"
    assert cell.evaluation_validity == "valid"
    assert cell.repetition_outcomes == ("accept", "accept", "accept")


def test_aggregate_cell_all_reject() -> None:
    attempts = [
        _make_attempt("a1", "j0", "reject", "valid"),
        _make_attempt("a2", "j1", "reject", "valid"),
        _make_attempt("a3", "j2", "reject", "valid"),
    ]
    job_rep = {"j0": 0, "j1": 1, "j2": 2}
    cell = aggregate_cell(
        task_key="task-1",
        repository_id="repo-1",
        case_id="case-1",
        verifier_key="v-1",
        adjudication_id="adj-1",
        label="invalid",
        role="challenge",
        planned_repetitions=3,
        attempts=attempts,
        job_repetition_map=job_rep,
    )
    assert cell.outcome == "reject"
    assert cell.evaluation_validity == "valid"
    assert cell.repetition_outcomes == ("reject", "reject", "reject")


def test_aggregate_cell_mixed_flaky_no_majority_voting() -> None:
    # 2 accepts, 1 reject -> must be FLAKY, not accept
    attempts = [
        _make_attempt("a1", "j0", "accept", "valid"),
        _make_attempt("a2", "j1", "accept", "valid"),
        _make_attempt("a3", "j2", "reject", "valid"),
    ]
    job_rep = {"j0": 0, "j1": 1, "j2": 2}
    cell = aggregate_cell(
        task_key="task-1",
        repository_id="repo-1",
        case_id="case-1",
        verifier_key="v-1",
        adjudication_id="adj-1",
        label="valid",
        role="challenge",
        planned_repetitions=3,
        attempts=attempts,
        job_repetition_map=job_rep,
    )
    assert cell.outcome == "flaky"
    assert cell.evaluation_validity == "invalid"
    assert "FLAKY" in cell.diagnostic_codes


def test_aggregate_cell_all_invalid() -> None:
    attempts = [
        _make_attempt(
            "a1", "j0", "invalid_evaluation", "invalid", error_code="TIMEOUT"
        ),
        _make_attempt(
            "a2", "j1", "invalid_evaluation", "invalid", error_code="TIMEOUT"
        ),
        _make_attempt(
            "a3", "j2", "invalid_evaluation", "invalid", error_code="TIMEOUT"
        ),
    ]
    job_rep = {"j0": 0, "j1": 1, "j2": 2}
    cell = aggregate_cell(
        task_key="task-1",
        repository_id="repo-1",
        case_id="case-1",
        verifier_key="v-1",
        adjudication_id="adj-1",
        label="valid",
        role="challenge",
        planned_repetitions=3,
        attempts=attempts,
        job_repetition_map=job_rep,
    )
    assert cell.outcome == "invalid_evaluation"
    assert cell.evaluation_validity == "invalid"
    assert "TIMEOUT" in cell.diagnostic_codes


def test_aggregate_cell_all_error() -> None:
    attempts = [
        _make_attempt("a1", "j0", "error", "invalid", error_code="CRASH"),
        _make_attempt("a2", "j1", "error", "invalid", error_code="CRASH"),
        _make_attempt("a3", "j2", "error", "invalid", error_code="CRASH"),
    ]
    job_rep = {"j0": 0, "j1": 1, "j2": 2}
    cell = aggregate_cell(
        task_key="task-1",
        repository_id="repo-1",
        case_id="case-1",
        verifier_key="v-1",
        adjudication_id="adj-1",
        label="valid",
        role="challenge",
        planned_repetitions=3,
        attempts=attempts,
        job_repetition_map=job_rep,
    )
    assert cell.outcome == "error"
    assert cell.evaluation_validity == "invalid"


def test_aggregate_cell_mixed_valid_and_nonvalid() -> None:
    # 2 accepts and 1 timeout -> instability_detected
    attempts = [
        _make_attempt("a1", "j0", "accept", "valid"),
        _make_attempt("a2", "j1", "accept", "valid"),
        _make_attempt(
            "a3", "j2", "invalid_evaluation", "invalid", error_code="TIMEOUT"
        ),
    ]
    job_rep = {"j0": 0, "j1": 1, "j2": 2}
    cell = aggregate_cell(
        task_key="task-1",
        repository_id="repo-1",
        case_id="case-1",
        verifier_key="v-1",
        adjudication_id="adj-1",
        label="valid",
        role="challenge",
        planned_repetitions=3,
        attempts=attempts,
        job_repetition_map=job_rep,
    )
    assert cell.outcome == "invalid_evaluation"
    assert cell.evaluation_validity == "invalid"
    assert "instability_detected" in cell.diagnostic_codes


def test_aggregate_cell_incomplete_repetitions() -> None:
    attempts = [
        _make_attempt("a1", "j0", "accept", "valid"),
    ]
    job_rep = {"j0": 0}
    cell = aggregate_cell(
        task_key="task-1",
        repository_id="repo-1",
        case_id="case-1",
        verifier_key="v-1",
        adjudication_id="adj-1",
        label="valid",
        role="challenge",
        planned_repetitions=3,
        attempts=attempts,
        job_repetition_map=job_rep,
    )
    assert cell.outcome == "invalid_evaluation"
    assert cell.evaluation_validity == "invalid"
    assert "INCOMPLETE_REPETITIONS" in cell.diagnostic_codes


def test_build_matrix_duplicate_job_id() -> None:
    manifest = AuditManifest(
        manifest_hash="mhash" + "0" * 59,
        run_id="run-1",
        benchmark_version="v1",
        task_pins=(),
        panel_key="panel@1.0",
        adjudication_version="adj-v1",
        evaluation_harness_version="harn-v1",
        config_hash="conf1" + "0" * 59,
        policy_hash="pol1" + "0" * 60,
        analysis_plan_hash=None,
        timestamp=datetime.now(UTC),
        host_fingerprint="arm64",
        seed=42,
        agent_version=None,
        model_identifier=None,
        max_repetitions=3,
        max_attempts_per_job=3,
        timeout_seconds=120,
        resource_policy="res1" + "0" * 60,
        expansion_digest="exp1" + "0" * 60,
        parent_run_id=None,
    )
    j1 = Job(
        job_id="dup-job",
        run_id="run-1",
        task_key="task-1",
        case_id="c-1",
        verifier_key="v-1",
        repetition=0,
        state="DONE",
        fence=1,
        attempt_id="a1",
        lease_token="t",
        worker_id="w",
        lease_expires_ms=0,
        attempts_started=1,
        selected_attempt_id="a1",
        terminal_reason=None,
    )
    with pytest.raises(IdentityConflict):
        build_matrix(manifest, [j1, j1], [], {}, {})


def test_build_matrix_builder_success() -> None:
    manifest = AuditManifest(
        manifest_hash="mhash" + "0" * 59,
        run_id="run-1",
        benchmark_version="v1",
        task_pins=(),
        panel_key="panel@1.0",
        adjudication_version="adj-v1",
        evaluation_harness_version="harn-v1",
        config_hash="conf1" + "0" * 59,
        policy_hash="pol1" + "0" * 60,
        analysis_plan_hash=None,
        timestamp=datetime.now(UTC),
        host_fingerprint="arm64",
        seed=42,
        agent_version=None,
        model_identifier=None,
        max_repetitions=1,
        max_attempts_per_job=3,
        timeout_seconds=120,
        resource_policy="res1" + "0" * 60,
        expansion_digest="exp1" + "0" * 60,
        parent_run_id=None,
    )
    job = Job(
        job_id="j1",
        run_id="run-1",
        task_key="task-1",
        case_id="case-1",
        verifier_key="v-1",
        repetition=0,
        state="DONE",
        fence=1,
        attempt_id="a1",
        lease_token="t",
        worker_id="w",
        lease_expires_ms=0,
        attempts_started=1,
        selected_attempt_id="a1",
        terminal_reason=None,
    )
    att = _make_attempt("a1", "j1", "accept", "valid")
    case = PatchCase(
        case_id="case-1",
        task_key="task-1",
        diff_digest="diff" + "0" * 60,
        base_snapshot_digest="snap" + "0" * 60,
        source="reference",
        source_run_id=None,
        parent_case_ids=(),
        family_id="fam-1",
        role="challenge",
        provenance_digest="prov" + "0" * 60,
        licence="MIT",
        created_at=datetime.now(UTC),
    )
    adj = Adjudication(
        adjudication_id="adj-1",
        case_id="case-1",
        contract_hash="con" + "0" * 61,
        version=1,
        label="valid",
        review_status="independent",
        votes=(),
        rationale="reviewed",
        requirement_hashes=(),
        witness_ids=(),
        uncertainty="none",
        supersedes_id=None,
        created_at=datetime.now(UTC),
    )

    builder = AcceptanceMatrixBuilder(manifest)
    matrix = builder.build(
        jobs=[job],
        attempts=[att],
        adjudications={"case-1": adj},
        cases={"case-1": case},
    )

    assert isinstance(matrix, AcceptanceMatrix)
    assert matrix.run_id == "run-1"
    assert matrix.complete is True
    assert len(matrix.cells) == 1
    assert matrix.cells[0].outcome == "accept"


def test_build_matrix_duplicate_attempt_id() -> None:
    manifest = AuditManifest(
        manifest_hash="mhash" + "0" * 59,
        run_id="run-1",
        benchmark_version="v1",
        task_pins=(),
        panel_key="panel@1.0",
        adjudication_version="adj-v1",
        evaluation_harness_version="harn-v1",
        config_hash="conf1" + "0" * 59,
        policy_hash="pol1" + "0" * 60,
        analysis_plan_hash=None,
        timestamp=datetime.now(UTC),
        host_fingerprint="arm64",
        seed=42,
        agent_version=None,
        model_identifier=None,
        max_repetitions=1,
        max_attempts_per_job=3,
        timeout_seconds=120,
        resource_policy="res1" + "0" * 60,
        expansion_digest="exp1" + "0" * 60,
        parent_run_id=None,
    )
    job = Job(
        job_id="j1",
        run_id="run-1",
        task_key="task-1",
        case_id="case-1",
        verifier_key="v-1",
        repetition=0,
        state="DONE",
        fence=1,
        attempt_id="a1",
        lease_token="t",
        worker_id="w",
        lease_expires_ms=0,
        attempts_started=1,
        selected_attempt_id="a1",
        terminal_reason=None,
    )
    att1 = _make_attempt("dup-att", "j1", "accept", "valid")
    att2 = _make_attempt("dup-att", "j1", "accept", "valid")
    with pytest.raises(IdentityConflict):
        build_matrix(manifest, [job], [att1, att2], {}, {})


def test_aggregate_cell_with_stale_and_multiple_attempts() -> None:
    # 2 attempts for repetition 0: 1 stale (failed infrastructure retry), 1 authoritative
    att_stale = _make_attempt(
        "a0_stale",
        "j0",
        "invalid_evaluation",
        "invalid",
        error_code="CRASH",
        disposition="stale",
    )
    att_auth = _make_attempt(
        "a0_auth", "j0", "accept", "valid", disposition="authoritative"
    )
    cell = aggregate_cell(
        task_key="task-1",
        repository_id="repo-1",
        case_id="case-1",
        verifier_key="v-1",
        adjudication_id="adj-1",
        label="valid",
        role="challenge",
        planned_repetitions=1,
        attempts=[att_stale, att_auth],
        job_repetition_map={"j0": 0},
    )
    assert cell.outcome == "accept"
    assert cell.selected_attempt_ids == ("a0_auth",)
    assert cell.excluded_attempt_ids == ("a0_stale",)


def test_build_matrix_with_indirect_adjudication_and_repo_map() -> None:
    manifest = AuditManifest(
        manifest_hash="mhash" + "0" * 59,
        run_id="run-1",
        benchmark_version="v1",
        task_pins=(),
        panel_key="panel@1.0",
        adjudication_version="adj-v1",
        evaluation_harness_version="harn-v1",
        config_hash="conf1" + "0" * 59,
        policy_hash="pol1" + "0" * 60,
        analysis_plan_hash=None,
        timestamp=datetime.now(UTC),
        host_fingerprint="arm64",
        seed=42,
        agent_version=None,
        model_identifier=None,
        max_repetitions=1,
        max_attempts_per_job=3,
        timeout_seconds=120,
        resource_policy="res1" + "0" * 60,
        expansion_digest="exp1" + "0" * 60,
        parent_run_id=None,
    )
    job = Job(
        job_id="j1",
        run_id="run-1",
        task_key="task-1",
        case_id="case-1",
        verifier_key="v-1",
        repetition=0,
        state="DONE",
        fence=1,
        attempt_id="a1",
        lease_token="t",
        worker_id="w",
        lease_expires_ms=0,
        attempts_started=1,
        selected_attempt_id="a1",
        terminal_reason=None,
    )
    att = _make_attempt("a1", "j1", "accept", "valid")
    adj = Adjudication(
        adjudication_id="adj-key-1",
        case_id="case-1",
        contract_hash="con" + "0" * 61,
        version=1,
        label="valid",
        review_status="independent",
        votes=(),
        rationale="reviewed",
        requirement_hashes=(),
        witness_ids=(),
        uncertainty="none",
        supersedes_id=None,
        created_at=datetime.now(UTC),
    )
    # Adjudication keyed by adjudication_id instead of case_id
    matrix = build_matrix(
        manifest=manifest,
        jobs=[job],
        attempts=[att],
        adjudications={"adj-key-1": adj},
        cases={},
        repository_map={"task-1": "repo-custom"},
    )
    assert matrix.cells[0].repository_id == "repo-custom"
    assert matrix.cells[0].adjudication_id == "adj-key-1"


def test_aggregate_cell_unmapped_and_out_of_bound_attempts() -> None:
    attempts = [
        _make_attempt("a0", "j0", "accept", "valid"),
        _make_attempt("a_unmapped", "j_unknown", "accept", "valid"),
        _make_attempt("a_oob", "j_oob", "accept", "valid"),
    ]
    job_rep = {"j0": 0, "j_oob": 99}
    cell = aggregate_cell(
        task_key="task-1",
        repository_id="repo-1",
        case_id="case-1",
        verifier_key="v-1",
        adjudication_id="adj-1",
        label="valid",
        role="challenge",
        planned_repetitions=1,
        attempts=attempts,
        job_repetition_map=job_rep,
    )
    assert "a_unmapped" in cell.excluded_attempt_ids
    assert "a_oob" in cell.excluded_attempt_ids
    assert cell.selected_attempt_ids == ("a0",)


def test_aggregate_cell_stale_or_abandoned_outcome_alignment() -> None:
    attempts = [
        _make_attempt("a0", "j0", "accept", "valid"),
        _make_attempt("a1", "j1", None, "invalid", disposition="abandoned"),
    ]
    job_rep = {"j0": 0, "j1": 1}
    cell = aggregate_cell(
        task_key="task-1",
        repository_id="repo-1",
        case_id="case-1",
        verifier_key="v-1",
        adjudication_id="adj-1",
        label="valid",
        role="challenge",
        planned_repetitions=2,
        attempts=attempts,
        job_repetition_map=job_rep,
    )
    assert cell.repetition_outcomes == ("accept", "pending")
    assert len(cell.repetition_outcomes) == 2
    assert "a1" in cell.excluded_attempt_ids


def test_build_matrix_unknown_job_raises() -> None:
    manifest = _make_manifest()
    job = Job(
        job_id="j1",
        run_id="run-1",
        task_key="task-1",
        case_id="case-1",
        verifier_key="v-1",
        repetition=0,
        state="DONE",
        fence=1,
        attempt_id="a1",
        lease_token="t",
        worker_id="w",
        lease_expires_ms=0,
        attempts_started=1,
        selected_attempt_id="a1",
        terminal_reason=None,
    )
    att_unknown = _make_attempt("a2", "nonexistent_job", "accept", "valid")
    with pytest.raises(IdentityConflict) as exc:
        build_matrix(
            manifest=manifest,
            jobs=[job],
            attempts=[att_unknown],
            adjudications={},
            cases={},
        )
    assert "references unknown job_id" in str(exc.value)


def test_aggregate_cell_deterministic_attempt_selection_order() -> None:
    # att_old has lower fence and earlier started_at
    att_old = EvaluationAttempt(
        attempt_id="att_old",
        job_id="j0",
        fence=1,
        outcome="reject",
        evaluation_validity="valid",
        error_code=None,
        disposition="authoritative",
        started_at=datetime(2026, 9, 21, 10, 0, 0, tzinfo=UTC),
        finished_at=datetime(2026, 9, 21, 10, 1, 0, tzinfo=UTC),
        exit_code=1,
        stdout_hash=None,
        stderr_hash=None,
        report_digest=None,
        test_collection=("t1",),
        tests_passed=0,
        tests_failed=1,
        resources=ResourceUsage(
            duration=1.0,
            allocated_cpu=1.0,
            cpu_seconds=1.0,
            peak_memory=None,
            model_usage=None,
            estimated_cost=None,
            pricing_version=None,
            bytes_written=0,
        ),
        artifact_digests=(),
        capture_truncated=False,
    )
    # att_new has higher fence and later started_at
    att_new = EvaluationAttempt(
        attempt_id="att_new",
        job_id="j0",
        fence=2,
        outcome="accept",
        evaluation_validity="valid",
        error_code=None,
        disposition="authoritative",
        started_at=datetime(2026, 9, 21, 10, 5, 0, tzinfo=UTC),
        finished_at=datetime(2026, 9, 21, 10, 6, 0, tzinfo=UTC),
        exit_code=0,
        stdout_hash=None,
        stderr_hash=None,
        report_digest=None,
        test_collection=("t1",),
        tests_passed=1,
        tests_failed=0,
        resources=ResourceUsage(
            duration=1.0,
            allocated_cpu=1.0,
            cpu_seconds=1.0,
            peak_memory=None,
            model_usage=None,
            estimated_cost=None,
            pricing_version=None,
            bytes_written=0,
        ),
        artifact_digests=(),
        capture_truncated=False,
    )

    # Pass in reversed order: [att_new, att_old]
    cell = aggregate_cell(
        task_key="task-1",
        repository_id="repo-1",
        case_id="case-1",
        verifier_key="v-1",
        adjudication_id="adj-1",
        label="valid",
        role="challenge",
        planned_repetitions=1,
        attempts=[att_new, att_old],
        job_repetition_map={"j0": 0},
    )

    # Must select att_new (max by fence, started_at, attempt_id)
    assert cell.selected_attempt_ids == ("att_new",)
    assert cell.repetition_outcomes == ("accept",)
    assert "att_old" in cell.excluded_attempt_ids


def test_aggregate_cell_flaky_with_execution_error() -> None:
    """SDD Section 8.4: accept + reject + error -> flaky with execution-error flag."""
    attempts = [
        _make_attempt("a0", "j0", "accept", "valid"),
        _make_attempt("a1", "j1", "reject", "valid"),
        _make_attempt("a2", "j2", "error", "invalid", error_code="CRASH"),
    ]
    cell = aggregate_cell(
        task_key="task-1",
        repository_id="repo-1",
        case_id="case-1",
        verifier_key="v-1",
        adjudication_id="adj-1",
        label="valid",
        role="challenge",
        planned_repetitions=3,
        attempts=attempts,
        job_repetition_map={"j0": 0, "j1": 1, "j2": 2},
    )
    assert cell.outcome == "flaky"
    assert cell.evaluation_validity == "invalid"
    assert "FLAKY" in cell.diagnostic_codes
    assert "execution_error" in cell.diagnostic_codes
    assert "CRASH" in cell.diagnostic_codes


def test_aggregate_cell_active_attempt_not_selected_as_terminal() -> None:
    """An active in-flight attempt must remain pending and not enter selected_attempt_ids."""
    att_active = _make_attempt("a_act", "j0", None, "pending", disposition="active")
    cell = aggregate_cell(
        task_key="task-1",
        repository_id="repo-1",
        case_id="case-1",
        verifier_key="v-1",
        adjudication_id="adj-1",
        label="valid",
        role="challenge",
        planned_repetitions=1,
        attempts=[att_active],
        job_repetition_map={"j0": 0},
    )
    assert cell.selected_attempt_ids == ()
    assert cell.repetition_outcomes == ("pending",)
    assert "INCOMPLETE_REPETITIONS" in cell.diagnostic_codes


@pytest.mark.parametrize(
    "pending_state",
    ["PENDING", "CLAIMED", "RUNNING", "ABANDONED"],
)
def test_build_matrix_refuses_finalization_with_pending_jobs(
    pending_state: str,
) -> None:
    """SDD Section 2.2 & 4.1: Refuse finalization if any planned job remains non-terminal."""
    manifest = _make_manifest(max_repetitions=2)
    j0 = Job(
        job_id="j0",
        run_id="run-1",
        task_key="task-1",
        case_id="case-1",
        verifier_key="v-1",
        repetition=0,
        state="DONE",
        fence=1,
        attempt_id="a0",
        lease_token=None,
        worker_id=None,
        lease_expires_ms=None,
        attempts_started=1,
        selected_attempt_id="a0",
        terminal_reason=None,
    )
    j1 = Job(
        job_id="j1",
        run_id="run-1",
        task_key="task-1",
        case_id="case-1",
        verifier_key="v-1",
        repetition=1,
        state=pending_state,  # type: ignore[arg-type]
        fence=1 if pending_state != "PENDING" else 0,
        attempt_id="a1" if pending_state != "PENDING" else None,
        lease_token=None,
        worker_id=None,
        lease_expires_ms=None,
        attempts_started=1 if pending_state != "PENDING" else 0,
        selected_attempt_id=None,
        terminal_reason=None,
    )
    att0 = _make_attempt("a0", "j0", "accept", "valid")

    with pytest.raises(
        ValidationError, match="Cannot finalize acceptance matrix"
    ) as exc:
        build_matrix(manifest, [j0, j1], [att0])
    assert exc.value.code == ErrorCode.VALIDATION_ERROR.value

    # Explicit provisional=True succeeds with complete=False
    provisional_matrix = build_matrix(manifest, [j0, j1], [att0], provisional=True)
    assert provisional_matrix.complete is False
    assert len(provisional_matrix.cells) == 1
    assert provisional_matrix.cells[0].repetition_outcomes == ("accept", "pending")
    assert "INCOMPLETE_REPETITIONS" in provisional_matrix.cells[0].diagnostic_codes


def test_build_matrix_refuses_finalization_when_planned_pin_jobs_missing() -> None:
    """Refuse finalization if manifest task_pins expect jobs not present in queue."""
    pin = TaskPin(
        task_key="task-1",
        task_version="1.0",
        contract_hash="c" * 64,
        repository_snapshot_digest="s" * 64,
        environment_id="env1",
        environment_image_digest=None,
        verifier_baseline_version="v-1",
        verifier_candidate_version="v-2",
        baseline_manifest_hash="b" * 64,
        candidate_manifest_hash="d" * 64,
        case_ids=("case-1",),
    )
    manifest = AuditManifest(
        manifest_hash="mhash" + "0" * 59,
        run_id="run-1",
        benchmark_version="v1",
        task_pins=(pin,),
        panel_key="panel@1.0",
        adjudication_version="adj-v1",
        evaluation_harness_version="harn-v1",
        config_hash="conf1" + "0" * 59,
        policy_hash="pol1" + "0" * 60,
        analysis_plan_hash=None,
        timestamp=datetime.now(UTC),
        host_fingerprint="arm64",
        seed=42,
        agent_version=None,
        model_identifier=None,
        max_repetitions=1,
        max_attempts_per_job=3,
        timeout_seconds=120,
        resource_policy="res1" + "0" * 60,
        expansion_digest="exp1" + "0" * 60,
        parent_run_id=None,
    )
    # Only supply v-1 job; v-2 job is missing
    j_v1 = Job(
        job_id="j1",
        run_id="run-1",
        task_key="task-1",
        case_id="case-1",
        verifier_key="v-1",
        repetition=0,
        state="DONE",
        fence=1,
        attempt_id="a1",
        lease_token=None,
        worker_id=None,
        lease_expires_ms=None,
        attempts_started=1,
        selected_attempt_id="a1",
        terminal_reason=None,
    )
    att = _make_attempt("a1", "j1", "accept", "valid")

    with pytest.raises(ValidationError, match="missing from execution queue"):
        build_matrix(manifest, [j_v1], [att])

    prov = build_matrix(manifest, [j_v1], [att], provisional=True)
    assert prov.complete is False
    assert len(prov.cells) == 2
    assert prov.cells[1].verifier_key == "v-2"
    assert "INCOMPLETE_REPETITIONS" in prov.cells[1].diagnostic_codes


def test_build_matrix_fenced_selected_attempt_validation() -> None:
    """Verify job.selected_attempt_id fencing checks and conflict detection."""
    manifest = _make_manifest(max_repetitions=1)
    job = Job(
        job_id="j1",
        run_id="run-1",
        task_key="task-1",
        case_id="case-1",
        verifier_key="v-1",
        repetition=0,
        state="DONE",
        fence=2,
        attempt_id="a_sel",
        lease_token=None,
        worker_id=None,
        lease_expires_ms=None,
        attempts_started=2,
        selected_attempt_id="a_sel",
        terminal_reason=None,
    )

    # Missing selected attempt -> IdentityConflict
    with pytest.raises(IdentityConflict, match="missing from attempts"):
        build_matrix(manifest, [job], [])

    # Selected attempt is stale instead of authoritative -> IdentityConflict
    att_stale = _make_attempt(
        "a_sel", "j1", "invalid_evaluation", "invalid", disposition="stale"
    )
    with pytest.raises(IdentityConflict, match="must have disposition 'authoritative'"):
        build_matrix(manifest, [job], [att_stale])

    # Multiple authoritative attempts for same fenced job -> IdentityConflict
    att_auth1 = _make_attempt("a_sel", "j1", "accept", "valid")
    att_auth2 = _make_attempt("a_other", "j1", "reject", "valid")
    with pytest.raises(IdentityConflict, match="multiple authoritative attempts"):
        build_matrix(manifest, [job], [att_auth1, att_auth2])


def test_build_matrix_run_id_and_coordinate_conflicts() -> None:
    """Reject mismatched run_id and duplicate job coordinates."""
    manifest = _make_manifest(run_id="run-1", max_repetitions=1)
    wrong_run_job = Job(
        job_id="j1",
        run_id="other-run",
        task_key="task-1",
        case_id="case-1",
        verifier_key="v-1",
        repetition=0,
        state="DONE",
        fence=1,
        attempt_id="a1",
        lease_token=None,
        worker_id=None,
        lease_expires_ms=None,
        attempts_started=1,
        selected_attempt_id="a1",
        terminal_reason=None,
    )
    with pytest.raises(IdentityConflict, match="does not match manifest run_id"):
        build_matrix(manifest, [wrong_run_job], [])

    j_a = Job(
        job_id="j_a",
        run_id="run-1",
        task_key="task-1",
        case_id="case-1",
        verifier_key="v-1",
        repetition=0,
        state="DONE",
        fence=1,
        attempt_id="a1",
        lease_token=None,
        worker_id=None,
        lease_expires_ms=None,
        attempts_started=1,
        selected_attempt_id="a1",
        terminal_reason=None,
    )
    j_b = Job(
        job_id="j_b",
        run_id="run-1",
        task_key="task-1",
        case_id="case-1",
        verifier_key="v-1",
        repetition=0,
        state="DONE",
        fence=1,
        attempt_id="a2",
        lease_token=None,
        worker_id=None,
        lease_expires_ms=None,
        attempts_started=1,
        selected_attempt_id="a2",
        terminal_reason=None,
    )
    with pytest.raises(IdentityConflict, match="Duplicate job coordinate"):
        build_matrix(manifest, [j_a, j_b], [])


def test_build_matrix_phase1_vertical_slice_30_jobs_to_10_cells() -> None:
    """Phase 1 slice: 1 task * 5 cases * 2 verifiers * 3 reps = 30 jobs -> 10 cells."""
    case_ids = ("c1", "c2", "c3", "c4", "c5")
    verifiers = ("v1", "v2")
    pin = TaskPin(
        task_key="retry-contract@1.0.0",
        task_version="1.0.0",
        contract_hash="c" * 64,
        repository_snapshot_digest="s" * 64,
        environment_id="env-fixture",
        environment_image_digest=None,
        verifier_baseline_version="v1",
        verifier_candidate_version="v2",
        baseline_manifest_hash="b" * 64,
        candidate_manifest_hash="d" * 64,
        case_ids=case_ids,
    )
    manifest = AuditManifest(
        manifest_hash="mhash" + "0" * 59,
        run_id="slice-run",
        benchmark_version="v1",
        task_pins=(pin,),
        panel_key="retry-contract-panel@1.0.0",
        adjudication_version="adj-v1",
        evaluation_harness_version="harn-v1",
        config_hash="conf1" + "0" * 59,
        policy_hash="pol1" + "0" * 60,
        analysis_plan_hash=None,
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        host_fingerprint="arm64",
        seed=42,
        agent_version=None,
        model_identifier=None,
        max_repetitions=3,
        max_attempts_per_job=3,
        timeout_seconds=120,
        resource_policy="res1" + "0" * 60,
        expansion_digest="exp1" + "0" * 60,
        parent_run_id=None,
    )

    jobs: list[Job] = []
    attempts: list[EvaluationAttempt] = []
    cases_dict: dict[str, PatchCase] = {}
    adjs_dict: dict[str, Adjudication] = {}

    for c_idx, cid in enumerate(case_ids):
        role = "reference" if c_idx == 0 else ("noop" if c_idx == 4 else "challenge")
        label = "valid" if c_idx in (0, 1, 4) else "invalid"
        cases_dict[cid] = PatchCase(
            case_id=cid,
            task_key="retry-contract@1.0.0",
            diff_digest="d" * 64,
            base_snapshot_digest="s" * 64,
            source="reference"
            if role == "reference"
            else ("noop" if role == "noop" else "human"),
            source_run_id=None,
            parent_case_ids=(),
            family_id=f"fam-{c_idx}",
            role=role,  # type: ignore[arg-type]
            provenance_digest="p" * 64,
            licence="MIT",
            created_at=datetime(2026, 1, 1, tzinfo=UTC),
        )
        adjs_dict[cid] = Adjudication(
            adjudication_id=f"adj-{cid}",
            case_id=cid,
            contract_hash="c" * 64,
            version=1,
            label=label,  # type: ignore[arg-type]
            review_status="provisional",
            votes=(),
            rationale="synthetic fixture",
            requirement_hashes=(),
            witness_ids=(),
            uncertainty="none",
            supersedes_id=None,
            created_at=datetime(2026, 1, 1, tzinfo=UTC),
        )

        for vid in verifiers:
            for rep in range(3):
                jid = f"job-{cid}-{vid}-{rep}"
                aid = f"att-{cid}-{vid}-{rep}"
                # v1 accepts all; v2 rejects invalid cases & c1 alt
                outcome = "accept" if vid == "v1" or c_idx in (0, 4) else "reject"
                jobs.append(
                    Job(
                        job_id=jid,
                        run_id="slice-run",
                        task_key="retry-contract@1.0.0",
                        case_id=cid,
                        verifier_key=vid,
                        repetition=rep,
                        state="DONE",
                        fence=1,
                        attempt_id=aid,
                        lease_token=None,
                        worker_id=None,
                        lease_expires_ms=None,
                        attempts_started=1,
                        selected_attempt_id=aid,
                        terminal_reason=None,
                    )
                )
                attempts.append(_make_attempt(aid, jid, outcome, "valid"))

    assert len(jobs) == 30
    ts = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    m1 = build_matrix(manifest, jobs, attempts, adjs_dict, cases_dict, created_at=ts)
    m2 = build_matrix(
        manifest,
        list(reversed(jobs)),
        list(reversed(attempts)),
        adjs_dict,
        cases_dict,
        created_at=ts,
    )

    assert m1.complete is True
    assert len(m1.cells) == 10
    assert m1.matrix_id == m2.matrix_id
    assert m1.source_attempts_digest == m2.source_attempts_digest
    assert [c.outcome for c in m1.cells] == [c.outcome for c in m2.cells]
