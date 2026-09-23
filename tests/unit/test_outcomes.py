"""Unit tests for outcome classification and precedence.

SDD Section 7.5: Classification Precedence.
Tests strict ordering of infrastructure errors, build failures, timeouts/cancellations,
limit truncations, report parser evaluation, and evidence digest propagation.
"""

from __future__ import annotations

import json

from verifierci.errors import ErrorCode
from verifierci.execution.outcomes import parse_capture
from verifierci.models.protocol import ExecutionCapture, ResourceUsage
from verifierci.models.verifier import VerifierManifest


def _make_capture(
    *,
    exit_code: int | None = 0,
    timed_out: bool = False,
    oom_killed: bool = False,
    cancelled: bool = False,
    build_exit_code: int | None = None,
    stdout_hash: str | None = "out_hash_1",
    stderr_hash: str | None = "err_hash_1",
    report_digest: str | None = "rep_hash_1",
    truncated: bool = False,
    runtime_error: str | None = None,
) -> ExecutionCapture:
    return ExecutionCapture(
        attempt_id="att-1",
        exit_code=exit_code,
        timed_out=timed_out,
        oom_killed=oom_killed,
        cancelled=cancelled,
        build_exit_code=build_exit_code,
        stdout_hash=stdout_hash,
        stderr_hash=stderr_hash,
        report_digest=report_digest,
        truncated=truncated,
        resources=ResourceUsage(
            duration=1.0,
            allocated_cpu=1.0,
            cpu_seconds=1.0,
            peak_memory=None,
            model_usage=None,
            estimated_cost=None,
            pricing_version=None,
            bytes_written=10,
        ),
        runtime_error=runtime_error,
    )


def _make_manifest(parser_id: str = "pytest-report-v1") -> VerifierManifest:
    return VerifierManifest(
        manifest_hash="mhash" + "0" * 59,
        mode="compatibility",
        command=("pytest",),
        build_command=(),
        expected_collection=("tests/test.py::test_pass",),
        parser_id=parser_id,
        report_path="report.json",
        payload_digest="pay" + "0" * 61,
        allowed_edit_paths=("*",),
        required_pass_ids=("tests/test.py::test_pass",),
        permitted_skips=(),
        timeout_seconds=30,
    )


def test_precedence_1_infrastructure_error() -> None:
    manifest = _make_manifest()
    # Even if cancelled or timed_out is also true, runtime_error takes precedence
    cap = _make_capture(runtime_error="Docker daemon died", timed_out=True)
    outcome = parse_capture(cap, manifest)
    assert outcome.outcome == "error"
    assert outcome.evaluation_validity == "invalid"
    assert outcome.error_code == "Docker daemon died"
    assert outcome.evidence_digests == ("out_hash_1", "err_hash_1", "rep_hash_1")


def test_precedence_1b_patch_error() -> None:
    manifest = _make_manifest()
    cap = _make_capture(runtime_error=ErrorCode.PATCH_ERROR.value)
    outcome = parse_capture(cap, manifest)
    assert outcome.outcome == "invalid_evaluation"
    assert outcome.evaluation_validity == "invalid"
    assert outcome.error_code == ErrorCode.PATCH_ERROR.value


def test_precedence_2_build_error() -> None:
    manifest = _make_manifest()
    cap = _make_capture(build_exit_code=2, timed_out=True)
    outcome = parse_capture(cap, manifest)
    assert outcome.outcome == "invalid_evaluation"
    assert outcome.evaluation_validity == "invalid"
    assert outcome.error_code == ErrorCode.BUILD_ERROR.value


def test_precedence_3_cancellation() -> None:
    manifest = _make_manifest()
    cap = _make_capture(cancelled=True, timed_out=True)
    outcome = parse_capture(cap, manifest)
    assert outcome.outcome == "invalid_evaluation"
    assert outcome.evaluation_validity == "invalid"
    assert outcome.error_code == ErrorCode.CANCELLED.value


def test_precedence_3_timeout() -> None:
    manifest = _make_manifest()
    cap = _make_capture(timed_out=True)
    outcome = parse_capture(cap, manifest)
    assert outcome.outcome == "invalid_evaluation"
    assert outcome.error_code == ErrorCode.TIMEOUT.value


def test_precedence_3_oom() -> None:
    manifest = _make_manifest()
    cap = _make_capture(oom_killed=True)
    outcome = parse_capture(cap, manifest)
    assert outcome.outcome == "invalid_evaluation"
    assert outcome.error_code == ErrorCode.RESOURCE_EXHAUSTED.value


def test_precedence_3_truncated() -> None:
    manifest = _make_manifest()
    cap = _make_capture(truncated=True)
    outcome = parse_capture(cap, manifest)
    assert outcome.outcome == "invalid_evaluation"
    assert outcome.error_code == ErrorCode.ARTIFACT_LIMIT.value


def test_precedence_4_report_parser_accept() -> None:
    manifest = _make_manifest()
    cap = _make_capture(exit_code=0)
    report_data = {
        "tests": [{"nodeid": "tests/test.py::test_pass", "outcome": "passed"}]
    }
    outcome = parse_capture(cap, manifest, json.dumps(report_data).encode("utf-8"))
    assert outcome.outcome == "accept"
    assert outcome.evaluation_validity == "valid"
    assert outcome.error_code is None
    assert "rep_hash_1" in outcome.evidence_digests


def test_unknown_parser() -> None:
    manifest = _make_manifest(parser_id="unknown-parser-v9")
    cap = _make_capture(exit_code=0)
    outcome = parse_capture(cap, manifest)
    assert outcome.outcome == "invalid_evaluation"
    assert outcome.evaluation_validity == "invalid"
    assert outcome.error_code == ErrorCode.PARSER_ERROR.value
