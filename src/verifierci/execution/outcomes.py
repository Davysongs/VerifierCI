"""Execution outcome models and classification.

SDD Section 7.5: Classification Precedence.
Deterministic mapping of low-level execution captures and test reports into
typed domain outcomes.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass

from verifierci.errors import ErrorCode
from verifierci.evaluators.pytest_report import PARSER_ID, PytestReportParser
from verifierci.models.protocol import ExecutionCapture, ParsedOutcome
from verifierci.models.verifier import VerifierManifest


@dataclass(frozen=True)
class ExecutionOutcome:
    """Execution outcome for a planned job."""

    task_id: str
    exit_code: int
    output: str = ""


def parse_capture(
    capture: ExecutionCapture,
    manifest: VerifierManifest,
    report_bytes: bytes | None = None,
) -> ParsedOutcome:
    """Parse execution capture into a domain ParsedOutcome per SDD Section 7.5 precedence.

    Precedence:
    1. Infrastructure/runtime error -> outcome='error', evaluation_validity='invalid'
    2. Patch/build error -> outcome='invalid_evaluation', evaluation_validity='invalid'
    3. Timeout / Cancel / OOM / Truncated limits -> outcome='invalid_evaluation', evaluation_validity='invalid'
    4. Evaluator / Report parser (empty collection, mismatch, assertion fail, accept)
    """
    evidence_digests: tuple[str, ...] = tuple(
        h
        for h in (capture.stdout_hash, capture.stderr_hash, capture.report_digest)
        if h is not None
    )

    # 1. Infrastructure / runtime error
    if capture.runtime_error:
        if (
            capture.runtime_error
            in (
                ErrorCode.PATCH_ERROR.value,
                ErrorCode.PROTECTION_ERROR.value,
                ErrorCode.VALIDATION_ERROR.value,
            )
            or "patch" in capture.runtime_error.lower()
        ):
            return ParsedOutcome(
                outcome="invalid_evaluation",
                evaluation_validity="invalid",
                error_code=ErrorCode.PATCH_ERROR.value,
                report=None,
                evidence_digests=evidence_digests,
            )
        return ParsedOutcome(
            outcome="error",
            evaluation_validity="invalid",
            error_code=capture.runtime_error,
            report=None,
            evidence_digests=evidence_digests,
        )

    # 2. Patch / build error
    if capture.build_exit_code is not None and capture.build_exit_code != 0:
        return ParsedOutcome(
            outcome="invalid_evaluation",
            evaluation_validity="invalid",
            error_code=ErrorCode.BUILD_ERROR.value,
            report=None,
            evidence_digests=evidence_digests,
        )

    # 3. Timeout / Cancellation / OOM / Limit truncation
    if capture.cancelled:
        return ParsedOutcome(
            outcome="invalid_evaluation",
            evaluation_validity="invalid",
            error_code=ErrorCode.CANCELLED.value,
            report=None,
            evidence_digests=evidence_digests,
        )
    if capture.timed_out:
        return ParsedOutcome(
            outcome="invalid_evaluation",
            evaluation_validity="invalid",
            error_code=ErrorCode.TIMEOUT.value,
            report=None,
            evidence_digests=evidence_digests,
        )
    if capture.oom_killed:
        return ParsedOutcome(
            outcome="invalid_evaluation",
            evaluation_validity="invalid",
            error_code=ErrorCode.RESOURCE_EXHAUSTED.value,
            report=None,
            evidence_digests=evidence_digests,
        )
    if capture.truncated:
        return ParsedOutcome(
            outcome="invalid_evaluation",
            evaluation_validity="invalid",
            error_code=ErrorCode.ARTIFACT_LIMIT.value,
            report=None,
            evidence_digests=evidence_digests,
        )

    # 4. Dispatch to structured report parser
    if manifest.parser_id == PARSER_ID:
        parser = PytestReportParser()
        result = parser.parse(report_bytes, manifest, capture)
        if not result.evidence_digests and evidence_digests:
            return dataclasses.replace(result, evidence_digests=evidence_digests)
        return result

    # Unsupported or unknown parser
    return ParsedOutcome(
        outcome="invalid_evaluation",
        evaluation_validity="invalid",
        error_code=ErrorCode.PARSER_ERROR.value,
        report=None,
        evidence_digests=evidence_digests,
    )
