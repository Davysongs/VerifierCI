"""Execution outcome models and classification.

SDD Section 5: verifierci.execution.outcomes.
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

    Precedence Hierarchy:
    1. Infrastructure/runtime failures (error / invalid)
    2. Patch application or build failures (invalid_evaluation / invalid with PATCH_ERROR or BUILD_ERROR)
    3. Timeouts, cancellations, or truncated output caps (invalid_evaluation / invalid with TIMEOUT, CANCELLED, or ARTIFACT_LIMIT)
    4. Missing/malformed reports, duplicate IDs, forbidden skips, or collection mismatches (invalid_evaluation / invalid)
    5. Complete reports containing required test assertion failures (reject / valid, recording exit mismatches if wrapper exited 0)
    6. Complete reports with all scored tests passed and matching exit protocol (accept / valid)
    7. Unclassified execution (invalid_evaluation / invalid)
    """
    evidence_digests: tuple[str, ...] = tuple(
        h
        for h in (capture.stdout_hash, capture.stderr_hash, capture.report_digest)
        if h is not None
    )

    # Tier 1 & 2 & 3: Check runtime_error diagnostics and build_exit_code
    tier_2_runtime_codes = {
        ErrorCode.PATCH_ERROR.value,
        ErrorCode.PROTECTION_ERROR.value,
        ErrorCode.VALIDATION_ERROR.value,
        ErrorCode.BUILD_ERROR.value,
    }
    tier_3_runtime_codes = {
        ErrorCode.CANCELLED.value,
        ErrorCode.TIMEOUT.value,
        ErrorCode.RESOURCE_EXHAUSTED.value,
        ErrorCode.ARTIFACT_LIMIT.value,
    }

    if capture.runtime_error:
        is_tier_2 = (
            capture.runtime_error in tier_2_runtime_codes
            or "patch" in capture.runtime_error.lower()
        )
        is_tier_3 = capture.runtime_error in tier_3_runtime_codes

        if not is_tier_2 and not is_tier_3:
            # Tier 1: True infrastructure / runtime failure
            return ParsedOutcome(
                outcome="error",
                evaluation_validity="invalid",
                error_code=capture.runtime_error,
                report=None,
                evidence_digests=evidence_digests,
            )

        if is_tier_2:
            # Tier 2: Patch or build error from runtime_error
            err_code = (
                ErrorCode.BUILD_ERROR.value
                if capture.runtime_error == ErrorCode.BUILD_ERROR.value
                else ErrorCode.PATCH_ERROR.value
            )
            return ParsedOutcome(
                outcome="invalid_evaluation",
                evaluation_validity="invalid",
                error_code=err_code,
                report=None,
                evidence_digests=evidence_digests,
            )

    # Tier 2: Build failure from build_exit_code (takes precedence over Tier 3 timeouts/cancellations)
    if capture.build_exit_code is not None and capture.build_exit_code != 0:
        return ParsedOutcome(
            outcome="invalid_evaluation",
            evaluation_validity="invalid",
            error_code=ErrorCode.BUILD_ERROR.value,
            report=None,
            evidence_digests=evidence_digests,
        )

    # Tier 3: Timeout / Cancellation / Limits in runtime_error
    if capture.runtime_error:
        if capture.runtime_error == ErrorCode.CANCELLED.value:
            return ParsedOutcome(
                outcome="invalid_evaluation",
                evaluation_validity="invalid",
                error_code=ErrorCode.CANCELLED.value,
                report=None,
                evidence_digests=evidence_digests,
            )
        if capture.runtime_error == ErrorCode.TIMEOUT.value:
            return ParsedOutcome(
                outcome="invalid_evaluation",
                evaluation_validity="invalid",
                error_code=ErrorCode.TIMEOUT.value,
                report=None,
                evidence_digests=evidence_digests,
            )
        if capture.runtime_error == ErrorCode.RESOURCE_EXHAUSTED.value:
            return ParsedOutcome(
                outcome="invalid_evaluation",
                evaluation_validity="invalid",
                error_code=ErrorCode.RESOURCE_EXHAUSTED.value,
                report=None,
                evidence_digests=evidence_digests,
            )
        if capture.runtime_error == ErrorCode.ARTIFACT_LIMIT.value:
            return ParsedOutcome(
                outcome="invalid_evaluation",
                evaluation_validity="invalid",
                error_code=ErrorCode.ARTIFACT_LIMIT.value,
                report=None,
                evidence_digests=evidence_digests,
            )

        # Fallback infrastructure error
        return ParsedOutcome(
            outcome="error",
            evaluation_validity="invalid",
            error_code=capture.runtime_error,
            report=None,
            evidence_digests=evidence_digests,
        )

    # 3. Timeouts, cancellations, or truncated output caps
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

    # 4-6. Structured report evaluation (Tiers 4, 5, and 6)
    if manifest.parser_id == PARSER_ID:
        parser = PytestReportParser()
        result = parser.parse(report_bytes, manifest, capture)
        if not result.evidence_digests and evidence_digests:
            return dataclasses.replace(result, evidence_digests=evidence_digests)
        return result

    # 7. Unclassified execution or unsupported parser
    return ParsedOutcome(
        outcome="invalid_evaluation",
        evaluation_validity="invalid",
        error_code=ErrorCode.PARSER_ERROR.value,
        report=None,
        evidence_digests=evidence_digests,
    )


__all__ = [
    "ExecutionOutcome",
    "parse_capture",
]
