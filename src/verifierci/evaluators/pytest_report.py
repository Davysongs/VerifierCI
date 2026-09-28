"""verifierci.evaluators.pytest_report — pytest JSON report parser (Phase 1).

Parses a pytest `--json-report` output and maps test IDs to pass/fail/skip
outcomes. This is the compatibility-mode evaluator for Python fixtures.

Parser ID: `pytest-report-v1`

Contract:
- A runner crash, empty collection or malformed response produces a typed
  non-valid observation (invalid_evaluation).
- Parse failures return invalid_evaluation.
- Compares observed collection strictly against manifest.expected_collection.
- Checks manifest.required_pass_ids and manifest.permitted_skips.
"""

from __future__ import annotations

import json

from verifierci.errors import ErrorCode
from verifierci.models.protocol import (
    ExecutionCapture,
    ParsedOutcome,
    TestReport,
    TestResult,
)
from verifierci.models.verifier import VerifierManifest

PARSER_ID = "pytest-report-v1"


class PytestReportParser:
    """Parses a pytest JSON report into a structured ParsedOutcome.

    Verifies the report and expected test identities before producing
    an outcome. Does not consult independent adjudication.
    """

    def parse(
        self,
        report_bytes: bytes | None,
        manifest: VerifierManifest,
        capture: ExecutionCapture,
    ) -> ParsedOutcome:
        """Parse raw report bytes and classify the outcome according to test results."""
        if not report_bytes or not report_bytes.strip():
            return ParsedOutcome(
                outcome="invalid_evaluation",
                evaluation_validity="invalid",
                error_code=ErrorCode.EMPTY_COLLECTION.value,
                report=None,
                evidence_digests=(),
            )

        try:
            data = json.loads(report_bytes.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            return ParsedOutcome(
                outcome="invalid_evaluation",
                evaluation_validity="invalid",
                error_code=ErrorCode.PARSER_ERROR.value,
                report=None,
                evidence_digests=(),
            )

        if not isinstance(data, dict):
            return ParsedOutcome(
                outcome="invalid_evaluation",
                evaluation_validity="invalid",
                error_code=ErrorCode.PARSER_ERROR.value,
                report=None,
                evidence_digests=(),
            )

        # Extract test items
        raw_tests = data.get("tests", [])
        if not isinstance(raw_tests, list):
            return ParsedOutcome(
                outcome="invalid_evaluation",
                evaluation_validity="invalid",
                error_code=ErrorCode.PARSER_ERROR.value,
                report=None,
                evidence_digests=(),
            )

        collected_ids: list[str] = []
        test_results: list[TestResult] = []
        passed_count = 0
        failed_count = 0
        parser_error = False

        for t in raw_tests:
            if not isinstance(t, dict):
                return ParsedOutcome(
                    outcome="invalid_evaluation",
                    evaluation_validity="invalid",
                    error_code=ErrorCode.PARSER_ERROR.value,
                    report=None,
                    evidence_digests=(),
                )
            nodeid = t.get("nodeid")
            if not isinstance(nodeid, str) or not nodeid.strip():
                return ParsedOutcome(
                    outcome="invalid_evaluation",
                    evaluation_validity="invalid",
                    error_code=ErrorCode.PARSER_ERROR.value,
                    report=None,
                    evidence_digests=(),
                )
            collected_ids.append(nodeid)
            raw_outcome = str(t.get("outcome", "failed")).lower()

            duration: float | None = None
            if "duration" in t and t["duration"] is not None:
                try:
                    duration = float(t["duration"])
                except (TypeError, ValueError):
                    duration = None
                    parser_error = True

            if raw_outcome == "passed":
                status = "passed"
                passed_count += 1
            elif raw_outcome == "skipped":
                status = "skipped"
            else:
                status = "failed"
                failed_count += 1

            test_results.append(
                TestResult(
                    test_id=nodeid,
                    status=status,  # type: ignore[arg-type]
                    duration=duration,
                    failure_digest=None,
                )
            )

        collected_tuple = tuple(collected_ids)
        test_report = TestReport(
            schema_version="1.0.0",
            collected_ids=collected_tuple,
            results=tuple(test_results),
            completed=True,
            runner_error=None,
        )

        if parser_error:
            return ParsedOutcome(
                outcome="invalid_evaluation",
                evaluation_validity="invalid",
                error_code=ErrorCode.PARSER_ERROR.value,
                report=test_report,
                evidence_digests=(),
            )

        # 1. Empty collection check
        if not collected_tuple:
            return ParsedOutcome(
                outcome="invalid_evaluation",
                evaluation_validity="invalid",
                error_code=ErrorCode.EMPTY_COLLECTION.value,
                report=test_report,
                evidence_digests=(),
            )

        # 2. Compare against manifest.expected_collection if specified
        if manifest.expected_collection:
            expected_set = set(manifest.expected_collection)
            observed_set = set(collected_tuple)
            if expected_set != observed_set:
                return ParsedOutcome(
                    outcome="invalid_evaluation",
                    evaluation_validity="invalid",
                    error_code=ErrorCode.COLLECTION_MISMATCH.value,
                    report=test_report,
                    evidence_digests=(),
                )
        if manifest.expected_collection and sorted(
            manifest.expected_collection
        ) != sorted(collected_tuple):
            return ParsedOutcome(
                outcome="invalid_evaluation",
                evaluation_validity="invalid",
                error_code=ErrorCode.COLLECTION_MISMATCH.value,
                report=test_report,
                evidence_digests=(),
            )

        # 3. Check for disallowed skips
        permitted_skips_set = set(manifest.permitted_skips)
        for tr in test_results:
            if tr.status == "skipped" and tr.test_id not in permitted_skips_set:
                return ParsedOutcome(
                    outcome="invalid_evaluation",
                    evaluation_validity="invalid",
                    error_code=ErrorCode.COLLECTION_MISMATCH.value,
                    report=test_report,
                    evidence_digests=(),
                )

        # 4. Check required pass IDs and general pass/fail
        results_map: dict[str, str] = {tr.test_id: tr.status for tr in test_results}
        all_required_passed = True
        for req_id in manifest.required_pass_ids:
            if results_map.get(req_id) != "passed":
                all_required_passed = False
                break

        # Check for contradictory nonzero exit when report claims all passed
        has_failures = failed_count > 0 or not all_required_passed
        if (
            not has_failures
            and capture.exit_code is not None
            and capture.exit_code != 0
        ):
            return ParsedOutcome(
                outcome="invalid_evaluation",
                evaluation_validity="invalid",
                error_code="EXIT_REPORT_MISMATCH",
                report=test_report,
                evidence_digests=(),
            )

        # Assertion failure -> reject (valid)
        if has_failures:
            error_code = "EXIT_REPORT_MISMATCH" if capture.exit_code == 0 else None
            return ParsedOutcome(
                outcome="reject",
                evaluation_validity="valid",
                error_code=error_code,
                report=test_report,
                evidence_digests=(),
            )

        # All passed -> accept (valid)
        return ParsedOutcome(
            outcome="accept",
            evaluation_validity="valid",
            error_code=None,
            report=test_report,
            evidence_digests=(),
        )
