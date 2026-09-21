"""Unit tests for pytest JSON report parser.

SDD Section 7.5.
Tests compatibility-mode report evaluator:
- Runner crash / empty report
- Collection verification against expected collection
- Required passes and permitted skips
- Contradictory exit status handling
"""

from __future__ import annotations

import json
from typing import Any

from verifierci.errors import ErrorCode
from verifierci.evaluators.pytest_report import PytestReportParser
from verifierci.models.protocol import ExecutionCapture, ResourceUsage
from verifierci.models.verifier import VerifierManifest


def _make_capture(exit_code: int = 0) -> ExecutionCapture:
    return ExecutionCapture(
        attempt_id="att-1",
        exit_code=exit_code,
        timed_out=False,
        oom_killed=False,
        cancelled=False,
        build_exit_code=None,
        stdout_hash=None,
        stderr_hash=None,
        report_digest=None,
        truncated=False,
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
        runtime_error=None,
    )


def _make_manifest(
    expected_collection: tuple[str, ...] = ("tests/test_app.py::test_one",),
    required_pass_ids: tuple[str, ...] = ("tests/test_app.py::test_one",),
    permitted_skips: tuple[str, ...] = (),
) -> VerifierManifest:
    return VerifierManifest(
        manifest_hash="mhash" + "0" * 59,
        mode="compatibility",
        command=("pytest",),
        build_command=(),
        expected_collection=expected_collection,
        parser_id="pytest-report-v1",
        report_path="report.json",
        payload_digest="pay" + "0" * 61,
        allowed_edit_paths=("*",),
        required_pass_ids=required_pass_ids,
        permitted_skips=permitted_skips,
        timeout_seconds=30,
    )


def test_empty_report() -> None:
    parser = PytestReportParser()
    manifest = _make_manifest()
    capture = _make_capture()

    outcome = parser.parse(None, manifest, capture)
    assert outcome.outcome == "invalid_evaluation"
    assert outcome.evaluation_validity == "invalid"
    assert outcome.error_code == ErrorCode.EMPTY_COLLECTION.value

    outcome2 = parser.parse(b"", manifest, capture)
    assert outcome2.error_code == ErrorCode.EMPTY_COLLECTION.value


def test_malformed_json() -> None:
    parser = PytestReportParser()
    manifest = _make_manifest()
    capture = _make_capture()

    outcome = parser.parse(b"not json", manifest, capture)
    assert outcome.outcome == "invalid_evaluation"
    assert outcome.error_code == ErrorCode.PARSER_ERROR.value

    # JSON valid but not a dict
    outcome2 = parser.parse(b'"just a string"', manifest, capture)
    assert outcome2.outcome == "invalid_evaluation"
    assert outcome2.error_code == ErrorCode.PARSER_ERROR.value


def test_empty_test_collection() -> None:
    parser = PytestReportParser()
    manifest = _make_manifest()
    capture = _make_capture()

    data = {"tests": []}
    data: dict[str, Any] = {"tests": []}
    outcome = parser.parse(json.dumps(data).encode("utf-8"), manifest, capture)
    assert outcome.outcome == "invalid_evaluation"
    assert outcome.error_code == ErrorCode.EMPTY_COLLECTION.value


def test_collection_mismatch() -> None:
    parser = PytestReportParser()
    manifest = _make_manifest(expected_collection=("tests/test_app.py::test_one",))
    capture = _make_capture()

    data = {"tests": [{"nodeid": "tests/test_app.py::test_other", "outcome": "passed"}]}
    outcome = parser.parse(json.dumps(data).encode("utf-8"), manifest, capture)
    assert outcome.outcome == "invalid_evaluation"
    assert outcome.error_code == ErrorCode.COLLECTION_MISMATCH.value


def test_disallowed_skip() -> None:
    parser = PytestReportParser()
    manifest = _make_manifest(
        expected_collection=("tests/test_app.py::test_one",),
        permitted_skips=(),
    )
    capture = _make_capture()

    data = {"tests": [{"nodeid": "tests/test_app.py::test_one", "outcome": "skipped"}]}
    outcome = parser.parse(json.dumps(data).encode("utf-8"), manifest, capture)
    assert outcome.outcome == "invalid_evaluation"
    assert outcome.error_code == ErrorCode.COLLECTION_MISMATCH.value


def test_allowed_skip() -> None:
    parser = PytestReportParser()
    manifest = _make_manifest(
        expected_collection=(
            "tests/test_app.py::test_one",
            "tests/test_app.py::test_optional",
        ),
        required_pass_ids=("tests/test_app.py::test_one",),
        permitted_skips=("tests/test_app.py::test_optional",),
    )
    capture = _make_capture(exit_code=0)

    data = {
        "tests": [
            {"nodeid": "tests/test_app.py::test_one", "outcome": "passed"},
            {"nodeid": "tests/test_app.py::test_optional", "outcome": "skipped"},
        ]
    }
    outcome = parser.parse(json.dumps(data).encode("utf-8"), manifest, capture)
    assert outcome.outcome == "accept"
    assert outcome.evaluation_validity == "valid"


def test_assertion_failure_reject() -> None:
    parser = PytestReportParser()
    manifest = _make_manifest(
        expected_collection=("tests/test_app.py::test_one",),
        required_pass_ids=("tests/test_app.py::test_one",),
    )
    capture = _make_capture(exit_code=1)

    data = {"tests": [{"nodeid": "tests/test_app.py::test_one", "outcome": "failed"}]}
    outcome = parser.parse(json.dumps(data).encode("utf-8"), manifest, capture)
    assert outcome.outcome == "reject"
    assert outcome.evaluation_validity == "valid"


def test_all_passed_accept() -> None:
    parser = PytestReportParser()
    manifest = _make_manifest(
        expected_collection=("tests/test_app.py::test_one",),
        required_pass_ids=("tests/test_app.py::test_one",),
    )
    capture = _make_capture(exit_code=0)

    data = {"tests": [{"nodeid": "tests/test_app.py::test_one", "outcome": "passed"}]}
    outcome = parser.parse(json.dumps(data).encode("utf-8"), manifest, capture)
    assert outcome.outcome == "accept"
    assert outcome.evaluation_validity == "valid"
    assert outcome.error_code is None


def test_contradictory_exit_with_passing_report() -> None:
    parser = PytestReportParser()
    manifest = _make_manifest(
        expected_collection=("tests/test_app.py::test_one",),
        required_pass_ids=("tests/test_app.py::test_one",),
    )
    # Report says passed, but exit_code is 1 (e.g. runner crash during teardown)
    capture = _make_capture(exit_code=1)

    data = {"tests": [{"nodeid": "tests/test_app.py::test_one", "outcome": "passed"}]}
    outcome = parser.parse(json.dumps(data).encode("utf-8"), manifest, capture)
    assert outcome.outcome == "invalid_evaluation"
    assert outcome.evaluation_validity == "invalid"
    assert outcome.error_code == "EXIT_REPORT_MISMATCH"


def test_malformed_test_entries() -> None:
    parser = PytestReportParser()
    manifest = _make_manifest()
    capture = _make_capture()

    # tests is not a list
    data1 = {"tests": "not-a-list"}
    outcome1 = parser.parse(json.dumps(data1).encode("utf-8"), manifest, capture)
    assert outcome1.outcome == "invalid_evaluation"
    assert outcome1.error_code == ErrorCode.PARSER_ERROR.value

    # test entry is not a dict
    data2 = {"tests": ["not-a-dict"]}
    outcome2 = parser.parse(json.dumps(data2).encode("utf-8"), manifest, capture)
    assert outcome2.outcome == "invalid_evaluation"
    assert outcome2.error_code == ErrorCode.PARSER_ERROR.value

    # test entry missing nodeid or empty nodeid
    data3 = {"tests": [{"outcome": "passed"}]}
    outcome3 = parser.parse(json.dumps(data3).encode("utf-8"), manifest, capture)
    assert outcome3.outcome == "invalid_evaluation"
    assert outcome3.error_code == ErrorCode.PARSER_ERROR.value

    data4 = {"tests": [{"nodeid": "   ", "outcome": "passed"}]}
    outcome4 = parser.parse(json.dumps(data4).encode("utf-8"), manifest, capture)
    assert outcome4.outcome == "invalid_evaluation"
    assert outcome4.error_code == ErrorCode.PARSER_ERROR.value


def test_duration_parsing() -> None:
    parser = PytestReportParser()
    manifest = _make_manifest()
    capture = _make_capture()

    # Valid duration
    data1 = {
        "tests": [
            {
                "nodeid": "tests/test_app.py::test_one",
                "outcome": "passed",
                "duration": 1.25,
            }
        ]
    }
    outcome1 = parser.parse(json.dumps(data1).encode("utf-8"), manifest, capture)
    assert outcome1.report is not None
    assert outcome1.report.results[0].duration == 1.25

    # Malformed duration should fall back to None without raising
    # Malformed duration should return PARSER_ERROR
    data2 = {
        "tests": [
            {
                "nodeid": "tests/test_app.py::test_one",
                "outcome": "passed",
                "duration": "not-a-number",
            }
        ]
    }
    outcome2 = parser.parse(json.dumps(data2).encode("utf-8"), manifest, capture)
    assert outcome2.report is not None
    assert outcome2.report.results[0].duration is None
    assert outcome2.outcome == "invalid_evaluation"
    assert outcome2.error_code == ErrorCode.PARSER_ERROR.value

    # Null duration should safely retain None
    data3 = {
        "tests": [
            {
                "nodeid": "tests/test_app.py::test_one",
                "outcome": "passed",
                "duration": None,
            }
        ]
    }
    outcome3 = parser.parse(json.dumps(data3).encode("utf-8"), manifest, capture)
    assert outcome3.report is not None
    assert outcome3.report.results[0].duration is None
