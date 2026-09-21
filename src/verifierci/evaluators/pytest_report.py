"""verifierci.evaluators.pytest_report — pytest JSON report parser (Phase 1).

Parses a pytest ``--json-report`` output and maps test IDs to pass/fail/skip
outcomes.  This is the compatibility-mode evaluator for Python fixtures.

Parser ID: ``pytest-report-v1``

Contract:
- A runner crash, empty collection or malformed response produces a typed
  non-valid observation.
- Parse failures return invalid_evaluation.
- Internal parser bugs return error and preserve input digests.
- The parser does not infer success from text such as ``result=pass``.
"""

from __future__ import annotations

PARSER_ID = "pytest-report-v1"


class PytestReportParser:
    """Parses a pytest JSON report into a structured ParsedOutcome.

    Verifies the report and expected test identities before producing
    an outcome.  Does not consult independent adjudication.
    """
