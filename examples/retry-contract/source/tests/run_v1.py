"""Weak baseline fixture verifier runner (retry-contract-v1).

Executes real behavioral checks against src.retry without asserting
permanent-failure call count or exact retry-exhaustion call counts.
Because of those weak assertions, all five synthetic fixture cases pass v1.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

from src.retry import PermanentError, TransientError, retry


def test_permanent_failure_no_retry() -> None:
    """Weak check: asserts PermanentError surfaces, without verifying call count."""

    def always_permanent() -> None:
        raise PermanentError("fatal")

    try:
        retry(always_permanent, max_retries=3)
    except PermanentError:
        return
    raise AssertionError("Expected PermanentError")


def test_transient_then_success() -> None:
    """Checks 1 transient failure followed by success."""
    calls = 0

    def flaky() -> str:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise TransientError("temporary")
        return "ok"

    result = retry(flaky, max_retries=3)
    assert result == "ok"


def test_max_retries_exhausted() -> None:
    """Weak check: asserts TransientError surfaces on exhaustion, without call count."""

    def always_transient() -> None:
        raise TransientError("still failing")

    try:
        retry(always_transient, max_retries=3)
    except TransientError:
        return
    raise AssertionError("Expected TransientError")


def test_immediate_success() -> None:
    """Checks immediate return on initial success."""
    calls = 0

    def succeed() -> int:
        nonlocal calls
        calls += 1
        return 42

    result = retry(succeed, max_retries=3)
    assert result == 42


TESTS = [
    (
        "tests/test_retry.py::test_permanent_failure_no_retry",
        test_permanent_failure_no_retry,
    ),
    ("tests/test_retry.py::test_transient_then_success", test_transient_then_success),
    ("tests/test_retry.py::test_max_retries_exhausted", test_max_retries_exhausted),
    ("tests/test_retry.py::test_immediate_success", test_immediate_success),
]


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: run_v1.py <out_dir>", file=sys.stderr)
        return 2
    out_dir = Path(sys.argv[1])
    out_dir.mkdir(parents=True, exist_ok=True)

    results: list[dict[str, str]] = []
    any_failed = False
    for nodeid, fn in TESTS:
        try:
            fn()
            results.append({"nodeid": nodeid, "outcome": "passed"})
        except (
            AssertionError,
            AttributeError,
            PermanentError,
            TransientError,
            RuntimeError,
            TypeError,
            ValueError,
        ) as exc:
            any_failed = True
            results.append({"nodeid": nodeid, "outcome": "failed"})
            print(f"FAIL {nodeid}: {exc}", file=sys.stderr)

    (out_dir / "report.json").write_text(
        json.dumps({"tests": results}, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return 1 if any_failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
