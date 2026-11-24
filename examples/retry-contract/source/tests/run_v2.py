"""Over-specific candidate fixture verifier runner (retry-contract-v2).

Enforces call-count bounds (catch permanent-retry and exceed-retry bugs) AND
wrongly requires the private helper symbol `_execute_with_retry`, which causes
the valid helper-free alternative patch to fail (SDD Section 1.3).
"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

retry_module = importlib.import_module("src.retry")
PermanentError = retry_module.PermanentError
TransientError = retry_module.TransientError
retry = retry_module.retry


def test_permanent_failure_no_retry() -> None:
    calls = 0

    def always_permanent() -> None:
        nonlocal calls
        calls += 1
        raise PermanentError("fatal")

    try:
        retry(always_permanent, max_retries=3)
    except PermanentError:
        assert calls == 1, f"Expected 1 call on PermanentError, got {calls}"
        return
    raise AssertionError("Expected PermanentError")


def test_permanent_failure_call_count() -> None:
    calls = 0

    def permanent_after_one() -> None:
        nonlocal calls
        calls += 1
        raise PermanentError("fatal")

    try:
        retry(permanent_after_one, max_retries=3)
    except PermanentError:
        pass
    assert calls == 1, f"Expected exactly 1 call before stopping, got {calls}"


def test_transient_then_success() -> None:
    calls = 0

    def flaky() -> str:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise TransientError("temporary")
        return "ok"

    result = retry(flaky, max_retries=3)
    assert result == "ok"
    assert calls == 2, f"Expected 2 calls, got {calls}"


def test_three_transients_then_success() -> None:
    calls = 0

    def succeed_on_fourth() -> str:
        nonlocal calls
        calls += 1
        if calls <= 3:
            raise TransientError(f"temporary #{calls}")
        return "recovered"

    result = retry(succeed_on_fourth, max_retries=3)
    assert result == "recovered"
    assert calls == 4, f"Expected 4 total calls (1 initial + 3 retries), got {calls}"


def test_four_transients_exhausted() -> None:
    calls = 0

    def always_transient() -> None:
        nonlocal calls
        calls += 1
        raise TransientError("still failing")

    try:
        retry(always_transient, max_retries=3)
    except TransientError:
        assert calls == 4, f"Expected 4 total calls on exhaustion, got {calls}"
        return
    raise AssertionError("Expected TransientError")


def test_immediate_success() -> None:
    calls = 0

    def succeed() -> int:
        nonlocal calls
        calls += 1
        return 7

    result = retry(succeed, max_retries=3)
    assert result == 7
    assert calls == 1, f"Expected 1 call on immediate success, got {calls}"


def test_private_helper_symbol() -> None:
    """Over-specific structural check violating REQ-NO-PRIVATE-STRUCTURE."""
    helper = getattr(retry_module, "_execute_with_retry", None)
    assert callable(helper), "Missing required private helper '_execute_with_retry'"


TESTS = [
    (
        "tests/test_retry.py::test_permanent_failure_no_retry",
        test_permanent_failure_no_retry,
    ),
    (
        "tests/test_retry.py::test_permanent_failure_call_count",
        test_permanent_failure_call_count,
    ),
    ("tests/test_retry.py::test_transient_then_success", test_transient_then_success),
    (
        "tests/test_retry.py::test_three_transients_then_success",
        test_three_transients_then_success,
    ),
    (
        "tests/test_retry.py::test_four_transients_exhausted",
        test_four_transients_exhausted,
    ),
    ("tests/test_retry.py::test_immediate_success", test_immediate_success),
    ("tests/test_retry.py::test_private_helper_symbol", test_private_helper_symbol),
]


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: run_v2.py <out_dir>", file=sys.stderr)
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
