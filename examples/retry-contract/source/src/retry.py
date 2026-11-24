"""Synthetic retry implementation for the VerifierCI retry-contract example.

Normative contract (SDD Section 1.3):
- On TransientError: retry up to max_retries (default 3) times after initial call
  (at most 4 total calls).
- On PermanentError: terminate immediately without retrying.
- On success: return the result immediately without further calls.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

T = TypeVar("T")


class TransientError(Exception):
    """Error indicating a transient condition that may succeed on retry."""


class PermanentError(Exception):
    """Error indicating a permanent condition that must not be retried."""


def _execute_with_retry(fn: Callable[[], T], max_retries: int) -> T:
    """Execute fn with at most max_retries retries on TransientError."""
    if max_retries < 0:
        raise ValueError("max_retries must be non-negative")

    for attempt in range(max_retries + 1):
        try:
            return fn()
        except PermanentError:
            raise
        except TransientError:
            if attempt >= max_retries:
                raise
    raise AssertionError("unreachable")


def retry(fn: Callable[[], T], max_retries: int = 3) -> T:
    """Invoke fn() with bounded retries for transient errors."""
    return _execute_with_retry(fn, max_retries=max_retries)
