"""Synthetic retry-contract package (SDD Section 1.3 illustrative fixture)."""

from .retry import PermanentError, TransientError, retry

__all__ = ["PermanentError", "TransientError", "retry"]
