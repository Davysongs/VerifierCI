"""verifierci.metrics.rates — two-sided acceptance rate computations (Phase 2).

Pure functions compute challenge-panel IAR and VRR, control diagnostics,
coverage and paired changes.  Zero denominators return None (null), not zero.

gate.py arrives in Phase 3.
"""
from __future__ import annotations


def invalid_acceptance_rate(
    accepted: int,
    total_invalid: int,
) -> float | None:
    """Challenge-panel Invalid Acceptance Rate (IAR).

    Returns None when total_invalid is zero.
    """
    if total_invalid == 0:
        return None
    return accepted / total_invalid


def valid_rejection_rate(
    rejected: int,
    total_valid: int,
) -> float | None:
    """Valid Rejection Rate (VRR).

    Returns None when total_valid is zero.
    """
    if total_valid == 0:
        return None
    return rejected / total_valid

