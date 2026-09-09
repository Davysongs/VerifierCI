"""Verification result model."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class VerificationResult:
    """Outcome of running one verifier against a patch candidate."""

    task_id: str
    verdict: str
    details: dict[str, Any] | None = None
