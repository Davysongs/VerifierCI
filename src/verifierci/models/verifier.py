"""Verifier configuration model."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class VerifierConfig:
    """Lightweight configuration for a verifier implementation."""

    name: str
    version: str
    settings: dict[str, Any]
