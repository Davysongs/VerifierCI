"""Execution job primitives."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Job:
    """Small immutable unit of verifier work."""

    task_id: str
    strategy: str = "baseline"
