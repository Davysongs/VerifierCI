"""Execution outcome models."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ExecutionOutcome:
    """Execution outcome for a planned job."""

    task_id: str
    exit_code: int
    output: str = ""
