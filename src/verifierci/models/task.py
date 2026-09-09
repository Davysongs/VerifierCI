"""Core task model."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Task:
    """A minimal verifier task record used by adapters and execution layers."""

    id: str
    title: str
    prompt: str
