"""Sandbox execution primitives."""

from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass


@dataclass
class DummySandbox(AbstractContextManager["DummySandbox"]):
    """No-op sandbox placeholder used during MVP bootstrap."""

    task_id: str

    def __enter__(self) -> "DummySandbox":
        return self

    def __exit__(self, *exc) -> None:
        return None
