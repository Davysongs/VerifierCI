"""Patch panel models."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence


@dataclass(frozen=True)
class PatchPanel:
    """A reviewed set of candidate patch outcomes for a task."""

    task_id: str
    approved_alternatives: tuple[str, ...]
    known_bad_patches: tuple[str, ...] = ()

    @classmethod
    def from_sequences(
        cls,
        task_id: str,
        approved_alternatives: Sequence[str],
        known_bad_patches: Sequence[str] | None = None,
    ) -> "PatchPanel":
        return cls(
            task_id=task_id,
            approved_alternatives=tuple(approved_alternatives),
            known_bad_patches=tuple(known_bad_patches or ()),
        )
