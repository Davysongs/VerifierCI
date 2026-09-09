"""Adapter contract for verifier backends."""

from __future__ import annotations

from abc import ABC, abstractmethod


class VerificationAdapter(ABC):
    """Abstract adapter interface for verifier-specific execution engines."""

    @abstractmethod
    def name(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def supports(self, task_id: str) -> bool:
        raise NotImplementedError
