"""Adapter contract for verifier backends."""
"""Adapter contract for verifier backends and task importers.

SDD Section 5: TaskAdapter boundary.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Protocol, runtime_checkable

from verifierci.models.protocol import ImportBundle, ImportRequest

class VerificationAdapter(ABC):
    """Abstract adapter interface for verifier-specific execution engines."""

    @abstractmethod
@runtime_checkable
class TaskAdapter(Protocol):
    """Abstract task adapter boundary for importing benchmark and native tasks."""

    def name(self) -> str:
        raise NotImplementedError
        """Return the adapter identity (e.g. 'local', 'swebench', 'harbor')."""
        ...

    @abstractmethod
    def supports(self, task_id: str) -> bool:
        raise NotImplementedError
        """Check whether this adapter supports the given task id."""
        ...

    def import_task(self, request: ImportRequest) -> ImportBundle:
        """Import and normalize a task into an in-memory ImportBundle."""
        ...

    def supported_source_version(self, version: str) -> bool:
        """Check whether the adapter supports the declared source version."""
        ...

    def validate_environment(self, bundle: ImportBundle) -> None:
        """Validate that the execution environment configuration is complete and supported."""
        ...


class VerificationAdapter(TaskAdapter, Protocol):
    """Compatibility protocol for verification adapters."""
