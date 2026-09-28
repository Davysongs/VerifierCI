"""Execution/verifier adapters."""

from .base import TaskAdapter
from .local import LocalAdapter

__all__ = ["LocalAdapter", "TaskAdapter"]
