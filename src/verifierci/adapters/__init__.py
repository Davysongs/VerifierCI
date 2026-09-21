"""Execution/verifier adapters."""

from .base import TaskAdapter, VerificationAdapter
from .local import LocalAdapter

__all__ = ["LocalAdapter", "TaskAdapter", "VerificationAdapter"]
