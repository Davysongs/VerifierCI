"""verifierci.panels.registry — panel file validation registry (Phase 1).

Sealed registry with full protection error handling arrives in Phase 6.
"""
from __future__ import annotations


class PanelRegistry:
    """In-process registry that freezes membership, split reservations, selected
    adjudications and exposure history.

    Phase 1: file validation only.  Validation is all-or-nothing.
    A disputed label stays visible as unresolved.
    A family reservation conflict raises ProtectionError before insertion.
    """


class ProtectionError(Exception):
    """Raised when a family reservation conflict is detected during panel insertion."""
