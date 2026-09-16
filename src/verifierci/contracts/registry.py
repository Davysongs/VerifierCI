"""verifierci.contracts.registry — minimal contract hashing registry (Phase 1).

Full requirement review arrives in Phase 6.
"""
from __future__ import annotations


class ContractRegistry:
    """In-process registry that validates requirements and records content hashes.

    Phase 1: minimal hashing only.  Hash conflicts abort the import transaction.
    Existing versions are immutable.
    """

