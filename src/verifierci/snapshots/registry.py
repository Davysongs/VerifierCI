"""verifierci.snapshots.registry — local snapshot digest registry (Phase 1).

Archive extraction and patch parsing occur on the disposable worker machine.
Retrieval is added in Phase 5.
"""

from __future__ import annotations


class SnapshotRegistry:
    """In-process registry that checks source archives and environment references.

    Phase 1: local digest checks only.
    A missing or mismatched archive produces SNAPSHOT_UNAVAILABLE or DIGEST_MISMATCH;
    no substitute commit or image is selected.
    """
