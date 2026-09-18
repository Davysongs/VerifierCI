"""verifierci.storage.artifacts — content-addressed artifact store (Phase 1).

The worker atomically stores content-addressed artifacts before committing
attempt and job transitions through the lease fence.

Hashing fixes the bytes that were captured; it does not establish their truth.
Failed collection prevents a valid result.
"""

from __future__ import annotations


class ArtifactStore:
    """Content-addressed, append-only local artifact store.

    Artifacts are identified by their 64-character lowercase hex SHA-256 digest.
    The store rejects links, duplicate paths, excess bytes and malformed archives.
    """
