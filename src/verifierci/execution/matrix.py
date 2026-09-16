"""verifierci.execution.matrix — acceptance matrix builder (Phase 1 basic / Phase 2 complete).

An in-process reducer selects authoritative attempts using the frozen retry
policy, then aggregates all planned repetitions.

Phase 1: basic row assembly.
Phase 2: full aggregation with duplicate/conflict rejection and finalisation
         guard for pending jobs.

Rules:
- Rejects duplicate or conflicting identities.
- Refuses finalisation with pending jobs.
- Incomplete rows are displayed only as provisional.
- Attaches the already-frozen adjudication by identity.
"""
from __future__ import annotations


class AcceptanceMatrixBuilder:
    """Reduces per-attempt results to a cell-keyed acceptance matrix.

    A cell is (task, case, verifier).  Each cell aggregates all planned
    repetitions and records the authoritative result selected by the
    frozen retry policy.
    """
