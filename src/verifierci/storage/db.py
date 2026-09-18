"""verifierci.storage.db — SQLite database layer (Phase 1).

SQLite settings per SDD Section 4.1:
  - Foreign keys enabled
  - WAL on local filesystem
  - synchronous=FULL
  - busy_timeout=5000
  - Schema-versioned migrations executed in a transaction

Immutable content rows reject UPDATE/DELETE through generated triggers.
Operational tables (audit_runs, jobs, active attempts, artifact
locations/availability) have narrow, documented mutations.
"""
from __future__ import annotations


class Database:
    """Local-disk SQLite database owning short, fenced claim and completion
    transactions.

    SQLITE_BUSY gets bounded retry; a lost connection aborts a mutation.
    Claim expiry records an abandoned attempt and requeues only eligible jobs.
    The controller is the sole database writer service.
    """

