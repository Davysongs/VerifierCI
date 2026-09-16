"""verifierci.execution.worker — Python execution worker (Phase 1).

A single process claims one job, renews its lease, supervises subprocesses
and records a result.

Responsibilities:
- Claim one job with BEGIN IMMEDIATE.
- Renew the lease on a background timer.
- Supervise execution subprocesses inside the sandbox.
- Own cleanup in finally; a controller-side reaper handles worker death.
- After lease loss: terminate execution and submit only stale diagnostic
  evidence, never an authoritative result.
"""
from __future__ import annotations


class Worker:
    """Single-job execution worker.

    Claims one job, executes it inside the declared sandbox, collects
    bounded artifacts and commits the attempt result through the lease fence.
    """

