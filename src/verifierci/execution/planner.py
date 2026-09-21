"""Execution planning primitives."""

from __future__ import annotations

from .jobs import Job


def plan_jobs(task_ids: list[str]) -> list[Job]:
    """Create stub planner jobs for task ids (Phase 1 slice)."""
    return [
        Job(
            job_id=f"job_{task_id}_0",
            run_id="run_0",
            task_key=task_id,
            case_id="case_0",
            verifier_key="verifier_0",
            repetition=0,
            state="PENDING",
            fence=0,
            attempt_id=None,
            lease_token=None,
            worker_id=None,
            lease_expires_ms=None,
            attempts_started=0,
            selected_attempt_id=None,
            terminal_reason=None,
        )
        for task_id in task_ids
    ]
