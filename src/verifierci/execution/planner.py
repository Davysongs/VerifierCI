"""Execution planning primitives."""

from __future__ import annotations

from .jobs import Job


def plan_jobs(task_ids: list[str]) -> list[Job]:
    """Create one planner job per task id."""

    return [Job(task_id=task_id) for task_id in task_ids]
