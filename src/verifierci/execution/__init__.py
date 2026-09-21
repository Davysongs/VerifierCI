"""verifierci.execution — Job planning, queue supervision, and sandbox execution."""

from .jobs import (
    Job,
    claim,
    complete,
    get_job,
    heartbeat,
    mark_running,
    reap_expired,
    request_cancel,
)
from .matrix import AcceptanceMatrixBuilder, aggregate_cell, build_matrix
from .outcomes import parse_capture
from .planner import build_manifest, compute_expansion_digest, expand, job_id, plan_jobs
from .sandbox import cleanup_attempt, execute, prepare_workspace, validate_patch
from .worker import Worker

__all__ = [
    "AcceptanceMatrixBuilder",
    "Job",
    "Worker",
    "aggregate_cell",
    "build_manifest",
    "build_matrix",
    "claim",
    "cleanup_attempt",
    "complete",
    "compute_expansion_digest",
    "execute",
    "expand",
    "get_job",
    "heartbeat",
    "job_id",
    "mark_running",
    "parse_capture",
    "plan_jobs",
    "prepare_workspace",
    "reap_expired",
    "request_cancel",
    "validate_patch",
]
