"""verifierci.execution.matrix — acceptance matrix builder and cell reducer.

SDD Section 8.4 and Section 4.1.
An in-process reducer selects authoritative attempts using the frozen retry policy,
then aggregates all planned repetitions into an AcceptanceMatrix.

Repetition Protocol (SDD 8.4):
- 3 repetitions per cell:
  - all accept -> accept (valid)
  - all reject -> reject (valid)
  - mixed accept/reject -> flaky (invalid)
  - all invalid -> invalid_evaluation (invalid)
  - all error -> error (invalid)
  - mixed valid and non-valid -> invalid_evaluation (invalid) with 'instability_detected'
- No majority voting.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Literal

from verifierci.errors import IdentityConflict
from verifierci.models.panel import Adjudication, PatchCase
from verifierci.models.protocol import AcceptanceCell, Job
from verifierci.models.result import (
    AcceptanceMatrix,
    AuditManifest,
    EvaluationAttempt,
    validate_matrix,
)
from verifierci.models.task import canonical_bytes

DEFAULT_REDUCER_VERSION = "1.0.0"


def aggregate_cell(
    *,
    task_key: str,
    repository_id: str,
    case_id: str,
    verifier_key: str,
    adjudication_id: str,
    label: Literal["valid", "invalid", "unresolved"],
    role: Literal["challenge", "reference", "noop"],
    planned_repetitions: int,
    attempts: Sequence[EvaluationAttempt],
    job_repetition_map: Mapping[str, int] | None = None,
) -> AcceptanceCell:
    """Aggregate all repetitions for a (task, case, verifier) cell per SDD Section 8.4."""
    # Group attempts by repetition
    repetition_to_attempts: dict[int, list[EvaluationAttempt]] = {
        r: [] for r in range(planned_repetitions)
    }

    for att in attempts:
        rep = 0
        if job_repetition_map and att.job_id in job_repetition_map:
            rep = job_repetition_map[att.job_id]
        if rep not in repetition_to_attempts:
            repetition_to_attempts[rep] = []
        repetition_to_attempts[rep].append(att)

    selected_attempt_ids: list[str] = []
    excluded_attempt_ids: list[str] = []
    repetition_outcomes: list[str] = []
    diagnostic_codes: list[str] = []

    for r in range(planned_repetitions):
        rep_attempts = repetition_to_attempts.get(r, [])
        authoritative = [a for a in rep_attempts if a.disposition == "authoritative"]

        if authoritative:
            selected = authoritative[-1]
            selected_attempt_ids.append(selected.attempt_id)
            if selected.outcome is not None:
                repetition_outcomes.append(selected.outcome)
            else:
                repetition_outcomes.append("pending")
            if selected.error_code:
                diagnostic_codes.append(selected.error_code)

            for a in rep_attempts:
                if a.attempt_id != selected.attempt_id:
                    excluded_attempt_ids.append(a.attempt_id)
        elif rep_attempts:
            # No authoritative attempt yet; pick the most recent if completed
            active_or_done = rep_attempts[-1]
            if active_or_done.disposition in ("stale", "abandoned"):
                excluded_attempt_ids.extend(a.attempt_id for a in rep_attempts)
            else:
                selected_attempt_ids.append(active_or_done.attempt_id)
                repetition_outcomes.append(active_or_done.outcome or "pending")
                if active_or_done.error_code:
                    diagnostic_codes.append(active_or_done.error_code)
                for a in rep_attempts[:-1]:
                    excluded_attempt_ids.append(a.attempt_id)
        else:
            repetition_outcomes.append("pending")

    # Determine cell outcome & validity from repetition_outcomes
    completed_outcomes = [o for o in repetition_outcomes if o != "pending"]
    if len(completed_outcomes) < planned_repetitions:
        outcome: Literal["accept", "reject", "invalid_evaluation", "flaky", "error"] = (
            "invalid_evaluation"
        )
        validity: Literal["valid", "invalid"] = "invalid"
        if "INCOMPLETE_REPETITIONS" not in diagnostic_codes:
            diagnostic_codes.append("INCOMPLETE_REPETITIONS")
    else:
        accept_count = completed_outcomes.count("accept")
        reject_count = completed_outcomes.count("reject")
        invalid_count = completed_outcomes.count("invalid_evaluation")
        error_count = completed_outcomes.count("error")
        total = len(completed_outcomes)

        if accept_count == total:
            outcome = "accept"
            validity = "valid"
        elif reject_count == total:
            outcome = "reject"
            validity = "valid"
        elif (
            accept_count > 0
            and reject_count > 0
            and (accept_count + reject_count == total)
        ):
            outcome = "flaky"
            validity = "invalid"
            if "FLAKY" not in diagnostic_codes:
                diagnostic_codes.append("FLAKY")
        elif invalid_count == total:
            outcome = "invalid_evaluation"
            validity = "invalid"
        elif error_count == total:
            outcome = "error"
            validity = "invalid"
        else:
            # Mixed valid and non-valid outcomes
            outcome = "invalid_evaluation"
            validity = "invalid"
            if "instability_detected" not in diagnostic_codes:
                diagnostic_codes.append("instability_detected")

    # Deduplicate diagnostic codes while preserving order
    seen_codes: set[str] = set()
    deduped_codes: list[str] = []
    for c in diagnostic_codes:
        if c not in seen_codes:
            seen_codes.add(c)
            deduped_codes.append(c)

    return AcceptanceCell(
        task_key=task_key,
        repository_id=repository_id,
        case_id=case_id,
        verifier_key=verifier_key,
        adjudication_id=adjudication_id,
        label=label,
        role=role,
        outcome=outcome,
        evaluation_validity=validity,
        planned_repetitions=planned_repetitions,
        selected_attempt_ids=tuple(selected_attempt_ids),
        excluded_attempt_ids=tuple(excluded_attempt_ids),
        repetition_outcomes=tuple(repetition_outcomes),
        diagnostic_codes=tuple(deduped_codes),
    )


def build_matrix(
    manifest: AuditManifest,
    jobs: Sequence[Job],
    attempts: Sequence[EvaluationAttempt],
    adjudications: Mapping[str, Adjudication],
    cases: Mapping[str, PatchCase],
    repository_map: Mapping[str, str] | None = None,
    *,
    reducer_version: str = DEFAULT_REDUCER_VERSION,
) -> AcceptanceMatrix:
    """Build authoritative AcceptanceMatrix from jobs and execution attempts."""
    # Check for duplicate job_ids
    seen_job_ids: set[str] = set()
    for j in jobs:
        if j.job_id in seen_job_ids:
            raise IdentityConflict(
                f"Duplicate job_id detected in matrix assembly: {j.job_id}"
            )
        seen_job_ids.add(j.job_id)

    # Check for duplicate attempt_ids
    seen_attempt_ids: set[str] = set()
    for a in attempts:
        if a.attempt_id in seen_attempt_ids:
            raise IdentityConflict(
                f"Duplicate attempt_id detected in matrix assembly: {a.attempt_id}"
            )
        seen_attempt_ids.add(a.attempt_id)

    job_repetition_map = {j.job_id: j.repetition for j in jobs}
    job_by_id = {j.job_id: j for j in jobs}

    # Group attempts by cell: (task_key, case_id, verifier_key)
    cell_keys: set[tuple[str, str, str]] = set()
    for j in jobs:
        cell_keys.add((j.task_key, j.case_id, j.verifier_key))

    attempts_by_cell: dict[tuple[str, str, str], list[EvaluationAttempt]] = {
        k: [] for k in cell_keys
    }
    for a in attempts:
        job = job_by_id.get(a.job_id)
        if job:
            k = (job.task_key, job.case_id, job.verifier_key)
            if k in attempts_by_cell:
                attempts_by_cell[k].append(a)

    cells: list[AcceptanceCell] = []
    # Sort cell keys for deterministic output
    for t_key, c_id, v_key in sorted(cell_keys):
        case = cases.get(c_id)
        role = case.role if case else "challenge"

        # Lookup adjudication
        adj = adjudications.get(c_id)
        if adj is None:
            # Try lookup by adjudication_id if keys are adjudication_ids
            for candidate_adj in adjudications.values():
                if candidate_adj.case_id == c_id:
                    adj = candidate_adj
                    break

        adjudication_id = adj.adjudication_id if adj else "unadjudicated"
        label = adj.label if adj else "unresolved"
        repo_id = repository_map.get(t_key, "") if repository_map else ""

        cell_attempts = attempts_by_cell.get((t_key, c_id, v_key), [])
        cell = aggregate_cell(
            task_key=t_key,
            repository_id=repo_id,
            case_id=c_id,
            verifier_key=v_key,
            adjudication_id=adjudication_id,
            label=label,
            role=role,
            planned_repetitions=manifest.max_repetitions,
            attempts=cell_attempts,
            job_repetition_map=job_repetition_map,
        )
        cells.append(cell)

    is_complete = all(j.state in ("DONE", "FAILED", "ABANDONED") for j in jobs) and all(
        len(c.selected_attempt_ids) == manifest.max_repetitions for c in cells
    )

    # Compute source_attempts_digest
    sorted_attempts = sorted(attempts, key=lambda a: a.attempt_id)
    attempt_records = [
        {
            "attempt_id": a.attempt_id,
            "job_id": a.job_id,
            "disposition": a.disposition,
            "outcome": a.outcome,
            "validity": a.evaluation_validity,
        }
        for a in sorted_attempts
    ]
    source_attempts_digest = hashlib.sha256(
        canonical_bytes(attempt_records)
    ).hexdigest()

    # Compute matrix_id
    matrix_id_payload = {
        "run_id": manifest.run_id,
        "reducer_version": reducer_version,
        "source_attempts_digest": source_attempts_digest,
        "cells": [
            {
                "task_key": c.task_key,
                "case_id": c.case_id,
                "verifier_key": c.verifier_key,
                "outcome": c.outcome,
                "validity": c.evaluation_validity,
            }
            for c in cells
        ],
    }
    matrix_id = hashlib.sha256(canonical_bytes(matrix_id_payload)).hexdigest()

    matrix = AcceptanceMatrix(
        matrix_id=matrix_id,
        run_id=manifest.run_id,
        reducer_version=reducer_version,
        cells=tuple(cells),
        complete=is_complete,
        source_attempts_digest=source_attempts_digest,
        created_at=datetime.now(UTC),
    )
    validate_matrix(matrix, manifest)
    return matrix


class AcceptanceMatrixBuilder:
    """Builder interface for assembling and validating an AcceptanceMatrix."""

    def __init__(
        self,
        manifest: AuditManifest,
        reducer_version: str = DEFAULT_REDUCER_VERSION,
        repository_map: Mapping[str, str] | None = None,
    ) -> None:
        self.manifest = manifest
        self.reducer_version = reducer_version
        self.repository_map = repository_map

    def build(
        self,
        jobs: Sequence[Job],
        attempts: Sequence[EvaluationAttempt],
        adjudications: Mapping[str, Adjudication],
        cases: Mapping[str, PatchCase],
    ) -> AcceptanceMatrix:
        """Build matrix using stored manifest and parameters."""
        return build_matrix(
            manifest=self.manifest,
            jobs=jobs,
            attempts=attempts,
            adjudications=adjudications,
            cases=cases,
            repository_map=self.repository_map,
            reducer_version=self.reducer_version,
        )
