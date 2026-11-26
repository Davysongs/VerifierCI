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

from verifierci.errors import ErrorCode, IdentityConflict, ValidationError
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
_TERMINAL_JOB_STATES = frozenset({"DONE", "FAILED"})


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
    selected_attempt_by_job: Mapping[str, str] | None = None,
    terminal_failed_rep_reasons: Mapping[int, str | None] | None = None,
) -> AcceptanceCell:
    """Aggregate all repetitions for a (task, case, verifier) cell per SDD Section 8.4."""
    if planned_repetitions < 1:
        raise ValidationError(
            f"planned_repetitions must be >= 1, got {planned_repetitions}.",
            code=ErrorCode.VALIDATION_ERROR.value,
        )

    seen_attempt_ids: set[str] = set()
    for att in attempts:
        if att.attempt_id in seen_attempt_ids:
            raise IdentityConflict(
                f"Duplicate attempt_id detected in cell aggregation: {att.attempt_id}",
                code=ErrorCode.IDENTITY_CONFLICT.value,
            )
        seen_attempt_ids.add(att.attempt_id)

    # Group attempts and planned jobs by repetition
    repetition_to_attempts: dict[int, list[EvaluationAttempt]] = {
        r: [] for r in range(planned_repetitions)
    }
    rep_to_job_ids: dict[int, list[str]] = {r: [] for r in range(planned_repetitions)}
    if job_repetition_map:
        for jid, rep_idx in job_repetition_map.items():
            if 0 <= rep_idx < planned_repetitions:
                rep_to_job_ids[rep_idx].append(jid)

    selected_attempt_ids: list[str] = []
    excluded_attempt_ids: list[str] = []
    repetition_outcomes: list[str] = []
    diagnostic_codes: list[str] = []

    for att in attempts:
        if not job_repetition_map or att.job_id not in job_repetition_map:
            excluded_attempt_ids.append(att.attempt_id)
            continue
        rep = job_repetition_map[att.job_id]
        if rep < 0 or rep >= planned_repetitions:
            excluded_attempt_ids.append(att.attempt_id)
            continue
        repetition_to_attempts[rep].append(att)

    for r in range(planned_repetitions):
        rep_attempts = repetition_to_attempts.get(r, [])
        authoritative = [a for a in rep_attempts if a.disposition == "authoritative"]

        selected: EvaluationAttempt | None = None
        if selected_attempt_by_job:
            expected_selected_ids = [
                selected_attempt_by_job[jid]
                for jid in rep_to_job_ids.get(r, ())
                if jid in selected_attempt_by_job
            ]
            if not expected_selected_ids:
                # Handle aggregate_cell calls without explicit job_repetition_map back-entries
                expected_selected_ids = [
                    selected_attempt_by_job[a.job_id]
                    for a in rep_attempts
                    if a.job_id in selected_attempt_by_job
                ]
            if expected_selected_ids:
                target_id = expected_selected_ids[0]
                fenced = [a for a in rep_attempts if a.attempt_id == target_id]
                if not fenced:
                    raise IdentityConflict(
                        f"Selected attempt '{target_id}' is missing from repetition {r} attempts.",
                        code=ErrorCode.IDENTITY_CONFLICT.value,
                    )
                selected = fenced[0]
                if selected.disposition != "authoritative":
                    raise IdentityConflict(
                        f"Selected attempt '{selected.attempt_id}' for job '{selected.job_id}' "
                        f"is not authoritative (disposition={selected.disposition}).",
                        code=ErrorCode.IDENTITY_CONFLICT.value,
                    )
                extra_auth = [
                    a
                    for a in authoritative
                    if a.job_id == selected.job_id
                    and a.attempt_id != selected.attempt_id
                ]
                if extra_auth:
                    raise IdentityConflict(
                        f"Multiple authoritative attempts found for fenced job '{selected.job_id}'.",
                        code=ErrorCode.IDENTITY_CONFLICT.value,
                    )

        if selected is None and authoritative:
            selected = max(
                authoritative,
                key=lambda a: (a.fence, a.started_at, a.attempt_id),
            )

        if selected is not None:
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
        elif (
            terminal_failed_rep_reasons is not None and r in terminal_failed_rep_reasons
        ):
            # Exhausted retries or cancelled job with only abandoned/stale attempts
            for a in rep_attempts:
                excluded_attempt_ids.append(a.attempt_id)
            repetition_outcomes.append("error")
            reason = terminal_failed_rep_reasons[r] or "INFRASTRUCTURE_ERROR"
            diagnostic_codes.append(reason)
        else:
            # No authoritative terminal selection yet; exclude stale/abandoned retries
            for a in rep_attempts:
                if a.disposition in ("stale", "abandoned"):
                    excluded_attempt_ids.append(a.attempt_id)
            repetition_outcomes.append("pending")

    # Determine cell outcome & validity from repetition_outcomes per SDD Section 8.4
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
        elif accept_count > 0 and reject_count > 0:
            outcome = "flaky"
            validity = "invalid"
            if "FLAKY" not in diagnostic_codes:
                diagnostic_codes.append("FLAKY")
            if (
                accept_count + reject_count < total
                and "execution_error" not in diagnostic_codes
            ):
                diagnostic_codes.append("execution_error")
        elif invalid_count == total:
            outcome = "invalid_evaluation"
            validity = "invalid"
        elif error_count == total:
            outcome = "error"
            validity = "invalid"
        else:
            # Mixed valid and non-valid outcomes (or mixed invalid_evaluation and error)
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
        excluded_attempt_ids=tuple(sorted(excluded_attempt_ids)),
        repetition_outcomes=tuple(repetition_outcomes),
        diagnostic_codes=tuple(deduped_codes),
    )


def build_matrix(
    manifest: AuditManifest,
    jobs: Sequence[Job],
    attempts: Sequence[EvaluationAttempt],
    adjudications: Mapping[str, Adjudication] | None = None,
    cases: Mapping[str, PatchCase] | None = None,
    repository_map: Mapping[str, str] | None = None,
    *,
    reducer_version: str = DEFAULT_REDUCER_VERSION,
    provisional: bool = False,
    created_at: datetime | None = None,
) -> AcceptanceMatrix:
    """Build authoritative AcceptanceMatrix from jobs and execution attempts.

    Refuses finalization (raises ValidationError) if any planned job remains pending
    or non-terminal unless provisional=True is explicitly requested.
    """
    if manifest.max_repetitions < 1:
        raise ValidationError(
            f"Manifest max_repetitions must be >= 1, got {manifest.max_repetitions}.",
            code=ErrorCode.VALIDATION_ERROR.value,
        )
    if not reducer_version:
        raise ValidationError(
            "reducer_version cannot be empty.",
            code=ErrorCode.VALIDATION_ERROR.value,
        )

    adj_map = adjudications if adjudications is not None else {}
    case_map = cases if cases is not None else {}

    # Validate jobs for duplicates, run consistency, and repetition bounds
    seen_job_ids: set[str] = set()
    seen_job_coords: set[tuple[str, str, str, int]] = set()
    for j in jobs:
        if j.job_id in seen_job_ids:
            raise IdentityConflict(
                f"Duplicate job_id detected in matrix assembly: {j.job_id}"
            )
        seen_job_ids.add(j.job_id)

        if j.run_id != manifest.run_id:
            raise IdentityConflict(
                f"Job '{j.job_id}' run_id '{j.run_id}' does not match manifest run_id '{manifest.run_id}'."
            )

        if j.repetition < 0 or j.repetition >= manifest.max_repetitions:
            raise ValidationError(
                f"Job '{j.job_id}' repetition {j.repetition} out of bounds [0, {manifest.max_repetitions}).",
                code=ErrorCode.VALIDATION_ERROR.value,
            )

        coord = (j.task_key, j.case_id, j.verifier_key, j.repetition)
        if coord in seen_job_coords:
            raise IdentityConflict(
                f"Duplicate job coordinate detected in matrix assembly: {coord}"
            )
        seen_job_coords.add(coord)

    # Check for duplicate attempt_ids
    seen_attempt_ids: set[str] = set()
    attempts_by_id: dict[str, EvaluationAttempt] = {}
    attempts_by_job: dict[str, list[EvaluationAttempt]] = {}
    for a in attempts:
        if a.attempt_id in seen_attempt_ids:
            raise IdentityConflict(
                f"Duplicate attempt_id detected in matrix assembly: {a.attempt_id}"
            )
        seen_attempt_ids.add(a.attempt_id)
        attempts_by_id[a.attempt_id] = a
        attempts_by_job.setdefault(a.job_id, []).append(a)

    job_repetition_map = {j.job_id: j.repetition for j in jobs}
    job_by_id = {j.job_id: j for j in jobs}

    # Verify attempts reference known jobs and honor job.selected_attempt_id fencing
    for a in attempts:
        if a.job_id not in job_by_id:
            raise IdentityConflict(
                f"Attempt {a.attempt_id} references unknown job_id: {a.job_id}"
            )

    selected_attempt_by_job: dict[str, str] = {}
    for j in jobs:
        if j.selected_attempt_id is not None:
            sel_att = attempts_by_id.get(j.selected_attempt_id)
            if sel_att is None:
                raise IdentityConflict(
                    f"Job '{j.job_id}' selected_attempt_id '{j.selected_attempt_id}' is missing from attempts."
                )
            if sel_att.job_id != j.job_id:
                raise IdentityConflict(
                    f"Job '{j.job_id}' selected_attempt_id '{j.selected_attempt_id}' belongs to job '{sel_att.job_id}'."
                )
            if sel_att.disposition != "authoritative":
                raise IdentityConflict(
                    f"Job '{j.job_id}' selected attempt '{sel_att.attempt_id}' must have disposition 'authoritative', "
                    f"got '{sel_att.disposition}'."
                )
            other_auth = [
                a
                for a in attempts_by_job.get(j.job_id, ())
                if a.disposition == "authoritative"
                and a.attempt_id != sel_att.attempt_id
            ]
            if other_auth:
                raise IdentityConflict(
                    f"Job '{j.job_id}' has multiple authoritative attempts while fenced to '{sel_att.attempt_id}'."
                )
            if sel_att.fence != j.fence:
                raise IdentityConflict(
                    f"Job '{j.job_id}' selected attempt '{sel_att.attempt_id}' has fence {sel_att.fence}, "
                    f"expected job fence {j.fence}."
                )
            selected_attempt_by_job[j.job_id] = j.selected_attempt_id

    # Collect planned cells from manifest pins (per-task: explicit case_ids vs derived) and jobs
    cell_keys: set[tuple[str, str, str]] = set()
    planned_job_coords: set[tuple[str, str, str, int]] = set()
    explicit_coords_by_task: dict[str, set[tuple[str, str, str, int]]] = {}
    pin_verifiers_by_task: dict[str, set[str]] = {}
    for pin in manifest.task_pins:
        verifiers = [
            v
            for v in dict.fromkeys(
                (pin.verifier_baseline_version, pin.verifier_candidate_version)
            )
            if v
        ]
        pin_verifiers_by_task.setdefault(pin.task_key, set()).update(verifiers)
        if pin.case_ids:
            task_coords = explicit_coords_by_task.setdefault(pin.task_key, set())
            for c_id in pin.case_ids:
                for v_key in verifiers:
                    cell_keys.add((pin.task_key, c_id, v_key))
                    for rep in range(manifest.max_repetitions):
                        coord = (pin.task_key, c_id, v_key, rep)
                        planned_job_coords.add(coord)
                        task_coords.add(coord)

    for j in jobs:
        cell_keys.add((j.task_key, j.case_id, j.verifier_key))

    attempts_by_cell: dict[tuple[str, str, str], list[EvaluationAttempt]] = {
        k: [] for k in cell_keys
    }
    for a in attempts:
        job = job_by_id[a.job_id]
        k = (job.task_key, job.case_id, job.verifier_key)
        attempts_by_cell[k].append(a)

    cells: list[AcceptanceCell] = []
    # Sort cell keys for deterministic output
    for t_key, c_id, v_key in sorted(cell_keys):
        case = case_map.get(c_id)
        role = case.role if case else "challenge"

        # Lookup adjudication
        adj = adj_map.get(c_id)
        if adj is None:
            # Try lookup by adjudication_id if keys are adjudication_ids
            matching_adjs = [
                candidate_adj
                for candidate_adj in adj_map.values()
                if candidate_adj.case_id == c_id
            ]
            if matching_adjs:
                adj = max(matching_adjs, key=lambda a: (a.version, a.adjudication_id))
        elif adj.case_id != c_id:
            raise IdentityConflict(
                f"Adjudication '{adj.adjudication_id}' case_id '{adj.case_id}' does not match '{c_id}'."
            )

        adjudication_id = adj.adjudication_id if adj else "unadjudicated"
        label = adj.label if adj else "unresolved"
        repo_id = repository_map.get(t_key, "") if repository_map else ""

        cell_jobs = [
            j
            for j in jobs
            if (j.task_key, j.case_id, j.verifier_key) == (t_key, c_id, v_key)
        ]
        job_repetition_map = {j.job_id: j.repetition for j in cell_jobs}
        failed_rep_reasons: dict[int, str | None] = {}
        for j in cell_jobs:
            if j.state == "FAILED" and j.selected_attempt_id is None:
                job_atts = attempts_by_job.get(j.job_id, ())
                has_authoritative = any(
                    a.disposition == "authoritative" for a in job_atts
                )
                if not has_authoritative:
                    failed_rep_reasons[j.repetition] = j.terminal_reason
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
            selected_attempt_by_job=selected_attempt_by_job,
            terminal_failed_rep_reasons=failed_rep_reasons,
        )
        cells.append(cell)

    non_terminal_jobs = [j for j in jobs if j.state not in _TERMINAL_JOB_STATES]
    missing_planned_coords = planned_job_coords - seen_job_coords
    extra_planned_coords: set[tuple[str, str, str, int]] = set()
    if pin_verifiers_by_task:
        for coord in seen_job_coords:
            t_key, _c_id, v_key, _rep = coord
            if (
                t_key not in pin_verifiers_by_task
                or v_key not in pin_verifiers_by_task[t_key]
            ):
                extra_planned_coords.add(coord)
                continue
            explicit_coords = explicit_coords_by_task.get(t_key)
            if explicit_coords is not None and coord not in explicit_coords:
                extra_planned_coords.add(coord)
    if extra_planned_coords:
        raise ValidationError(
            f"Cannot finalize acceptance matrix: {len(extra_planned_coords)} job(s) "
            "reference unplanned task/case/verifier/repetition coordinates.",
            code=ErrorCode.VALIDATION_ERROR.value,
        )

    is_complete = (
        len(jobs) > 0
        and not non_terminal_jobs
        and not missing_planned_coords
        and all("pending" not in c.repetition_outcomes for c in cells)
        and all(len(c.repetition_outcomes) == manifest.max_repetitions for c in cells)
        and all("INCOMPLETE_REPETITIONS" not in c.diagnostic_codes for c in cells)
    )

    if not provisional and not is_complete:
        if non_terminal_jobs:
            raise ValidationError(
                f"Cannot finalize acceptance matrix: {len(non_terminal_jobs)} planned job(s) "
                "remain non-terminal (PENDING/CLAIMED/RUNNING/ABANDONED).",
                code=ErrorCode.VALIDATION_ERROR.value,
            )
        if missing_planned_coords:
            raise ValidationError(
                f"Cannot finalize acceptance matrix: {len(missing_planned_coords)} planned job(s) "
                "are missing from execution queue.",
                code=ErrorCode.VALIDATION_ERROR.value,
            )
        raise ValidationError(
            "Cannot finalize acceptance matrix: planned repetitions lack complete terminal attempts.",
            code=ErrorCode.VALIDATION_ERROR.value,
        )

    # Compute source_attempts_digest
    sorted_attempts = sorted(attempts, key=lambda a: a.attempt_id)
    attempt_records = [
        {
            "attempt_id": a.attempt_id,
            "job_id": a.job_id,
            "fence": a.fence,
            "disposition": a.disposition,
            "outcome": a.outcome,
            "validity": a.evaluation_validity,
            "error_code": a.error_code,
        }
        for a in sorted_attempts
    ]
    source_attempts_digest = hashlib.sha256(
        canonical_bytes(attempt_records)
    ).hexdigest()

    # Compute matrix_id
    matrix_id_payload = {
        "manifest_hash": manifest.manifest_hash,
        "run_id": manifest.run_id,
        "reducer_version": reducer_version,
        "complete": is_complete,
        "source_attempts_digest": source_attempts_digest,
        "cells": [
            {
                "task_key": c.task_key,
                "case_id": c.case_id,
                "verifier_key": c.verifier_key,
                "adjudication_id": c.adjudication_id,
                "label": c.label,
                "role": c.role,
                "outcome": c.outcome,
                "validity": c.evaluation_validity,
                "selected_attempt_ids": list(c.selected_attempt_ids),
                "excluded_attempt_ids": list(c.excluded_attempt_ids),
                "repetition_outcomes": list(c.repetition_outcomes),
                "diagnostic_codes": list(c.diagnostic_codes),
            }
            for c in cells
        ],
    }
    matrix_id = hashlib.sha256(canonical_bytes(matrix_id_payload)).hexdigest()

    ts = created_at if created_at is not None else datetime.now(UTC)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)

    matrix = AcceptanceMatrix(
        matrix_id=matrix_id,
        run_id=manifest.run_id,
        reducer_version=reducer_version,
        cells=tuple(cells),
        complete=is_complete,
        source_attempts_digest=source_attempts_digest,
        created_at=ts,
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
        adjudications: Mapping[str, Adjudication] | None = None,
        cases: Mapping[str, PatchCase] | None = None,
        *,
        provisional: bool = False,
        created_at: datetime | None = None,
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
            provisional=provisional,
            created_at=created_at,
        )
