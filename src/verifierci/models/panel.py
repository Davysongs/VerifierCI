"""Patch panel models."""
"""Patch panel, case, witness, adjudication, and membership domain models.

SDD Section 4.1, 4.4, and Section 5.
All domain entities are immutable (@dataclass(frozen=True, slots=True)).
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Sequence
from datetime import datetime
from typing import TYPE_CHECKING, Literal

from verifierci.errors import ValidationError
from verifierci.models.task import Contract, canonical_bytes

@dataclass(frozen=True)
if TYPE_CHECKING:
    from verifierci.models.protocol import ReviewVote


@dataclass(frozen=True, slots=True)
class PatchCase:
    """An immutable patch case with provenance and lineage."""

    case_id: str  # Content-derived immutable case identifier.
    task_key: str  # Exact task version used for patch application.
    diff_digest: str  # Unified diff bytes, including empty no-op diff.
    base_snapshot_digest: str  # Source against which the diff was authored.
    source: Literal[
        "human", "agent", "mutation", "reference", "noop"
    ]  # Patch production category.
    source_run_id: str | None  # Optional recorded agent generation run.
    parent_case_ids: tuple[str, ...]  # Direct derivation links to other patches.
    family_id: str  # Implementation/fault lineage group for split control.
    role: Literal["challenge", "reference", "noop"]  # Primary metric eligibility role.
    provenance_digest: str  # Restricted source and generation record.
    licence: str  # Patch redistribution rights record.
    created_at: datetime  # Case registration time.


@dataclass(frozen=True, slots=True)
class Witness:
    """Contract-linked counterexample evidence supporting invalidity or correctness."""

    witness_id: str  # Immutable witness record identity.
    case_id: str  # Patch for which violation evidence is claimed.
    contract_hash: str  # Contract assessed by this witness.
    requirement_hashes: tuple[str, ...]  # Requirements implicated by the evidence.
    input_digest: str  # Bounded witness setup/input.
    expected_digest: str  # Reviewed expected behaviour description/data.
    observed_digest: str  # Recorded counterexample result.
    reproducer_command: tuple[
        str, ...
    ]  # Sandboxed executable plus argv, never a host shell string.
    environment_id: str  # Environment of witness reproduction.
    reviewed_by: tuple[str, ...]  # Reviewers who accepted the evidence link.
    reproduced_at: (
        datetime | None
    )  # Last independently reproduced timestamp, null if pending.


@dataclass(frozen=True, slots=True)
class Adjudication:
    """Independent review decision on a patch case under a specific contract."""

    adjudication_id: str  # Immutable review decision digest.
    case_id: str  # Reviewed patch case.
    contract_hash: str  # Contract on which the label depends.
    version: int  # Monotonic revision number for this case/contract.
    label: Literal[
        "valid", "invalid", "unresolved"
    ]  # Independent bounded correctness assessment.
    review_status: Literal[
        "provisional", "independent", "disputed"
    ]  # Strength and agreement status.
    votes: tuple[ReviewVote, ...]  # Original reviewer decisions retained verbatim.
    rationale: str  # Requirement-based explanation, not a verifier pass count.
    requirement_hashes: tuple[str, ...]  # Reviewed normative requirements.
    witness_ids: tuple[
        str, ...
    ]  # Accepted counterexamples for invalidity or supporting checks.
    uncertainty: str  # Remaining qualifications and disagreements.
    supersedes_id: str | None  # Earlier decision replaced by this revision.
    created_at: datetime  # Decision timestamp.


@dataclass(frozen=True, slots=True)
class PatchPanel:
    """A reviewed set of candidate patch outcomes for a task."""
    """Sealed or development cohort of patch cases for auditing verifiers."""

    task_id: str
    approved_alternatives: tuple[str, ...]
    known_bad_patches: tuple[str, ...] = ()
    panel_key: str  # Stable panel_id plus version.
    panel_id: str  # Cohort identifier.
    version: str  # Immutable panel version.
    split: Literal["development", "assessment", "train"]  # Permitted purpose.
    membership_digest: str  # Canonical sorted membership and adjudication mapping hash.
    sampling_policy: str  # Selection procedure and exclusions.
    exposed_at: (
        datetime | None
    )  # Earliest known disclosure to developers/generators or public.
    development_used_at: datetime | None  # First use for verifier selection or tuning.
    sealed_at: datetime | None  # Irreversible cohort freeze time.
    retired_at: datetime | None  # Date assessment stopped supporting unseen claims.
    parent_panel_key: str | None  # Previous panel version or promotion source.

    @classmethod
    def from_sequences(
        cls,
        task_id: str,
        approved_alternatives: Sequence[str],
        known_bad_patches: Sequence[str] | None = None,
    ) -> "PatchPanel":
        return cls(
            task_id=task_id,
            approved_alternatives=tuple(approved_alternatives),
            known_bad_patches=tuple(known_bad_patches or ()),

@dataclass(frozen=True, slots=True)
class PatchPanelMembership:
    """Membership of one case within a patch panel with its exact adjudication."""

    panel_key: str  # Owning immutable panel version.
    case_id: str  # Member patch.
    adjudication_id: str  # Exact decision used by this panel.
    ordinal: int  # Stable display order, excluded from metric meaning.
    expected_control_outcomes: dict[
        str, str
    ]  # Verifier-key to expected control observation.


@dataclass(frozen=True, slots=True)
class AgentRun:
    """Recorded agent generation run providing candidate patch provenance."""

    agent_run_id: str  # UUID of recorded generation.
    agent_version: str  # Pinned scaffold version or commit.
    model_identifier: str  # Provider/model/snapshot from actual generation.
    prompt_digest: str  # Exact prompt identity, restricted when necessary.
    config_hash: str  # Sampling, tool and reasoning configuration identity.
    budget: dict[str, float | None]  # Token, wall-time and monetary limits.
    patch_digest: str  # Generated diff artifact.
    trajectory_digest: str | None  # Original ATIF/native trace when available.
    model_usage: dict[str, int] | None  # Observed billed usage, never inferred as zero.
    exposure_record_digest: str  # Material available during generation.
    created_at: datetime  # Generation timestamp.


def panel_digest(
    members: tuple[PatchPanelMembership, ...] | Sequence[PatchPanelMembership],
) -> str:
    """Compute 64-char lowercase SHA-256 digest of canonical sorted membership records."""
    # Sort members by case_id to ensure deterministic membership identity
    sorted_members = sorted(members, key=lambda m: m.case_id)
    raw = [
        {
            "panel_key": m.panel_key,
            "case_id": m.case_id,
            "adjudication_id": m.adjudication_id,
            "ordinal": m.ordinal,
            "expected_control_outcomes": m.expected_control_outcomes,
        }
        for m in sorted_members
    ]
    return hashlib.sha256(canonical_bytes(raw)).hexdigest()


def validate_membership(
    case: PatchCase, review: Adjudication, contract: Contract
) -> None:
    """Validate that an adjudication matches the given patch case and task contract."""
    if review.case_id != case.case_id:
        raise ValidationError(
            f"Adjudication case_id '{review.case_id}' does not match case '{case.case_id}'.",
            details={"adjudication_case_id": review.case_id, "case_id": case.case_id},
        )
    if review.contract_hash != contract.contract_hash:
        raise ValidationError(
            f"Adjudication contract_hash '{review.contract_hash}' does not match contract '{contract.contract_hash}'.",
            details={
                "adjudication_contract_hash": review.contract_hash,
                "contract_hash": contract.contract_hash,
            },
        )
    if review.review_status == "disputed" and review.label != "unresolved":
        raise ValidationError(
            f"Disputed adjudication {review.adjudication_id} must have label 'unresolved', got '{review.label}'."
        )


def validate_lineage(cases: tuple[PatchCase, ...] | Sequence[PatchCase]) -> None:
    """Detect lineage cycles and invalid derivation dependencies."""
    case_ids = {c.case_id for c in cases}
    graph: dict[str, list[str]] = {c.case_id: list(c.parent_case_ids) for c in cases}

    # Detect cycles using standard DFS
    visited: dict[str, int] = {}  # 0: visiting, 1: visited

    def dfs(node: str, path: list[str]) -> None:
        visited[node] = 0
        for parent in graph.get(node, []):
            if parent not in case_ids:
                continue
            state = visited.get(parent)
            if state == 0:
                cycle_str = " -> ".join(path + [parent])
                raise ValidationError(
                    f"Lineage cycle detected: {cycle_str}",
                    details={"cycle": path + [parent]},
                )
            if state is None:
                dfs(parent, path + [parent])
        visited[node] = 1

    for cid in case_ids:
        if cid not in visited:
            dfs(cid, [cid])
