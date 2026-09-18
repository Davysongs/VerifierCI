"""Task, requirement, contract, snapshot, and environment domain models.

SDD Section 4.1, 4.4, and Section 5.
All domain entities are immutable (@dataclass(frozen=True, slots=True)).
Canonical JSON uses UTF-8, sorted keys, compact separators, no NaN/Infinity,
and RFC 3339 UTC timestamps.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, fields, is_dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from packaging.version import InvalidVersion
from packaging.version import parse as parse_version

from verifierci.errors import ValidationError

_HEX_64_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def _is_hex_64(val: str) -> bool:
    return bool(_HEX_64_PATTERN.match(val))


def canonical_repr(value: Any) -> Any:
    """Recursively convert values into canonical JSON-serializable primitives."""
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise ValidationError(
                "Non-finite float values are prohibited in canonical JSON."
            )
        return value
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ValidationError("Datetime must be timezone-aware.")
        utc_dt = value.astimezone(UTC)
        return utc_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    if is_dataclass(value):
        res: dict[str, Any] = {}
        for f in fields(value):
            res[f.name] = canonical_repr(getattr(value, f.name))
        return res
    if isinstance(value, dict):
        return {str(k): canonical_repr(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [canonical_repr(v) for v in value]
    raise ValidationError(
        f"Object of type {type(value).__name__} is not canonically serializable."
    )


def canonical_bytes(value: object) -> bytes:
    """Deterministic UTF-8 canonical JSON bytes.

    Compact separators (',', ':'), sorted keys, no NaN/Infinity.
    """
    normalized = canonical_repr(value)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
        ensure_ascii=False,
    ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class Requirement:
    """Normative behavioural requirement within a task contract."""

    requirement_hash: str  # Digest of canonical requirement content.
    requirement_id: str  # Stable identifier within the task contract.
    text: str  # Behaviour an implementation must satisfy.
    source_kind: Literal[
        "explicit", "repository", "clarification"
    ]  # Legitimate source category.
    evidence_digests: tuple[
        str, ...
    ]  # Immutable source excerpts supporting this requirement.
    source_locator: str  # Issue text, repository path/commit or approved clarification.
    allowed_variation: str  # Implementation freedoms relevant to this requirement.


def requirement_hash(requirement: Requirement | dict[str, Any]) -> str:
    """Compute 64-char lowercase SHA-256 hex digest of canonical requirement content.

    Excludes requirement_hash itself. Sorts set-like evidence_digests.
    """
    if isinstance(requirement, Requirement):
        data = {
            "requirement_id": requirement.requirement_id,
            "text": requirement.text,
            "source_kind": requirement.source_kind,
            "evidence_digests": sorted(requirement.evidence_digests),
            "source_locator": requirement.source_locator,
            "allowed_variation": requirement.allowed_variation,
        }
    else:
        evidence = requirement.get("evidence_digests", ())
        data = {
            "requirement_id": requirement["requirement_id"],
            "text": requirement["text"],
            "source_kind": requirement["source_kind"],
            "evidence_digests": sorted(evidence),
            "source_locator": requirement["source_locator"],
            "allowed_variation": requirement["allowed_variation"],
        }
    return hashlib.sha256(canonical_bytes(data)).hexdigest()


@dataclass(frozen=True, slots=True)
class Contract:
    """Normative contract defining acceptable behaviours for a task."""

    contract_hash: str  # Digest of the canonical normative payload.
    task_id: str  # Logical task this contract describes.
    version: str  # Contract semantic version.
    requirement_hashes: tuple[str, ...]  # Sorted requirement content references.
    allowed_variation: str  # Contract-wide implementation freedom.
    unresolved_questions: tuple[
        str, ...
    ]  # Ambiguities that prevent eligibility when material.
    evidence_digests: tuple[str, ...]  # Supporting immutable source evidence.
    created_at: datetime  # Registry creation timestamp.


def contract_hash(contract: Contract | dict[str, Any]) -> str:
    """Compute 64-char lowercase SHA-256 hex digest of normative contract content.

    Excludes contract_hash and non-normative timestamp created_at.
    Sorts set-like requirement_hashes, unresolved_questions, and evidence_digests.
    """
    if isinstance(contract, Contract):
        data = {
            "task_id": contract.task_id,
            "version": contract.version,
            "requirement_hashes": sorted(contract.requirement_hashes),
            "allowed_variation": contract.allowed_variation,
            "unresolved_questions": sorted(contract.unresolved_questions),
            "evidence_digests": sorted(contract.evidence_digests),
        }
    else:
        data = {
            "task_id": contract["task_id"],
            "version": contract["version"],
            "requirement_hashes": sorted(contract.get("requirement_hashes", ())),
            "allowed_variation": contract["allowed_variation"],
            "unresolved_questions": sorted(contract.get("unresolved_questions", ())),
            "evidence_digests": sorted(contract.get("evidence_digests", ())),
        }
    return hashlib.sha256(canonical_bytes(data)).hexdigest()


@dataclass(frozen=True, slots=True)
class RepositorySnapshot:
    """Base source code artifact and commit identity for task evaluation."""

    snapshot_digest: str  # SHA-256 of the normalised archive.
    repository_id: str  # Canonical repository identity used for clustering.
    commit_oid: str  # Exact upstream commit, or native fixture tree identity.
    archive_uri: str  # Approved retrieval locator without embedded credentials.
    tree_digest: str  # Digest of sorted path, mode and content records.
    submodule_digests: tuple[str, ...]  # Explicitly resolved submodule artifacts.
    lock_digests: tuple[str, ...]  # Dependency lock artifacts.
    licence: str  # Source redistribution provenance.
    created_at: datetime  # Snapshot registration time.


@dataclass(frozen=True, slots=True)
class Environment:
    """Immutable execution environment manifest."""

    environment_id: str  # Immutable environment manifest digest.
    backend: Literal[
        "fixture", "docker"
    ]  # Reviewed fixture subprocess or constrained Docker.
    image_digest: str | None  # OCI repository@sha256 reference, required for Docker.
    platform: str  # Pinned OS/architecture, for example linux/amd64.
    recipe_digest: str  # Immutable build recipe identity.
    lock_digests: tuple[str, ...]  # Locked dependencies and wheelhouse references.
    service_manifests: tuple[str, ...]  # Empty for MVP single-container tasks.
    resource_policy_hash: str  # Sandbox limits and allowlist identity.
    runtime_fingerprint: str  # Required interpreter/runtime build identity.
    mirror_uris: tuple[str, ...]  # Approved identical-byte image/archive mirrors.


@dataclass(frozen=True, slots=True)
class Task:
    """Frozen task specification and execution references."""

    task_key: str  # Immutable task_id@version key.
    task_id: str  # Stable logical task identifier.
    version: str  # Semantic task version.
    statement: str  # Exact agent-visible task statement.
    adapter: str  # Importer name and supported format family.
    contract_hash: str  # Frozen contract content identity.
    snapshot_digest: str  # Base source artifact identity.
    environment_id: str  # Frozen execution environment.
    licence: str  # SPDX expression or NOASSERTION pending review.
    provenance: str  # Source URL or dataset revision and instance locator.
    eligibility: Literal[
        "eligible", "excluded", "pending"
    ]  # Admission state for this version.
    notes: str  # Exclusion reasons and unresolved import context.
    created_at: datetime  # UTC creation time, serialised as RFC 3339.


def compare_versions(left: str, right: str) -> int:
    """Compare two semantic version strings using packaging.version.

    Returns:
      -1 if left < right
       0 if left == right
       1 if left > right
    """
    try:
        vl = parse_version(left)
        vr = parse_version(right)
    except InvalidVersion as exc:
        raise ValidationError(
            f"Invalid version comparison '{left}' vs '{right}': {exc}"
        ) from exc

    if vl < vr:
        return -1
    if vl > vr:
        return 1
    return 0


def validate_task(task: Task, contract: Contract) -> None:
    """Validate task integrity and contract linkage."""
    expected_key = f"{task.task_id}@{task.version}"
    if task.task_key != expected_key:
        raise ValidationError(
            f"task_key '{task.task_key}' does not match expected '{expected_key}'.",
            details={"task_key": task.task_key, "expected": expected_key},
        )
    if task.task_id != contract.task_id:
        raise ValidationError(
            f"task.task_id '{task.task_id}' does not match contract.task_id '{contract.task_id}'.",
            details={"task_id": task.task_id, "contract_task_id": contract.task_id},
        )
    if task.contract_hash != contract.contract_hash:
        raise ValidationError(
            f"task.contract_hash '{task.contract_hash}' does not match contract.contract_hash '{contract.contract_hash}'.",
            details={
                "task_contract_hash": task.contract_hash,
                "contract_hash": contract.contract_hash,
            },
        )
    if not _is_hex_64(task.contract_hash):
        raise ValidationError(
            f"task.contract_hash '{task.contract_hash}' is not a valid 64-character lowercase hex digest."
        )
    if not _is_hex_64(task.snapshot_digest):
        raise ValidationError(
            f"task.snapshot_digest '{task.snapshot_digest}' is not a valid 64-character lowercase hex digest."
        )
    if task.eligibility not in ("eligible", "excluded", "pending"):
        raise ValidationError(f"Invalid task eligibility: {task.eligibility}")
    if task.created_at.tzinfo is None or task.created_at.utcoffset() != timedelta(0):
        raise ValidationError("task.created_at must be a timezone-aware UTC datetime.")
