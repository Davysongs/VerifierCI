"""verifierci.panels.registry — panel file validation registry (Phase 1).

SDD Section 4.1, 4.3, 4.4, 5, and 6.5.
Validates panel schema, split constraints, membership uniqueness, lineage,
review/label consistency, and optional artifact verification.
Sealed registry with full protection error handling arrives in Phase 6.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from verifierci.errors import (
    ErrorCode,
    InfrastructureError,
    ProtectionError,
    ValidationError,
)
from verifierci.models.panel import (
    Adjudication,
    PatchCase,
    PatchPanel,
    PatchPanelMembership,
    panel_digest,
    validate_lineage,
)

MAX_PANEL_BYTES = 2 * 1024 * 1024  # 2 MiB
_VALID_SPLITS = frozenset({"development", "assessment", "train"})
_VALID_ROLES = frozenset({"challenge", "reference", "noop"})
_VALID_SOURCES = frozenset({"human", "agent", "mutation", "reference", "noop"})
_VALID_LABELS = frozenset({"valid", "invalid", "unresolved"})
_VALID_REVIEW_STATUSES = frozenset({"provisional", "independent", "disputed"})


@dataclass(frozen=True, slots=True)
class PanelValidationResult:
    """Validated panel records and diagnostic summary."""

    panel: PatchPanel
    cases: tuple[PatchCase, ...]
    adjudications: tuple[Adjudication, ...]
    memberships: tuple[PatchPanelMembership, ...]
    case_diffs: dict[str, bytes]
    findings: tuple[str, ...]
    valid: bool


def _resolve_panel_artifact(root_dir: Path, rel_path_str: str) -> Path:
    """Resolve an artifact path relative to the panel directory without traversal/symlinks."""
    if not rel_path_str:
        raise ProtectionError(
            "Empty artifact path is prohibited in panel records.",
            code=ErrorCode.PROTECTION_ERROR.value,
        )
    if Path(rel_path_str).is_absolute() or rel_path_str.startswith(("/", "\\")):
        raise ProtectionError(
            f"Absolute path is prohibited in panel artifacts: {rel_path_str}",
            code=ErrorCode.PROTECTION_ERROR.value,
        )
    norm_parts = rel_path_str.replace("\\", "/").split("/")
    if ".." in norm_parts:
        raise ProtectionError(
            f"Path traversal is prohibited in panel artifacts: {rel_path_str}",
            code=ErrorCode.PROTECTION_ERROR.value,
        )

    p = root_dir / rel_path_str
    resolved_root = root_dir.resolve()
    cur = p
    while cur != root_dir and cur != cur.parent:
        if cur.is_symlink() or os.path.islink(cur):
            raise ProtectionError(
                f"Symlink rejected in panel artifact path: {rel_path_str}",
                code=ErrorCode.PROTECTION_ERROR.value,
            )
        cur = cur.parent

    try:
        resolved = p.resolve()
        if not resolved.is_relative_to(resolved_root):
            raise ProtectionError(
                f"Panel artifact escapes root directory: {rel_path_str}",
                code=ErrorCode.PROTECTION_ERROR.value,
            )
    except (ValueError, RuntimeError) as exc:
        raise ProtectionError(
            f"Invalid panel artifact path {rel_path_str}: {exc}",
            code=ErrorCode.PROTECTION_ERROR.value,
        ) from exc
    return p


def _parse_panel_payload(
    panel_path: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Parse either a JSON panel object or line-delimited JSONL records."""
    if panel_path.is_symlink() or os.path.islink(panel_path):
        raise ProtectionError(
            f"Symlink rejected in panel loading: {panel_path}",
            code=ErrorCode.PROTECTION_ERROR.value,
        )
    if not panel_path.is_file():
        raise ValidationError(
            f"Panel file not found: {panel_path}",
            code=ErrorCode.VALIDATION_ERROR.value,
        )
    if panel_path.stat().st_size > MAX_PANEL_BYTES:
        raise ValidationError(
            f"Panel file exceeds size limit of {MAX_PANEL_BYTES} bytes: {panel_path}",
            code=ErrorCode.ARTIFACT_LIMIT.value,
        )

    raw_text = panel_path.read_text(encoding="utf-8").strip()
    if not raw_text:
        raise ValidationError(
            f"Panel file is empty: {panel_path}",
            code=ErrorCode.VALIDATION_ERROR.value,
        )

    # First try full-document JSON (e.g. examples/retry-contract/panel.jsonl)
    try:
        doc = json.loads(raw_text)
        if isinstance(doc, dict):
            cases = doc.get("cases", [])
            if not isinstance(cases, list):
                raise ValidationError(
                    "Panel 'cases' field must be a list.",
                    code=ErrorCode.VALIDATION_ERROR.value,
                )
            return doc, cases
    except json.JSONDecodeError:
        pass

    # Fallback: line-delimited JSONL (panel header followed by case/membership lines)
    lines = [line.strip() for line in raw_text.splitlines() if line.strip()]
    records: list[dict[str, Any]] = []
    for idx, line in enumerate(lines, start=1):
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValidationError(
                f"Malformed JSON in panel file {panel_path} line {idx}: {exc}",
                code=ErrorCode.VALIDATION_ERROR.value,
            ) from exc
        if not isinstance(obj, dict):
            raise ValidationError(
                f"Panel line {idx} must be a JSON object.",
                code=ErrorCode.VALIDATION_ERROR.value,
            )
        # Unwrap SDD entity envelope if present
        if (
            "schema_version" in obj
            and "kind" in obj
            and "data" in obj
            and isinstance(obj["data"], dict)
        ):
            inner = dict(obj["data"])
            inner.setdefault("_kind", obj["kind"])
            records.append(inner)
        else:
            records.append(obj)

    header = records[0]
    case_records = records[1:]
    if "cases" in header and isinstance(header["cases"], list) and not case_records:
        return header, header["cases"]
    return header, case_records


def load_and_validate_panel(
    panel_path: Path,
    *,
    task_key: str = "",
    contract_hash: str = "",
    base_snapshot_digest: str = "",
    verify_artifacts: bool = False,
    require_independent: bool = False,
    expected_split: Literal["development", "assessment", "train"] | None = None,
) -> PanelValidationResult:
    """Load and validate a panel file per SDD Section 6.5.

    Read-only: performs no database mutations.
    """
    header, raw_cases = _parse_panel_payload(panel_path)
    root_dir = panel_path.parent
    findings: list[str] = []

    panel_id = header.get("panel_id")
    version = header.get("version")
    split = header.get("split")
    sampling_policy = header.get("sampling_policy", "")

    if not isinstance(panel_id, str) or not panel_id.strip():
        raise ValidationError(
            "Panel missing required 'panel_id'.",
            code=ErrorCode.VALIDATION_ERROR.value,
        )
    if not isinstance(version, str) or not version.strip():
        raise ValidationError(
            "Panel missing required 'version'.",
            code=ErrorCode.VALIDATION_ERROR.value,
        )
    if split not in _VALID_SPLITS:
        raise ValidationError(
            f"Invalid panel split '{split}'. Expected one of {sorted(_VALID_SPLITS)}.",
            code=ErrorCode.VALIDATION_ERROR.value,
        )

    if expected_split is not None and split != expected_split:
        raise ProtectionError(
            f"Panel split '{split}' violates expected split '{expected_split}'.",
            code=ErrorCode.PROTECTION_ERROR.value,
        )

    panel_key = f"{panel_id}@{version}"
    if not raw_cases:
        raise ValidationError(
            f"Panel '{panel_key}' contains no cases.",
            code=ErrorCode.VALIDATION_ERROR.value,
        )

    now = datetime.now(UTC)
    cases: list[PatchCase] = []
    adjudications: list[Adjudication] = []
    memberships: list[PatchPanelMembership] = []
    case_diffs: dict[str, bytes] = {}
    seen_case_ids: set[str] = set()

    effective_task_key = task_key or str(header.get("task_key", "unknown@1.0.0"))
    effective_contract_hash = contract_hash or ("0" * 64)
    effective_snapshot_digest = base_snapshot_digest or ("0" * 64)

    for ordinal, raw_c in enumerate(raw_cases):
        if not isinstance(raw_c, dict):
            raise ValidationError(
                f"Panel case at index {ordinal} must be an object.",
                code=ErrorCode.VALIDATION_ERROR.value,
            )

        case_id = raw_c.get("case_id")
        if not isinstance(case_id, str) or not case_id.strip():
            raise ValidationError(
                f"Panel case at index {ordinal} missing required 'case_id'.",
                code=ErrorCode.VALIDATION_ERROR.value,
            )
        if case_id in seen_case_ids:
            raise ValidationError(
                f"Duplicate case_id '{case_id}' in panel '{panel_key}'.",
                code=ErrorCode.VALIDATION_ERROR.value,
            )
        seen_case_ids.add(case_id)

        role = raw_c.get("role")
        if role not in _VALID_ROLES:
            raise ValidationError(
                f"Case '{case_id}' has invalid role '{role}'. Expected one of {sorted(_VALID_ROLES)}.",
                code=ErrorCode.VALIDATION_ERROR.value,
            )

        source = raw_c.get("source")
        if source not in _VALID_SOURCES:
            raise ValidationError(
                f"Case '{case_id}' has invalid source '{source}'. Expected one of {sorted(_VALID_SOURCES)}.",
                code=ErrorCode.VALIDATION_ERROR.value,
            )

        family_id = raw_c.get("family_id")
        if not isinstance(family_id, str) or not family_id.strip():
            raise ValidationError(
                f"Case '{case_id}' missing required 'family_id'.",
                code=ErrorCode.VALIDATION_ERROR.value,
            )

        raw_parents = raw_c.get("parent_case_ids", ())
        if not isinstance(raw_parents, (list, tuple)):
            raise ValidationError(
                f"Case '{case_id}' 'parent_case_ids' must be a list.",
                code=ErrorCode.VALIDATION_ERROR.value,
            )
        parent_case_ids = tuple(str(p) for p in raw_parents)

        raw_adj = raw_c.get("adjudication")
        if not isinstance(raw_adj, dict):
            raise ValidationError(
                f"Case '{case_id}' missing required 'adjudication' record.",
                code=ErrorCode.VALIDATION_ERROR.value,
            )

        label = raw_adj.get("label")
        if label not in _VALID_LABELS:
            raise ValidationError(
                f"Case '{case_id}' has invalid adjudication label '{label}'.",
                code=ErrorCode.VALIDATION_ERROR.value,
            )
        review_status = raw_adj.get("review_status")
        if review_status not in _VALID_REVIEW_STATUSES:
            raise ValidationError(
                f"Case '{case_id}' has invalid review_status '{review_status}'.",
                code=ErrorCode.VALIDATION_ERROR.value,
            )
        if review_status == "disputed" and label != "unresolved":
            raise ValidationError(
                f"Case '{case_id}' has review_status='disputed' so label must be 'unresolved', got '{label}'.",
                code=ErrorCode.VALIDATION_ERROR.value,
            )

        if require_independent and (
            review_status != "independent" or label == "unresolved"
        ):
            raise ValidationError(
                f"Case '{case_id}' requires independent resolved review (got review_status='{review_status}', label='{label}').",
                code=ErrorCode.VALIDATION_ERROR.value,
            )

        if review_status == "provisional":
            findings.append(f"Case '{case_id}' uses provisional adjudication.")

        # Resolve optional diff / witness artifact references
        diff_field = raw_c.get("diff", "")
        diff_bytes = b""
        if isinstance(diff_field, str) and diff_field:
            if diff_field.startswith("diff --git ") or "\n" in diff_field:
                diff_bytes = diff_field.encode("utf-8")
            else:
                diff_path = _resolve_panel_artifact(root_dir, diff_field)
                if diff_path.is_file():
                    try:
                        diff_bytes = diff_path.read_bytes()
                    except OSError as exc:
                        raise InfrastructureError(
                            f"Failed to read diff artifact '{diff_field}' for case '{case_id}': {exc}",
                            code=ErrorCode.INFRASTRUCTURE_ERROR.value,
                        ) from exc
                elif verify_artifacts:
                    raise InfrastructureError(
                        f"Missing diff artifact '{diff_field}' referenced by case '{case_id}'.",
                        code=ErrorCode.INFRASTRUCTURE_ERROR.value,
                    )
                else:
                    findings.append(
                        f"Diff path '{diff_field}' for case '{case_id}' not present locally."
                    )

        witness_ref = raw_adj.get("witness")
        witness_ids: tuple[str, ...] = ()
        if isinstance(witness_ref, str) and witness_ref:
            witness_ids = (witness_ref,)
            w_path = _resolve_panel_artifact(root_dir, witness_ref)
            if w_path.is_file():
                try:
                    _ = w_path.read_bytes()
                except OSError as exc:
                    raise InfrastructureError(
                        f"Failed to read witness artifact '{witness_ref}' for case '{case_id}': {exc}",
                        code=ErrorCode.INFRASTRUCTURE_ERROR.value,
                    ) from exc
            elif verify_artifacts:
                raise InfrastructureError(
                    f"Missing witness artifact '{witness_ref}' referenced by case '{case_id}'.",
                    code=ErrorCode.INFRASTRUCTURE_ERROR.value,
                )
            else:
                findings.append(
                    f"Witness path '{witness_ref}' for case '{case_id}' not present locally."
                )

        diff_digest = hashlib.sha256(diff_bytes).hexdigest()
        case_diffs[case_id] = diff_bytes

        case_task_key = str(raw_c.get("task_key", effective_task_key))
        prov_digest = hashlib.sha256(
            json.dumps(raw_c, sort_keys=True).encode("utf-8")
        ).hexdigest()

        case_obj = PatchCase(
            case_id=case_id,
            task_key=case_task_key,
            diff_digest=diff_digest,
            base_snapshot_digest=effective_snapshot_digest,
            source=source,
            source_run_id=raw_c.get("source_run_id"),
            parent_case_ids=parent_case_ids,
            family_id=family_id,
            role=role,
            provenance_digest=prov_digest,
            licence=str(raw_c.get("licence", header.get("licence", "Apache-2.0"))),
            created_at=now,
        )
        cases.append(case_obj)

        rationale = str(raw_adj.get("rationale", ""))
        adj_id = str(
            raw_adj.get(
                "adjudication_id",
                hashlib.sha256(
                    f"{case_id}:{effective_contract_hash}:{label}:{rationale}".encode()
                ).hexdigest(),
            )
        )
        adj_obj = Adjudication(
            adjudication_id=adj_id,
            case_id=case_id,
            contract_hash=effective_contract_hash,
            version=int(raw_adj.get("version", 1)),
            label=label,
            review_status=review_status,
            votes=(),
            rationale=rationale,
            requirement_hashes=tuple(
                str(r) for r in raw_adj.get("requirement_hashes", ())
            ),
            witness_ids=witness_ids,
            uncertainty=str(raw_adj.get("uncertainty", "")),
            supersedes_id=raw_adj.get("supersedes_id"),
            created_at=now,
        )
        adjudications.append(adj_obj)

        raw_expected = raw_c.get("expected_control_outcomes", {})
        if raw_expected is None:
            raw_expected = {}
        if not isinstance(raw_expected, dict):
            raise ValidationError(
                f"Case '{case_id}' expected_control_outcomes must be a mapping.",
                code=ErrorCode.VALIDATION_ERROR.value,
            )
        expected_outcomes = {str(k): str(v) for k, v in raw_expected.items()}

        memberships.append(
            PatchPanelMembership(
                panel_key=panel_key,
                case_id=case_id,
                adjudication_id=adj_id,
                ordinal=ordinal,
                expected_control_outcomes=expected_outcomes,
            )
        )

    # Validate lineage across all cases (no cycles)
    validate_lineage(cases)

    m_digest = panel_digest(memberships)
    panel = PatchPanel(
        panel_key=panel_key,
        panel_id=panel_id,
        version=version,
        split=split,
        membership_digest=m_digest,
        sampling_policy=str(sampling_policy),
        exposed_at=None,
        development_used_at=None,
        sealed_at=None,
        retired_at=None,
        parent_panel_key=header.get("parent_panel_key"),
    )

    return PanelValidationResult(
        panel=panel,
        cases=tuple(cases),
        adjudications=tuple(adjudications),
        memberships=tuple(memberships),
        case_diffs=case_diffs,
        findings=tuple(findings),
        valid=True,
    )


class PanelRegistry:
    """In-process registry that freezes membership, split reservations, selected
    adjudications and exposure history.

    Phase 1: file validation only. Validation is all-or-nothing.
    A disputed label stays visible as unresolved.
    """

    def validate_file(
        self,
        panel_path: Path,
        *,
        verify_artifacts: bool = False,
        require_independent: bool = False,
        expected_split: Literal["development", "assessment", "train"] | None = None,
    ) -> PanelValidationResult:
        """Validate a panel file without mutating the database."""
        return load_and_validate_panel(
            panel_path,
            verify_artifacts=verify_artifacts,
            require_independent=require_independent,
            expected_split=expected_split,
        )


__all__ = [
    "PanelRegistry",
    "PanelValidationResult",
    "ProtectionError",
    "load_and_validate_panel",
]
