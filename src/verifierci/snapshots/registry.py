"""verifierci.snapshots.registry — local snapshot & trusted fixture digest registry (Phase 1).

Archive extraction and patch parsing occur on the disposable worker machine.
Remote retrieval is added in Phase 5.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from verifierci.errors import ErrorCode, ProtectionError, ValidationError

_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


def _require_sha256_hex(value: Any, *, field: str, source: Path) -> str:
    if not isinstance(value, str) or not _SHA256_HEX_RE.fullmatch(value):
        raise ValidationError(
            f"Fixture manifest {source} has invalid SHA-256 hex digest for '{field}': {value!r}",
            code=ErrorCode.VALIDATION_ERROR.value,
        )
    return value


@dataclass(frozen=True, slots=True)
class TrustedFixtureRecord:
    """Registered SHA-256 digests for a reviewed synthetic fixture."""

    manifest_id: str
    task_key: str
    panel_key: str
    contract_hash: str
    snapshot_digest: str
    trusted_verifiers: dict[
        str, tuple[str, str]
    ]  # verifier_key -> (payload_digest, manifest_hash)
    trusted_case_diffs: dict[str, str]  # case_id -> diff_digest
    synthetic: bool = True
    review_status: str = "provisional"


def _default_manifests_dir() -> Path | None:
    """Locate trusted fixture manifests in checkout datasets/ or packaged data."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "datasets" / "manifests"
        if candidate.is_dir():
            return candidate
    packaged = here.parent / "manifests"
    if packaged.is_dir():
        return packaged
    return None


class SnapshotRegistry:
    """In-process registry that checks source snapshots and trusted fixture digests.

    Phase 1: local digest checks only.
    A missing, unpinned, or mismatched digest for a registered trusted fixture
    raises ProtectionError (DIGEST_MISMATCH) so tampering cannot proceed.
    """

    def __init__(self, records: dict[str, TrustedFixtureRecord] | None = None) -> None:
        self._records: dict[str, TrustedFixtureRecord] = dict(records or {})

    @classmethod
    def from_manifests_dir(cls, manifests_dir: Path | None = None) -> SnapshotRegistry:
        """Load and validate all trusted fixture manifests from manifests_dir."""
        registry = cls()
        target_dir = (
            manifests_dir if manifests_dir is not None else _default_manifests_dir()
        )
        if target_dir is None or not target_dir.is_dir():
            return registry

        for path in sorted(target_dir.glob("*.json")):
            if path.is_symlink() or os.path.islink(path):
                continue
            try:
                raw: Any = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValidationError(
                    f"Malformed fixture manifest {path}: {exc}",
                    code=ErrorCode.VALIDATION_ERROR.value,
                ) from exc
            if not isinstance(raw, dict) or "task_key" not in raw:
                continue

            task_key = raw.get("task_key")
            panel_key = raw.get("panel_key")
            if not isinstance(task_key, str) or not task_key:
                raise ValidationError(
                    f"Fixture manifest {path} missing valid 'task_key'.",
                    code=ErrorCode.VALIDATION_ERROR.value,
                )
            if not isinstance(panel_key, str) or not panel_key:
                raise ValidationError(
                    f"Fixture manifest {path} missing valid 'panel_key'.",
                    code=ErrorCode.VALIDATION_ERROR.value,
                )

            contract_digest = _require_sha256_hex(
                raw.get("contract_hash"), field="contract_hash", source=path
            )
            snapshot_digest = _require_sha256_hex(
                raw.get("snapshot_digest"), field="snapshot_digest", source=path
            )

            raw_verifiers = raw.get("trusted_verifiers")
            if not isinstance(raw_verifiers, dict) or not raw_verifiers:
                raise ValidationError(
                    f"Fixture manifest {path} must define non-empty 'trusted_verifiers' mapping.",
                    code=ErrorCode.VALIDATION_ERROR.value,
                )
            verifiers: dict[str, tuple[str, str]] = {}
            for v_key, v_info in raw_verifiers.items():
                if not isinstance(v_key, str) or not isinstance(v_info, dict):
                    raise ValidationError(
                        f"Fixture manifest {path} has malformed verifier pin '{v_key}'.",
                        code=ErrorCode.VALIDATION_ERROR.value,
                    )
                p_dig = _require_sha256_hex(
                    v_info.get("payload_digest"),
                    field=f"trusted_verifiers.{v_key}.payload_digest",
                    source=path,
                )
                m_hash = _require_sha256_hex(
                    v_info.get("manifest_hash"),
                    field=f"trusted_verifiers.{v_key}.manifest_hash",
                    source=path,
                )
                verifiers[v_key] = (p_dig, m_hash)

            raw_diffs = raw.get("trusted_case_diffs")
            if not isinstance(raw_diffs, dict) or not raw_diffs:
                raise ValidationError(
                    f"Fixture manifest {path} must define non-empty 'trusted_case_diffs' mapping.",
                    code=ErrorCode.VALIDATION_ERROR.value,
                )
            diffs: dict[str, str] = {}
            for cid, d_hash in raw_diffs.items():
                if not isinstance(cid, str) or not cid:
                    raise ValidationError(
                        f"Fixture manifest {path} contains invalid case ID in 'trusted_case_diffs'.",
                        code=ErrorCode.VALIDATION_ERROR.value,
                    )
                diffs[cid] = _require_sha256_hex(
                    d_hash, field=f"trusted_case_diffs.{cid}", source=path
                )

            record = TrustedFixtureRecord(
                manifest_id=str(raw.get("manifest_id", path.stem)),
                task_key=task_key,
                panel_key=panel_key,
                contract_hash=contract_digest,
                snapshot_digest=snapshot_digest,
                trusted_verifiers=verifiers,
                trusted_case_diffs=diffs,
                synthetic=bool(raw.get("synthetic", True)),
                review_status=str(raw.get("review_status", "provisional")),
            )
            registry.register(record)

        return registry

    def register(self, record: TrustedFixtureRecord) -> None:
        """Register or replace a trusted fixture digest record by task_key."""
        self._records[record.task_key] = record

    def get(self, task_key: str) -> TrustedFixtureRecord | None:
        """Return registered trusted fixture digests for task_key, or None if unregistered."""
        return self._records.get(task_key)

    def verify_fixture(
        self,
        *,
        task_key: str,
        contract_hash: str,
        snapshot_digest: str,
        panel_key: str,
        verifier_digests: dict[str, tuple[str, str]],
        case_diff_digests: dict[str, str],
    ) -> list[str]:
        """Verify digests if task_key is registered; return diagnostic messages.

        Raises ProtectionError (DIGEST_MISMATCH) if a registered fixture's panel,
        contract, snapshot, verifiers, or case diffs do not match pinned digests.
        """
        record = self.get(task_key)
        if record is None:
            return [
                (
                    f"Unregistered local fixture '{task_key}' running under explicit "
                    "--trusted-fixture opt-in (digests not checked against an installed manifest)."
                )
            ]

        if snapshot_digest != record.snapshot_digest:
            raise ProtectionError(
                f"Trusted fixture snapshot digest mismatch for '{task_key}': "
                f"expected {record.snapshot_digest}, got {snapshot_digest}.",
                code=ErrorCode.DIGEST_MISMATCH.value,
            )

        if contract_hash != record.contract_hash:
            raise ProtectionError(
                f"Trusted fixture contract hash mismatch for '{task_key}': "
                f"expected {record.contract_hash}, got {contract_hash}.",
                code=ErrorCode.DIGEST_MISMATCH.value,
            )

        if panel_key != record.panel_key:
            raise ProtectionError(
                f"Trusted fixture panel key mismatch for '{task_key}': "
                f"expected '{record.panel_key}', got '{panel_key}'.",
                code=ErrorCode.DIGEST_MISMATCH.value,
            )

        if not verifier_digests:
            raise ProtectionError(
                f"Trusted fixture '{task_key}' requires pinned verifier digests.",
                code=ErrorCode.DIGEST_MISMATCH.value,
            )
        for v_key, (p_dig, m_hash) in verifier_digests.items():
            if v_key not in record.trusted_verifiers:
                raise ProtectionError(
                    f"Verifier '{v_key}' is not pinned in trusted fixture manifest '{record.manifest_id}'.",
                    code=ErrorCode.DIGEST_MISMATCH.value,
                )
            exp_p, exp_m = record.trusted_verifiers[v_key]
            if p_dig != exp_p or m_hash != exp_m:
                raise ProtectionError(
                    f"Trusted fixture verifier digest mismatch for '{v_key}'.",
                    code=ErrorCode.DIGEST_MISMATCH.value,
                )

        if set(case_diff_digests.keys()) != set(record.trusted_case_diffs.keys()):
            raise ProtectionError(
                f"Trusted fixture case set mismatch for '{task_key}': "
                f"expected {sorted(record.trusted_case_diffs)}, got {sorted(case_diff_digests)}.",
                code=ErrorCode.DIGEST_MISMATCH.value,
            )
        for cid, c_digest in case_diff_digests.items():
            exp_diff = record.trusted_case_diffs[cid]
            if c_digest != exp_diff:
                raise ProtectionError(
                    f"Trusted fixture patch diff digest mismatch for case '{cid}': "
                    f"expected {exp_diff}, got {c_digest}.",
                    code=ErrorCode.DIGEST_MISMATCH.value,
                )

        return [
            (
                f"Verified trusted fixture digests against '{record.manifest_id}' "
                f"(synthetic={record.synthetic}, review_status={record.review_status})."
            )
        ]
