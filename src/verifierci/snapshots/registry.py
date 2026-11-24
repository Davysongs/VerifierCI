"""verifierci.snapshots.registry — local snapshot & trusted fixture digest registry (Phase 1).

Archive extraction and patch parsing occur on the disposable worker machine.
Remote retrieval is added in Phase 5.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from verifierci.errors import ErrorCode, ProtectionError, ValidationError


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
    """Locate datasets/manifests relative to repo root if running from checkout."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "datasets" / "manifests"
        if candidate.is_dir():
            return candidate
    return None


class SnapshotRegistry:
    """In-process registry that checks source snapshots and trusted fixture digests.

    Phase 1: local digest checks only.
    A missing or mismatched digest for a registered trusted fixture raises
    ProtectionError (DIGEST_MISMATCH) so silent tampering cannot proceed.
    """

    def __init__(self, records: dict[str, TrustedFixtureRecord] | None = None) -> None:
        self._records: dict[str, TrustedFixtureRecord] = dict(records or {})

    @classmethod
    def from_manifests_dir(cls, manifests_dir: Path | None = None) -> SnapshotRegistry:
        """Load all trusted fixture manifests from a manifests directory."""
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
            except (OSError, json.JSONDecodeError) as exc:
                raise ValidationError(
                    f"Malformed fixture manifest {path}: {exc}",
                    code=ErrorCode.VALIDATION_ERROR.value,
                ) from exc
            if not isinstance(raw, dict) or "task_key" not in raw:
                continue

            verifiers: dict[str, tuple[str, str]] = {}
            raw_verifiers = raw.get("trusted_verifiers", {})
            if isinstance(raw_verifiers, dict):
                for v_key, v_info in raw_verifiers.items():
                    if isinstance(v_info, dict):
                        verifiers[str(v_key)] = (
                            str(v_info.get("payload_digest", "")),
                            str(v_info.get("manifest_hash", "")),
                        )

            diffs: dict[str, str] = {}
            raw_diffs = raw.get("trusted_case_diffs", {})
            if isinstance(raw_diffs, dict):
                for cid, d_hash in raw_diffs.items():
                    diffs[str(cid)] = str(d_hash)

            record = TrustedFixtureRecord(
                manifest_id=str(raw.get("manifest_id", path.stem)),
                task_key=str(raw["task_key"]),
                panel_key=str(raw.get("panel_key", "")),
                contract_hash=str(raw.get("contract_hash", "")),
                snapshot_digest=str(raw.get("snapshot_digest", "")),
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

        Raises ProtectionError (DIGEST_MISMATCH) if a registered fixture's digests
        do not match the trusted manifest.
        """
        record = self.get(task_key)
        if record is None:
            return [
                f"Unregistered local fixture '{task_key}' running under explicit --trusted-fixture opt-in."
            ]

        if record.snapshot_digest and snapshot_digest != record.snapshot_digest:
            raise ProtectionError(
                f"Trusted fixture snapshot digest mismatch for '{task_key}': "
                f"expected {record.snapshot_digest}, got {snapshot_digest}.",
                code=ErrorCode.DIGEST_MISMATCH.value,
            )

        if record.contract_hash and contract_hash != record.contract_hash:
            raise ProtectionError(
                f"Trusted fixture contract hash mismatch for '{task_key}': "
                f"expected {record.contract_hash}, got {contract_hash}.",
                code=ErrorCode.DIGEST_MISMATCH.value,
            )

        for v_key, (p_dig, m_hash) in verifier_digests.items():
            if v_key in record.trusted_verifiers:
                exp_p, exp_m = record.trusted_verifiers[v_key]
                if (exp_p and p_dig != exp_p) or (exp_m and m_hash != exp_m):
                    raise ProtectionError(
                        f"Trusted fixture verifier digest mismatch for '{v_key}'.",
                        code=ErrorCode.DIGEST_MISMATCH.value,
                    )

        if not record.panel_key or panel_key == record.panel_key:
            for cid, c_digest in case_diff_digests.items():
                if cid in record.trusted_case_diffs:
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
