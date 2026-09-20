"""Verifier version and manifest domain models.

SDD Section 4.1 and Section 5.
All domain entities are immutable (@dataclass(frozen=True, slots=True)).
"""

from __future__ import annotations

import hashlib
import re
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Any, Literal

from verifierci.errors import ValidationError
from verifierci.models.task import canonical_bytes

_PLACEHOLDER_PATTERN = re.compile(r"\{[^{}]*\}")
_ALLOWED_PLACEHOLDERS = {"{workspace}", "{verifier}", "{out}", "{seed}"}


@dataclass(frozen=True, slots=True)
class CommandSpec:
    """Resolved command specification for container or subprocess execution."""

    argv: tuple[str, ...]  # Resolved executable plus argument strings.
    cwd: str  # Validated working directory inside execution boundary.
    env: Mapping[str, str]  # Explicit allowlist, never inherited controller environment.
    stdin_digest: str | None  # Bounded input artifact when needed.
    timeout_seconds: int  # Deadline bounded by the audit and sandbox policies.

    def __post_init__(self) -> None:
        object.__setattr__(self, "env", MappingProxyType(dict(self.env)))


@dataclass(frozen=True, slots=True)
class VerifierManifest:
    """Immutable verifier execution configuration and test inventory."""

    manifest_hash: str  # Canonical manifest content digest.
    mode: Literal["compatibility", "blackbox"]  # Declared assurance boundary.
    command: tuple[str, ...]  # Executable and exact argv template.
    build_command: tuple[str, ...]  # Optional build argv, empty when absent.
    expected_collection: tuple[
        str, ...
    ]  # Exact required test IDs for this verifier version.
    parser_id: str  # Versioned parser name, such as pytest-report-v1.
    report_path: str  # Allowlisted relative result path under /out.
    payload_digest: str  # Read-only verifier bundle artifact.
    allowed_edit_paths: tuple[str, ...]  # Explicit candidate patch path policy.
    required_pass_ids: tuple[str, ...]  # Scored tests whose success is mandatory.
    permitted_skips: tuple[str, ...]  # Explicit optional tests allowed to skip.
    timeout_seconds: int  # Declared full-attempt wall limit.


def manifest_hash(manifest: VerifierManifest | dict[str, Any]) -> str:
    """Compute 64-char lowercase SHA-256 digest of canonical verifier manifest content.

    Excludes manifest_hash itself.
    """
    if isinstance(manifest, VerifierManifest):
        data = {
            "mode": manifest.mode,
            "command": list(manifest.command),
            "build_command": list(manifest.build_command),
            "expected_collection": list(manifest.expected_collection),
            "parser_id": manifest.parser_id,
            "report_path": manifest.report_path,
            "payload_digest": manifest.payload_digest,
            "allowed_edit_paths": list(manifest.allowed_edit_paths),
            "required_pass_ids": list(manifest.required_pass_ids),
            "permitted_skips": list(manifest.permitted_skips),
            "timeout_seconds": manifest.timeout_seconds,
        }
    else:
        data = {
            "mode": manifest["mode"],
            "command": list(manifest["command"]),
            "build_command": list(manifest.get("build_command", ())),
            "expected_collection": list(manifest["expected_collection"]),
            "parser_id": manifest["parser_id"],
            "report_path": manifest["report_path"],
            "payload_digest": manifest["payload_digest"],
            "allowed_edit_paths": list(manifest["allowed_edit_paths"]),
            "required_pass_ids": list(manifest["required_pass_ids"]),
            "permitted_skips": list(manifest.get("permitted_skips", ())),
            "timeout_seconds": manifest["timeout_seconds"],
        }
    return hashlib.sha256(canonical_bytes(data)).hexdigest()


@dataclass(frozen=True, slots=True)
class VerifierVersion:
    """Versioned identity and manifest linkage for an auditing verifier."""

    verifier_key: str  # Logical verifier ID plus semantic version.
    verifier_id: str  # Stable grader family name.
    version: str  # Version changed when tests, commands or parsing change.
    parent_key: str | None  # Previous version in its lineage.
    manifest_hash: str  # Digest of its VerifierManifest.
    payload_digest: str  # Frozen test/checker bundle.
    compatible_contract_hashes: tuple[str, ...]  # Explicit supported contracts.
    created_at: datetime  # Registration time.


def validate_verifier(version: VerifierVersion, manifest: VerifierManifest) -> None:
    """Validate verifier version and manifest integrity."""
    expected_key = f"{version.verifier_id}@{version.version}"
    if version.verifier_key != expected_key:
        raise ValidationError(
            f"verifier_key '{version.verifier_key}' does not match expected '{expected_key}'.",
            details={"verifier_key": version.verifier_key, "expected": expected_key},
        )
    computed_manifest_hash = manifest_hash(manifest)
    if manifest.manifest_hash != computed_manifest_hash:
        raise ValidationError(
            f"manifest.manifest_hash '{manifest.manifest_hash}' does not match computed '{computed_manifest_hash}'.",
            details={
                "declared_manifest_hash": manifest.manifest_hash,
                "computed_manifest_hash": computed_manifest_hash,
            },
        )
    if version.manifest_hash != computed_manifest_hash:
        raise ValidationError(
            f"version.manifest_hash '{version.manifest_hash}' does not match manifest '{manifest.manifest_hash}'.",
            details={
                "version_manifest_hash": version.manifest_hash,
                "manifest_hash": manifest.manifest_hash,
            },
        )
    if version.payload_digest != manifest.payload_digest:
        raise ValidationError(
            f"version.payload_digest '{version.payload_digest}' does not match manifest '{manifest.payload_digest}'.",
            details={
                "version_payload_digest": version.payload_digest,
                "manifest_payload_digest": manifest.payload_digest,
            },
        )
    if manifest.timeout_seconds <= 0:
        raise ValidationError(
            f"Verifier manifest timeout must be positive, got {manifest.timeout_seconds}."
        )
    if not manifest.command:
        raise ValidationError("Verifier manifest command cannot be empty.")
    if manifest.mode not in ("compatibility", "blackbox"):
        raise ValidationError(f"Invalid verifier mode: {manifest.mode}")


def resolve_command(
    template: tuple[str, ...],
    paths: dict[str, str],
    *,
    cwd: str | None = None,
    timeout_seconds: int = 60,
    env: dict[str, str] | None = None,
) -> CommandSpec:
    """Resolve whole-token placeholders in command argv.

    SDD Section 5:
    Only {workspace}, {verifier}, {out} and {seed} placeholders may occupy
    whole argument tokens. No shell interpolation or unknown placeholder expansion.
    """
    resolved_argv: list[str] = []
    for token in template:
        if "{" in token or "}" in token:
            if token not in _ALLOWED_PLACEHOLDERS:
                raise ValidationError(
                    f"Invalid placeholder in token '{token}'. Only whole-token placeholders "
                    f"({', '.join(sorted(_ALLOWED_PLACEHOLDERS))}) are allowed; partial expansion is prohibited."
                )
            key = token[1:-1]
            if key not in paths:
                raise ValidationError(
                    f"Missing required path substitution for placeholder '{token}'."
                )
            resolved_argv.append(str(paths[key]))
        else:
            resolved_argv.append(token)

    resolved_cwd = cwd if cwd is not None else paths.get("workspace", "/")
    return CommandSpec(
        argv=tuple(resolved_argv),
        cwd=resolved_cwd,
        env=dict(env or {}),
        stdin_digest=None,
        timeout_seconds=timeout_seconds,
    )


def register_verifier(
    conn: sqlite3.Connection,
    version: VerifierVersion,
    manifest: VerifierManifest,
) -> None:
    """Store manifest and version records in the database."""
    validate_verifier(version, manifest)
    raise NotImplementedError(
        "Phase 1 stub: verifier registry persistence is not implemented yet."
    )
