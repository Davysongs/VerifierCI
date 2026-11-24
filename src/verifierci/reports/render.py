"""verifierci.reports.render — atomic, static report renderer (Phase 1 JSON / Phase 3 HTML).

SDD Section 2.2, Section 4.3 & 4.4, and Section 5.
An in-process renderer produces atomic, static outputs with sanitized artifact
URIs (no private storage credentials). A failed render leaves the previous file
intact and raises InfrastructureError. Rendering success is distinct from the
audit's gate status.

HTML templates with escaped content arrive in Phase 3.
"""

from __future__ import annotations

import dataclasses
import json
import os
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from verifierci.errors import (
    ErrorCode,
    InfrastructureError,
    ProtectionError,
    ValidationError,
)
from verifierci.models.protocol import AuditResult
from verifierci.models.result import Artifact
from verifierci.models.task import canonical_repr

REPORT_SCHEMA_VERSION = "1.0.0"

_SENSITIVE_QUERY_TOKENS = (
    "token",
    "secret",
    "password",
    "passwd",
    "key",
    "sig",
    "signature",
    "auth",
    "credential",
    "sas",
    "x-amz-",
)


def _sanitize_storage_uri(uri: str) -> str:
    """Strip embedded credentials and sensitive query tokens from a storage URI."""
    if not uri:
        return uri
    parsed = urlsplit(uri)
    if not parsed.scheme and "@" not in parsed.path:
        return uri

    netloc = parsed.netloc
    if "@" in netloc:
        # Strip userinfo (user:pass@host -> host)
        netloc = netloc.rsplit("@", 1)[-1]

    query = parsed.query
    if query:
        filtered_params = [
            (k, v)
            for k, v in parse_qsl(query, keep_blank_values=True)
            if not any(tok in k.lower() for tok in _SENSITIVE_QUERY_TOKENS)
        ]
        query = urlencode(filtered_params)

    # Do not carry fragments or unparsed credentials
    return urlunsplit((parsed.scheme, netloc, parsed.path, query, ""))


def _sanitize_artifacts(
    artifacts: tuple[Artifact, ...],
    *,
    public: bool = False,
) -> tuple[Artifact, ...]:
    """Return artifact index entries with private storage credentials removed."""
    sanitized: list[Artifact] = []
    for art in artifacts:
        if public and art.access_policy != "public":
            continue
        clean_uri = _sanitize_storage_uri(art.storage_uri)
        if clean_uri != art.storage_uri:
            sanitized.append(dataclasses.replace(art, storage_uri=clean_uri))
        else:
            sanitized.append(art)
    return tuple(sanitized)


def serialize_audit_result(
    result: AuditResult,
    *,
    provisional: bool = False,
    public: bool = False,
) -> dict[str, Any]:
    """Validate and convert an AuditResult into its SDD §4.3 JSON envelope."""
    if not isinstance(result, AuditResult):
        raise ValidationError(
            f"Expected AuditResult, got {type(result).__name__}.",
            code=ErrorCode.VALIDATION_ERROR.value,
        )
    if result.manifest is None:
        raise ValidationError(
            "AuditResult manifest cannot be None.",
            code=ErrorCode.VALIDATION_ERROR.value,
        )

    if result.matrix is not None and not result.matrix.complete and not provisional:
        raise ValidationError(
            "Cannot render incomplete acceptance matrix without provisional=True.",
            code=ErrorCode.VALIDATION_ERROR.value,
        )
    if (
        result.matrix is None
        and not provisional
        and not result.diagnostics
        and (result.gate is None or result.gate.state != "INFRASTRUCTURE_ERROR")
    ):
        raise ValidationError(
            "Cannot render AuditResult without a completed matrix or diagnostics unless provisional=True.",
            code=ErrorCode.VALIDATION_ERROR.value,
        )

    sanitized_result = dataclasses.replace(
        result,
        artifacts=_sanitize_artifacts(result.artifacts, public=public),
    )

    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "kind": "AuditResult",
        "data": canonical_repr(sanitized_result),
    }


def format_json_bytes(
    result: AuditResult,
    *,
    provisional: bool = False,
    public: bool = False,
    indent: int | None = 2,
) -> bytes:
    """Serialize an AuditResult to deterministic UTF-8 JSON bytes."""
    envelope = serialize_audit_result(result, provisional=provisional, public=public)
    text = json.dumps(
        envelope,
        sort_keys=True,
        indent=indent,
        allow_nan=False,
        ensure_ascii=False,
    )
    return (text + "\n").encode("utf-8")


def _atomic_write_bytes(destination: Path, payload: bytes) -> None:
    """Write payload to a temporary file in destination's directory, fsync, and replace."""
    if destination.is_symlink() or os.path.islink(destination):
        raise ProtectionError(
            f"Refusing to overwrite symlink report destination: {destination}",
            code=ErrorCode.PROTECTION_ERROR.value,
        )
    if destination.exists() and destination.is_dir():
        raise ValidationError(
            f"Report destination cannot be a directory: {destination}",
            code=ErrorCode.VALIDATION_ERROR.value,
        )

    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        temp_fd, temp_path_str = tempfile.mkstemp(
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
        )
    except OSError as exc:
        raise InfrastructureError(
            f"Failed to prepare temporary report file for {destination}: {exc}",
            code=ErrorCode.INFRASTRUCTURE_ERROR.value,
        ) from exc

    temp_path = Path(temp_path_str)
    try:
        try:
            f = os.fdopen(temp_fd, "wb")
        except Exception:
            os.close(temp_fd)
            raise

        with f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())

        os.replace(temp_path, destination)

        # Best-effort directory fsync for rename durability
        try:
            dir_fd = os.open(destination.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    except OSError as exc:
        raise InfrastructureError(
            f"Failed to write report to {destination}: {exc}",
            code=ErrorCode.INFRASTRUCTURE_ERROR.value,
        ) from exc
    finally:
        if temp_path.exists():
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass


def render_json(
    result: AuditResult,
    destination: Path,
    *,
    provisional: bool = False,
    public: bool = False,
    indent: int | None = 2,
) -> None:
    """Atomically render an AuditResult as static JSON to destination."""
    payload = format_json_bytes(
        result, provisional=provisional, public=public, indent=indent
    )
    _atomic_write_bytes(destination, payload)


def render_html(result: AuditResult, destination: Path) -> None:
    """Render static HTML audit report (scheduled for Phase 3)."""
    raise NotImplementedError("Phase 3 HTML report rendering is not implemented yet.")


def render_summary(result: AuditResult) -> str:
    """Render a concise plain-text summary of an AuditResult."""
    run_id = getattr(result.manifest, "run_id", None) or (
        result.manifest.get("run_id")
        if isinstance(result.manifest, dict)
        else "unknown"
    )
    gate_state = result.gate.state if result.gate is not None else "null"
    complete = result.matrix.complete if result.matrix is not None else False
    cells = result.matrix.cells if result.matrix is not None else ()

    counts: dict[str, int] = {}
    for cell in cells:
        counts[cell.outcome] = counts.get(cell.outcome, 0) + 1

    lines = [
        f"Run ID: {run_id}",
        f"Matrix Complete: {complete}" + (" [PROVISIONAL]" if not complete else ""),
        f"Gate State: {gate_state}",
        f"Cells: {len(cells)} ({', '.join(f'{k}={v}' for k, v in sorted(counts.items())) or 'none'})",
        f"Artifacts: {len(result.artifacts)}",
    ]
    if result.diagnostics:
        lines.append(f"Diagnostics: {'; '.join(result.diagnostics)}")
    return "\n".join(lines)


class ReportRenderer:
    """Renders audit results to JSON (Phase 1) and escaped HTML (Phase 3).

    Outputs are written atomically: the previous file is preserved on failure.
    """

    def render_json(
        self,
        result: AuditResult,
        destination: Path,
        *,
        provisional: bool = False,
        public: bool = False,
        indent: int | None = 2,
    ) -> None:
        """Atomically render an AuditResult as JSON."""
        render_json(
            result,
            destination,
            provisional=provisional,
            public=public,
            indent=indent,
        )

    def render_html(self, result: AuditResult, destination: Path) -> None:
        """Render static HTML audit report (Phase 3)."""
        render_html(result, destination)

    def render_summary(self, result: AuditResult) -> str:
        """Render plain-text summary."""
        return render_summary(result)


__all__ = [
    "REPORT_SCHEMA_VERSION",
    "ReportRenderer",
    "format_json_bytes",
    "render_html",
    "render_json",
    "render_summary",
    "serialize_audit_result",
]
