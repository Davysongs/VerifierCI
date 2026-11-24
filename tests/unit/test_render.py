"""Unit tests for static JSON report renderer (verifierci.reports.render).

SDD Section 2.2, Section 4.3 & 4.4, and Section 5.
Tests atomic writes (temp file + fsync + replace), preservation of prior files
on failure, JSON schema & AuditResult round-trip conformance, credential
redaction in artifact index, provisional/public guards, and symlink rejections.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import jsonschema  # type: ignore[import-untyped]
import pytest

from verifierci.errors import (
    ErrorCode,
    InfrastructureError,
    ProtectionError,
    ValidationError,
)
from verifierci.models.protocol import (
    AcceptanceCell,
    AuditResult,
    decode_record,
)
from verifierci.models.result import AcceptanceMatrix, Artifact, AuditManifest
from verifierci.reports.render import (
    ReportRenderer,
    render_html,
    render_json,
    render_summary,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
AUDIT_RESULT_SCHEMA_PATH = REPO_ROOT / "schemas" / "audit-result.schema.json"


def _make_manifest(run_id: str = "run-render-1") -> AuditManifest:
    return AuditManifest(
        manifest_hash="m" * 64,
        run_id=run_id,
        benchmark_version="1.0.0",
        task_pins=(),
        panel_key="panel@1.0.0",
        adjudication_version="adj-v1",
        evaluation_harness_version="h-1",
        config_hash="c" * 64,
        policy_hash="p" * 64,
        analysis_plan_hash=None,
        timestamp=datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC),
        host_fingerprint="darwin-arm64",
        seed=42,
        agent_version=None,
        model_identifier=None,
        max_repetitions=3,
        max_attempts_per_job=3,
        timeout_seconds=120,
        resource_policy="r" * 64,
        expansion_digest="e" * 64,
        parent_run_id=None,
    )


def _make_matrix(
    run_id: str = "run-render-1",
    *,
    complete: bool = True,
) -> AcceptanceMatrix:
    cell = AcceptanceCell(
        task_key="retry-contract@1.0.0",
        repository_id="repo-1",
        case_id="case-1",
        verifier_key="v1@1.0.0",
        adjudication_id="adj-1",
        label="valid",
        role="reference",
        outcome="accept" if complete else "invalid_evaluation",
        evaluation_validity="valid" if complete else "invalid",
        planned_repetitions=3,
        selected_attempt_ids=("a1", "a2", "a3") if complete else ("a1",),
        excluded_attempt_ids=(),
        repetition_outcomes=("accept", "accept", "accept")
        if complete
        else ("accept", "pending", "pending"),
        diagnostic_codes=() if complete else ("INCOMPLETE_REPETITIONS",),
    )
    return AcceptanceMatrix(
        matrix_id="x" * 64,
        run_id=run_id,
        reducer_version="1.0.0",
        cells=(cell,),
        complete=complete,
        source_attempts_digest="s" * 64,
        created_at=datetime(2026, 1, 1, 12, 5, 0, tzinfo=UTC),
    )


def _make_artifact(
    digest_char: str,
    storage_uri: str,
    access_policy: str = "restricted",
) -> Artifact:
    return Artifact(
        digest=digest_char * 64,
        kind="report",
        size_bytes=256,
        storage_uri=storage_uri,
        media_type="application/json",
        access_policy=access_policy,  # type: ignore[arg-type]
        retention_until=None,
        available=True,
        created_at=datetime(2026, 1, 1, 12, 1, 0, tzinfo=UTC),
    )


def test_render_json_writes_valid_schema_and_roundtrips(tmp_path: Path) -> None:
    manifest = _make_manifest()
    matrix = _make_matrix(complete=True)
    art = _make_artifact("a", "file:///var/verifierci/sha256/aa/aaaa")
    result = AuditResult(
        manifest=manifest,
        matrix=matrix,
        metrics=(),
        gate=None,
        diagnostics=("Synthetic provisional fixture",),
        artifacts=(art,),
    )

    out_path = tmp_path / "reports" / "result.json"
    render_json(result, out_path)

    assert out_path.is_file()
    raw_bytes = out_path.read_bytes()
    payload = json.loads(raw_bytes.decode("utf-8"))

    schema = json.loads(AUDIT_RESULT_SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.validate(instance=payload, schema=schema)

    assert payload["schema_version"] == "1.0.0"
    assert payload["kind"] == "AuditResult"
    assert payload["data"]["manifest"]["run_id"] == "run-render-1"
    assert payload["data"]["matrix"]["complete"] is True
    assert payload["data"]["diagnostics"] == ["Synthetic provisional fixture"]
    assert len(payload["data"]["artifacts"]) == 1

    decoded = decode_record("AuditResult", raw_bytes)
    assert isinstance(decoded, AuditResult)
    assert decoded.matrix == matrix
    assert decoded.diagnostics == ("Synthetic provisional fixture",)


def test_render_json_strips_private_storage_credentials(tmp_path: Path) -> None:
    manifest = _make_manifest()
    matrix = _make_matrix(complete=True)
    art_http = _make_artifact(
        "b",
        "https://admin:supersecret@artifacts.example.com:8443/runs/1?token=abc&region=us-east&X-Amz-Signature=deadbeef#frag",
        access_policy="public",
    )
    art_s3 = _make_artifact(
        "c",
        "s3://accesskey:secretkey@my-bucket/path/obj?AWSAccessKeyId=123&Signature=xyz",
        access_policy="restricted",
    )
    result = AuditResult(
        manifest=manifest,
        matrix=matrix,
        metrics=(),
        gate=None,
        diagnostics=(),
        artifacts=(art_http, art_s3),
    )

    out_path = tmp_path / "sanitized.json"
    render_json(result, out_path)

    text = out_path.read_text(encoding="utf-8")
    for secret in (
        "supersecret",
        "admin",
        "token=abc",
        "deadbeef",
        "secretkey",
        "accesskey",
        "AWSAccessKeyId",
        "Signature=xyz",
        "#frag",
    ):
        assert secret not in text

    payload = json.loads(text)
    uris = [a["storage_uri"] for a in payload["data"]["artifacts"]]
    assert uris[0] == "https://artifacts.example.com:8443/runs/1?region=us-east"
    assert uris[1] == "s3://my-bucket/path/obj"


def test_render_json_public_mode_filters_non_public_artifacts(tmp_path: Path) -> None:
    manifest = _make_manifest()
    matrix = _make_matrix(complete=True)
    art_pub = _make_artifact("1", "https://cdn.example.com/pub.json", "public")
    art_res = _make_artifact("2", "file:///restricted.json", "restricted")
    art_sea = _make_artifact("3", "file:///sealed.json", "sealed")
    result = AuditResult(
        manifest=manifest,
        matrix=matrix,
        metrics=(),
        gate=None,
        diagnostics=(),
        artifacts=(art_pub, art_res, art_sea),
    )

    out_path = tmp_path / "public.json"
    render_json(result, out_path, public=True)

    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert [a["digest"] for a in payload["data"]["artifacts"]] == ["1" * 64]


def test_render_json_rejects_incomplete_matrix_unless_provisional(
    tmp_path: Path,
) -> None:
    manifest = _make_manifest()
    incomplete_matrix = _make_matrix(complete=False)
    result = AuditResult(
        manifest=manifest,
        matrix=incomplete_matrix,
        metrics=(),
        gate=None,
        diagnostics=(),
        artifacts=(),
    )

    out_path = tmp_path / "out.json"
    out_path.write_text('{"previous": "intact"}\n', encoding="utf-8")

    with pytest.raises(ValidationError, match="incomplete acceptance matrix") as exc:
        render_json(result, out_path)
    assert exc.value.code == ErrorCode.VALIDATION_ERROR.value
    # Existing file must stay intact
    assert out_path.read_text(encoding="utf-8") == '{"previous": "intact"}\n'

    # Explicit provisional=True succeeds
    render_json(result, out_path, provisional=True)
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert payload["data"]["matrix"]["complete"] is False


def test_render_json_atomic_failure_preserves_existing_file(tmp_path: Path) -> None:
    manifest = _make_manifest()
    matrix = _make_matrix(complete=True)
    result = AuditResult(
        manifest=manifest,
        matrix=matrix,
        metrics=(),
        gate=None,
        diagnostics=(),
        artifacts=(),
    )

    out_path = tmp_path / "existing.json"
    original_content = '{"keep": "original"}\n'
    out_path.write_text(original_content, encoding="utf-8")

    with patch(
        "verifierci.reports.render.os.replace", side_effect=OSError("disk full")
    ):
        with pytest.raises(InfrastructureError, match="Failed to write report") as exc:
            render_json(result, out_path)
        assert exc.value.code == ErrorCode.INFRASTRUCTURE_ERROR.value

    # Previous file is untouched and no temp files remain
    assert out_path.read_text(encoding="utf-8") == original_content
    assert list(tmp_path.iterdir()) == [out_path]


def test_render_json_fsyncs_and_renames_on_target_filesystem(tmp_path: Path) -> None:
    manifest = _make_manifest()
    matrix = _make_matrix(complete=True)
    result = AuditResult(
        manifest=manifest,
        matrix=matrix,
        metrics=(),
        gate=None,
        diagnostics=(),
        artifacts=(),
    )

    out_path = tmp_path / "atomic.json"
    fsync_calls: list[int] = []
    replace_calls: list[tuple[Path, Path]] = []

    real_fsync = os.fsync
    real_replace = os.replace

    def spy_fsync(fd: int) -> None:
        fsync_calls.append(fd)
        real_fsync(fd)

    def spy_replace(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> None:
        src_p = Path(src)
        dst_p = Path(dst)
        # Temp file must be created in destination's directory (same filesystem)
        assert src_p.parent == dst_p.parent
        replace_calls.append((src_p, dst_p))
        real_replace(src, dst)

    with (
        patch("verifierci.reports.render.os.fsync", side_effect=spy_fsync),
        patch("verifierci.reports.render.os.replace", side_effect=spy_replace),
    ):
        render_json(result, out_path)

    assert len(fsync_calls) >= 1
    assert replace_calls and replace_calls[0][1] == out_path
    assert out_path.is_file()


def test_render_json_rejects_symlink_and_directory_destinations(tmp_path: Path) -> None:
    manifest = _make_manifest()
    matrix = _make_matrix(complete=True)
    result = AuditResult(
        manifest=manifest,
        matrix=matrix,
        metrics=(),
        gate=None,
        diagnostics=(),
        artifacts=(),
    )

    real_target = tmp_path / "real.json"
    real_target.write_text("do-not-overwrite", encoding="utf-8")
    symlink_dest = tmp_path / "link.json"
    symlink_dest.symlink_to(real_target)

    with pytest.raises(ProtectionError, match="symlink") as exc:
        render_json(result, symlink_dest)
    assert exc.value.code == ErrorCode.PROTECTION_ERROR.value
    assert real_target.read_text(encoding="utf-8") == "do-not-overwrite"

    dir_dest = tmp_path / "dir_dest"
    dir_dest.mkdir()
    with pytest.raises(ValidationError, match="cannot be a directory"):
        render_json(result, dir_dest)


def test_report_renderer_methods_and_summary(tmp_path: Path) -> None:
    manifest = _make_manifest()
    matrix = _make_matrix(complete=True)
    result = AuditResult(
        manifest=manifest,
        matrix=matrix,
        metrics=(),
        gate=None,
        diagnostics=("diagnostic-note",),
        artifacts=(),
    )

    renderer = ReportRenderer()
    out_path = tmp_path / "renderer_out.json"
    renderer.render_json(result, out_path)
    assert out_path.is_file()

    summary = renderer.render_summary(result)
    assert summary == render_summary(result)
    assert "Run ID: run-render-1" in summary
    assert "Matrix Complete: True" in summary
    assert "Gate State: null" in summary
    assert "accept=1" in summary
    assert "diagnostic-note" in summary

    with pytest.raises(NotImplementedError):
        renderer.render_html(result, tmp_path / "out.html")
    with pytest.raises(NotImplementedError):
        render_html(result, tmp_path / "out.html")


def test_sanitize_storage_uri_handles_scheme_relative_authorities() -> None:
    from verifierci.reports.render import _sanitize_storage_uri

    sanitized = _sanitize_storage_uri(
        "//alice:secret@storage.example.org/bucket/file.json?token=xyz&keep=1#frag"
    )
    assert "alice" not in sanitized
    assert "secret" not in sanitized
    assert "token" not in sanitized
    assert "frag" not in sanitized
    assert sanitized == "//storage.example.org/bucket/file.json?keep=1"
