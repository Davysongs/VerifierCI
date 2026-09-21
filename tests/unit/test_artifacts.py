"""Unit tests for content-addressed append-only local artifact store.

SDD Section 4.1 & Section 7.1.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import io
from pathlib import Path
import pytest

from verifierci.errors import (
    ErrorCode,
    InfrastructureError,
    ProtectionError,
    ValidationError,
)
from verifierci.storage.artifacts import ArtifactStore
from verifierci.storage.db import Database


def test_put_bytes_and_open_verified(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    data = b"hello verifierci content-addressed store\n"
    artifact = store.put_bytes(
        data,
        max_bytes=1024,
        kind="evidence",
        access_policy="public",
        media_type="text/plain",
    )

    assert len(artifact.digest) == 64
    assert artifact.size_bytes == len(data)
    assert artifact.kind == "evidence"
    assert artifact.access_policy == "public"
    assert artifact.available is True

    # Check on-disk path structure
    expected_path = tmp_path / "sha256" / artifact.digest[:2] / artifact.digest[2:]
    assert expected_path.is_file()
    assert store.exists(artifact.digest)

    # Read and verify content
    content = store.read_bytes(artifact.digest)
    assert content == data

    # Open verified stream
    with store.open_verified(artifact.digest) as stream:
        assert stream.read() == data


def test_put_stream_atomic(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    stream = io.BytesIO(b"streamed chunk data")
    artifact = store.put_stream(
        stream,
        max_bytes=500,
        kind="snapshot",
        access_policy="restricted",
    )
    assert store.exists(artifact.digest)
    assert store.read_bytes(artifact.digest) == b"streamed chunk data"

    # Verify temporary directory is clean
    tmp_files = list((tmp_path / "tmp").glob("*"))
    assert len(tmp_files) == 0


def test_put_bytes_and_stream_max_bytes_exceeded(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    data = b"1234567890"

    # put_bytes exceeded
    with pytest.raises(ValidationError) as exc_info:
        store.put_bytes(data, max_bytes=5, kind="diff", access_policy="public")
    assert exc_info.value.code == ErrorCode.ARTIFACT_LIMIT.value

    # put_stream exceeded
    with pytest.raises(ValidationError) as exc_info:
        store.put_stream(io.BytesIO(data), max_bytes=5, kind="diff", access_policy="public")
    assert exc_info.value.code == ErrorCode.ARTIFACT_LIMIT.value

    # Check temporary files cleaned up
    tmp_files = list((tmp_path / "tmp").glob("*"))
    assert len(tmp_files) == 0


def test_invalid_access_policy(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    with pytest.raises(ValidationError):
        store.put_bytes(b"data", max_bytes=100, kind="diff", access_policy="unknown")  # type: ignore[arg-type]


def test_corrupted_artifact_detection(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    data = b"pristine authentic content"
    artifact = store.put_bytes(data, max_bytes=100, kind="evidence", access_policy="public")

    # Mutate a byte on disk
    target_path = store.get_path(artifact.digest)
    with open(target_path, "wb") as f:
        f.write(b"tampered fraudulent content")

    with pytest.raises(InfrastructureError) as exc_info:
        store.open_verified(artifact.digest)
    assert exc_info.value.code == ErrorCode.DIGEST_MISMATCH.value


def test_missing_and_invalid_digest(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    # Non-existent valid digest
    non_existent = "0" * 64
    with pytest.raises(InfrastructureError) as exc_info:
        store.open_verified(non_existent)
    assert exc_info.value.code == ErrorCode.INFRASTRUCTURE_ERROR.value

    # Invalid digest format
    with pytest.raises(ValidationError) as exc_info:
        store.open_verified("short_digest")
    assert exc_info.value.code == ErrorCode.VALIDATION_ERROR.value

    assert store.exists("short_digest") is False


def test_collect_outputs_success(tmp_path: Path) -> None:
    sandbox_dir = tmp_path / "sandbox"
    sandbox_dir.mkdir()
    store_dir = tmp_path / "store"
    store = ArtifactStore(store_dir)

    # Populate sandbox outputs
    (sandbox_dir / "report.json").write_text('{"tests": 5}', encoding="utf-8")
    (sandbox_dir / "stdout.log").write_text("running test 1...\n", encoding="utf-8")
    (sandbox_dir / "patch.diff").write_text("--- a\n+++ b\n", encoding="utf-8")

    collected = store.collect_outputs(
        output_dir=sandbox_dir,
        allowed=("report.json", "stdout.log", "patch.diff", "nonexistent.txt"),
        max_bytes=1024,
        access_policy="restricted",
    )

    assert len(collected) == 3
    kinds = {a.kind for a in collected}
    media_types = {a.media_type for a in collected}
    assert "report" in kinds
    assert "stdout" in kinds
    assert "diff" in kinds
    assert "application/json" in media_types
    assert "text/plain" in media_types
    assert "text/x-diff" in media_types


def test_collect_outputs_rejects_symlink(tmp_path: Path) -> None:
    sandbox_dir = tmp_path / "sandbox"
    sandbox_dir.mkdir()
    store_dir = tmp_path / "store"
    store = ArtifactStore(store_dir)

    secret_file = tmp_path / "secret.key"
    secret_file.write_text("top secret", encoding="utf-8")

    symlink_file = sandbox_dir / "link_to_secret"
    symlink_file.symlink_to(secret_file)

    with pytest.raises(ProtectionError) as exc_info:
        store.collect_outputs(
            output_dir=sandbox_dir,
            allowed=("link_to_secret",),
            max_bytes=1024,
        )
    assert exc_info.value.code == ErrorCode.PROTECTION_ERROR.value


def test_collect_outputs_rejects_directory_traversal(tmp_path: Path) -> None:
    sandbox_dir = tmp_path / "sandbox"
    sandbox_dir.mkdir()
    store_dir = tmp_path / "store"
    store = ArtifactStore(store_dir)

    with pytest.raises(ProtectionError) as exc_info:
        store.collect_outputs(
            output_dir=sandbox_dir,
            allowed=("../escape.txt",),
            max_bytes=1024,
        )
    assert exc_info.value.code == ErrorCode.PROTECTION_ERROR.value


def test_garbage_collection(tmp_path: Path) -> None:
    store_dir = tmp_path / "store"
    store = ArtifactStore(store_dir)
    db = Database(":memory:")
    db.migrate()

    now = datetime.now(timezone.utc)
    expired = now - timedelta(days=1)
    future = now + timedelta(days=1)

    # 1. Expired restricted artifact (eligible for purge)
    art1 = store.put_bytes(b"temp1", max_bytes=100, kind="evidence", access_policy="restricted", retention_until=expired)
    # 2. Expired sealed artifact (protected from purge)
    art2 = store.put_bytes(b"sealed_temp", max_bytes=100, kind="evidence", access_policy="sealed", retention_until=expired)
    # 3. Future restricted artifact (not expired)
    art3 = store.put_bytes(b"active", max_bytes=100, kind="evidence", access_policy="restricted", retention_until=future)

    with db.transaction(immediate=True) as conn:
        for a in (art1, art2, art3):
            conn.execute(
                """
                INSERT INTO artifacts (digest, kind, size_bytes, storage_uri, media_type, access_policy, retention_until, available, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
                """,
                (a.digest, a.kind, a.size_bytes, a.storage_uri, a.media_type, a.access_policy, a.retention_until.isoformat() if a.retention_until else None, a.created_at.isoformat()),
            )

    # Dry run
    dry_purged = store.garbage_collect(db.connection, now=now, dry_run=True)
    assert dry_purged == (art1.digest,)
    assert store.exists(art1.digest) is True

    # Real purge
    purged = store.garbage_collect(db.connection, now=now, dry_run=False)
    assert purged == (art1.digest,)
    assert store.exists(art1.digest) is False
    assert store.exists(art2.digest) is True
    assert store.exists(art3.digest) is True

    # Database marked art1 unavailable
    row = db.connection.execute("SELECT available FROM artifacts WHERE digest = ?", (art1.digest,)).fetchone()
    assert row[0] == 0

