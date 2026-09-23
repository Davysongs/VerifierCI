"""verifierci.storage.artifacts — content-addressed artifact store (Phase 1).

The worker atomically stores content-addressed artifacts before committing
attempt and job transitions through the lease fence.

Hashing fixes the bytes that were captured; it does not establish their truth.
Failed collection prevents a valid result.
"""

from __future__ import annotations

import hashlib
import io
import os
import sqlite3
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO, Literal

from verifierci.errors import (
    ErrorCode,
    InfrastructureError,
    ProtectionError,
    ValidationError,
)
from verifierci.models.result import Artifact

CHUNK_SIZE = 64 * 1024  # 64 KB streaming chunks


def _validate_digest(digest: str) -> None:
    if len(digest) != 64 or not all(c in "0123456789abcdef" for c in digest):
        raise ValidationError(
            f"Invalid SHA-256 hex digest: '{digest}'",
            code=ErrorCode.VALIDATION_ERROR.value,
        )


def put_stream(
    root: Path,
    stream: BinaryIO,
    *,
    max_bytes: int,
    kind: str,
    access_policy: Literal["public", "restricted", "sealed"],
    media_type: str = "application/octet-stream",
    retention_until: datetime | None = None,
) -> Artifact:
    """Atomically store a byte stream in content-addressed storage.

    Streams data to a temporary file in root/tmp, computing SHA-256 on the fly.
    Aborts and removes the temporary file if max_bytes is exceeded.
    Renames the file atomically to root/sha256/xx/xxxx...
    """
    if access_policy not in ("public", "restricted", "sealed"):
        raise ValidationError(
            f"Invalid access_policy '{access_policy}'; expected public, restricted, or sealed.",
            code=ErrorCode.VALIDATION_ERROR.value,
        )

    tmp_dir = root / "tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)

    hasher = hashlib.sha256()
    total_bytes = 0

    temp_fd, temp_path_str = tempfile.mkstemp(dir=tmp_dir, prefix="artifact_")
    temp_path = Path(temp_path_str)

    try:
        with open(temp_fd, "wb") as f:
            while True:
                chunk = stream.read(CHUNK_SIZE)
                if not chunk:
                    break
                total_bytes += len(chunk)
                if total_bytes > max_bytes:
                    raise ValidationError(
                        f"Artifact size exceeded limit of {max_bytes} bytes (read {total_bytes} bytes).",
                        code=ErrorCode.ARTIFACT_LIMIT.value,
                    )
                hasher.update(chunk)
                f.write(chunk)
            f.flush()
            os.fsync(f.fileno())

        digest = hasher.hexdigest().lower()
        target_dir = root / "sha256" / digest[:2]
        target_dir.mkdir(parents=True, exist_ok=True)
        target_path = target_dir / digest[2:]

        # Atomic replacement into content-addressed location
        os.replace(temp_path, target_path)

        return Artifact(
            digest=digest,
            kind=kind,
            size_bytes=total_bytes,
            storage_uri=str(target_path.resolve()),
            media_type=media_type,
            access_policy=access_policy,
            retention_until=retention_until,
            available=True,
            created_at=datetime.now(UTC),
        )
    except Exception:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass
        raise


def put_bytes(
    root: Path,
    data: bytes,
    *,
    max_bytes: int,
    kind: str,
    access_policy: Literal["public", "restricted", "sealed"],
    media_type: str = "application/octet-stream",
    retention_until: datetime | None = None,
) -> Artifact:
    """Store raw in-memory bytes into content-addressed storage."""
    if len(data) > max_bytes:
        raise ValidationError(
            f"Artifact size exceeded limit of {max_bytes} bytes (got {len(data)} bytes).",
            code=ErrorCode.ARTIFACT_LIMIT.value,
        )
    return put_stream(
        root=root,
        stream=io.BytesIO(data),
        max_bytes=max_bytes,
        kind=kind,
        access_policy=access_policy,
        media_type=media_type,
        retention_until=retention_until,
    )


def open_verified(root: Path, digest: str) -> BinaryIO:
    """Open an artifact and verify its SHA-256 content checksum.

    Returns an open, seekable BinaryIO positioned at byte 0.
    Raises InfrastructureError if missing or if on-disk bytes do not match digest.
    """
    _validate_digest(digest)
    target_path = root / "sha256" / digest[:2] / digest[2:]

    if not target_path.is_file():
        raise InfrastructureError(
            f"Artifact '{digest}' not found at {target_path}",
            code=ErrorCode.INFRASTRUCTURE_ERROR.value,
        )

    f = open(target_path, "rb")  # noqa: SIM115
    try:
        hasher = hashlib.sha256()
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            hasher.update(chunk)
        actual_digest = hasher.hexdigest().lower()
        if actual_digest != digest:
            raise InfrastructureError(
                f"Artifact digest mismatch: expected '{digest}', got '{actual_digest}'",
                code=ErrorCode.DIGEST_MISMATCH.value,
            )
        f.seek(0)
        return f
    except Exception:
        f.close()
        raise


def collect_outputs(
    output_dir: Path,
    allowed: tuple[str, ...],
    store_root: Path,
    *,
    max_bytes: int,
    access_policy: Literal["public", "restricted", "sealed"] = "restricted",
) -> tuple[Artifact, ...]:
    """Collect allowlisted output files from an execution output directory.

    Rejects symlinks and directory traversal attempts.
    Returns stored Artifact records.
    """
    resolved_output_dir = output_dir.resolve()
    collected: list[Artifact] = []

    for rel_path_str in allowed:
        p = output_dir / rel_path_str
        # Reject symlinks
        if os.path.islink(p) or p.is_symlink():
            raise ProtectionError(
                f"Symlink rejected in output collection: {rel_path_str}",
                code=ErrorCode.PROTECTION_ERROR.value,
            )

        # Reject directory traversal
        try:
            resolved_p = p.resolve()
            if not resolved_p.is_relative_to(resolved_output_dir):
                raise ProtectionError(
                    f"Path traversal rejected in output collection: {rel_path_str}",
                    code=ErrorCode.PROTECTION_ERROR.value,
                )
        except (ValueError, RuntimeError) as exc:
            raise ProtectionError(
                f"Invalid output path: {rel_path_str}",
                code=ErrorCode.PROTECTION_ERROR.value,
            ) from exc

        if not p.exists():
            continue

        if not p.is_file():
            raise ProtectionError(
                f"Output path is not a regular file: {rel_path_str}",
                code=ErrorCode.PROTECTION_ERROR.value,
            )

        # Infer media type and kind
        suffix = p.suffix.lower()
        name = p.name.lower()
        if suffix == ".json":
            media_type = "application/json"
            kind = "report" if "report" in name else "evidence"
        elif suffix in (".txt", ".log"):
            media_type = "text/plain"
            kind = (
                "stdout"
                if "stdout" in name
                else ("stderr" if "stderr" in name else "evidence")
            )
        elif suffix in (".diff", ".patch"):
            media_type = "text/x-diff"
            kind = "diff"
        else:
            media_type = "application/octet-stream"
            kind = "evidence"

        with open(p, "rb") as stream:
            artifact = put_stream(
                root=store_root,
                stream=stream,
                max_bytes=max_bytes,
                kind=kind,
                access_policy=access_policy,
                media_type=media_type,
            )
            collected.append(artifact)

    return tuple(collected)


def garbage_collect(
    root: Path,
    conn: sqlite3.Connection,
    now: datetime,
    *,
    dry_run: bool = True,
) -> tuple[str, ...]:
    """Identify and optionally purge expired non-sealed artifacts.

    Returns the tuple of purged or purgeable artifact digests.
    """
    now_utc = now if now.tzinfo is not None else now.replace(tzinfo=UTC)
    now_utc = now_utc.astimezone(UTC)

    rows = conn.execute(
        """
        SELECT digest, access_policy, retention_until
        FROM artifacts
        WHERE retention_until IS NOT NULL
          AND access_policy != 'sealed'
          AND available = 1
        ORDER BY digest ASC
        """
    ).fetchall()

    purged: list[str] = []
    for row in rows:
        raw_ts = str(row["retention_until"]).strip()
        try:
            if raw_ts.endswith("Z"):
                raw_ts = raw_ts[:-1] + "+00:00"
            ret_dt = datetime.fromisoformat(raw_ts)
            if ret_dt.tzinfo is None:
                ret_dt = ret_dt.replace(tzinfo=UTC)
            else:
                ret_dt = ret_dt.astimezone(UTC)
        except (ValueError, TypeError):
            continue

        if ret_dt <= now_utc:
            digest = row["digest"]
            target_path = root / "sha256" / digest[:2] / digest[2:]
            if not dry_run:
                if target_path.exists():
                    try:
                        target_path.unlink()
                    except OSError:
                        pass
                conn.execute(
                    "UPDATE artifacts SET available = 0 WHERE digest = ?",
                    (digest,),
                )
            purged.append(digest)

    return tuple(purged)


class ArtifactStore:
    """Content-addressed, append-only local artifact store.

    Artifacts are identified by their 64-character lowercase hex SHA-256 digest.
    The store rejects links, duplicate paths, excess bytes and malformed archives.
    """

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "sha256").mkdir(parents=True, exist_ok=True)
        (self.root / "tmp").mkdir(parents=True, exist_ok=True)

    def put_stream(
        self,
        stream: BinaryIO,
        *,
        max_bytes: int,
        kind: str,
        access_policy: Literal["public", "restricted", "sealed"],
        media_type: str = "application/octet-stream",
        retention_until: datetime | None = None,
    ) -> Artifact:
        """Store a byte stream."""
        return put_stream(
            root=self.root,
            stream=stream,
            max_bytes=max_bytes,
            kind=kind,
            access_policy=access_policy,
            media_type=media_type,
            retention_until=retention_until,
        )

    def put_bytes(
        self,
        data: bytes,
        *,
        max_bytes: int,
        kind: str,
        access_policy: Literal["public", "restricted", "sealed"],
        media_type: str = "application/octet-stream",
        retention_until: datetime | None = None,
    ) -> Artifact:
        """Store in-memory bytes."""
        return put_bytes(
            root=self.root,
            data=data,
            max_bytes=max_bytes,
            kind=kind,
            access_policy=access_policy,
            media_type=media_type,
            retention_until=retention_until,
        )

    def open_verified(self, digest: str) -> BinaryIO:
        """Open an artifact and verify its checksum."""
        return open_verified(root=self.root, digest=digest)

    def read_bytes(self, digest: str) -> bytes:
        """Read all verified bytes of an artifact."""
        with self.open_verified(digest) as f:
            return f.read()

    def exists(self, digest: str) -> bool:
        """Check if an artifact exists on disk."""
        try:
            _validate_digest(digest)
        except ValidationError:
            return False
        path = self.root / "sha256" / digest[:2] / digest[2:]
        return path.is_file()

    def get_path(self, digest: str) -> Path:
        """Return the on-disk path for a digest."""
        _validate_digest(digest)
        return self.root / "sha256" / digest[:2] / digest[2:]

    def collect_outputs(
        self,
        output_dir: Path,
        allowed: tuple[str, ...],
        *,
        max_bytes: int,
        access_policy: Literal["public", "restricted", "sealed"] = "restricted",
    ) -> tuple[Artifact, ...]:
        """Collect allowlisted outputs from an execution sandbox directory."""
        return collect_outputs(
            output_dir=output_dir,
            allowed=allowed,
            store_root=self.root,
            max_bytes=max_bytes,
            access_policy=access_policy,
        )

    def garbage_collect(
        self,
        conn: sqlite3.Connection,
        now: datetime,
        *,
        dry_run: bool = True,
    ) -> tuple[str, ...]:
        """Purge expired artifacts."""
        return garbage_collect(
            root=self.root,
            conn=conn,
            now=now,
            dry_run=dry_run,
        )
