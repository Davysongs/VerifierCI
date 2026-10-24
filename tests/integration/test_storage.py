"""Integration tests for storage engine, migrations, triggers, and artifact store.

SDD Section 4.1, 4.4, and 9.2:
- Private temporary database roots and artifact directories.
- Verifies WAL mode, foreign key enforcement, and migration execution.
- Asserts immutability triggers permanently abort UPDATE and DELETE operations on frozen rows.
- Asserts stream writes enforce byte quotas, write to prefixed paths, and re-verify SHA-256 digests on read.
- Asserts bit-rot and tampering detection.
"""

from __future__ import annotations

import io
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from verifierci.errors import (
    ErrorCode,
    InfrastructureError,
    ProtectionError,
    ValidationError,
)
from verifierci.storage.artifacts import ArtifactStore
from verifierci.storage.db import Database, backup_database, connect


def test_disk_database_wal_mode_and_pragmas(tmp_path: Path) -> None:
    """Verify that a disk database automatically uses WAL mode and strict pragmas."""
    db_file = tmp_path / "nested" / "disk_verifier.db"
    assert not db_file.parent.exists()

    conn = connect(db_file)
    try:
        assert db_file.parent.is_dir()
        journal = conn.execute("PRAGMA journal_mode").fetchone()[0]
        fk = conn.execute("PRAGMA foreign_keys").fetchone()[0]
        sync = conn.execute("PRAGMA synchronous").fetchone()[0]
        busy = conn.execute("PRAGMA busy_timeout").fetchone()[0]

        assert journal.lower() == "wal"
        assert fk == 1
        assert sync == 2  # FULL
        assert busy == 5000
    finally:
        conn.close()


def test_foreign_key_enforcement_on_disk(tmp_path: Path) -> None:
    """Verify foreign key constraint enforcement on disk database."""
    db_path = tmp_path / "fk_test.db"
    db = Database(db_path)
    db.migrate()
    conn = db.connection

    # Attempt to insert a task referencing a non-existent contract and snapshot
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            """
            INSERT INTO tasks (
                task_key, task_id, version, statement, adapter,
                contract_hash, snapshot_digest, environment_id,
                licence, provenance, eligibility, notes, created_at
            ) VALUES (
                't1@1.0', 't1', '1.0', 'Statement', 'fixture',
                'nonexistent_contract', 'nonexistent_snapshot', 'env1',
                'MIT', 'prov', 'eligible', '', '2026-09-21T00:00:00Z'
            )
            """
        )


def test_migration_execution_and_backup(tmp_path: Path) -> None:
    """Verify migration execution, schema version tracking, and pre-migration backup."""
    db_path = tmp_path / "mig_test.db"
    db = Database(db_path)

    # Initial migration
    applied = db.migrate()
    assert applied == 2
    conn = db.connection

    # Verify migration records in schema_migrations
    rows = conn.execute(
        "SELECT version, checksum, applied_at FROM schema_migrations ORDER BY version ASC"
    ).fetchall()
    assert len(rows) == 2
    assert rows[0]["version"] == 1
    assert len(rows[0]["checksum"]) == 64
    assert rows[1]["version"] == 2
    assert len(rows[1]["checksum"]) == 64

    # Running migrate again is idempotent and returns latest version
    assert db.migrate() == 2

    # Foreign key check on clean schema returns no errors
    fk_errors = conn.execute("PRAGMA foreign_key_check").fetchall()
    assert len(fk_errors) == 0

    # Verify online backup API
    backup_path = tmp_path / "manual_backup.bak"
    backup_database(conn, backup_path)
    assert backup_path.is_file()
    assert backup_path.stat().st_size > 0

    backup_conn = connect(backup_path)
    try:
        b_row = backup_conn.execute(
            "SELECT version FROM schema_migrations WHERE version = 1"
        ).fetchone()
        assert b_row is not None
    finally:
        backup_conn.close()


def test_immutability_triggers_abort_updates_and_deletes(tmp_path: Path) -> None:
    """Assert triggers abort attempts to update or delete immutable domain rows."""
    db = Database(tmp_path / "triggers.db")
    db.migrate()
    conn = db.connection

    # Seed valid relational hierarchy
    conn.execute(
        """
        INSERT INTO artifacts (digest, kind, size_bytes, storage_uri, media_type, access_policy, available, created_at)
        VALUES ('snap1_hash', 'snapshot', 10, 'file:///s', 'text/plain', 'public', 1, '2026-09-21T00:00:00Z'),
               ('diff1_hash', 'diff', 10, 'file:///d', 'text/x-diff', 'public', 1, '2026-09-21T00:00:00Z'),
               ('pay1_hash', 'payload', 10, 'file:///p', 'application/zip', 'public', 1, '2026-09-21T00:00:00Z'),
               ('out1_hash', 'stdout', 20, 'file:///o', 'text/plain', 'public', 1, '2026-09-21T00:00:00Z'),
               ('err1_hash', 'stderr', 20, 'file:///e', 'text/plain', 'public', 1, '2026-09-21T00:00:00Z'),
               ('rep1_hash', 'report', 20, 'file:///r', 'application/json', 'public', 1, '2026-09-21T00:00:00Z')
        """
    )
    conn.execute(
        """
        INSERT INTO environments (environment_id, backend, platform, recipe_digest, lock_digests, service_manifests, resource_policy_hash, runtime_fingerprint, mirror_uris)
        VALUES ('env1', 'fixture', 'linux/arm64', 'rec1', '[]', '{}', 'p1', 'fp1', '[]')
        """
    )
    conn.execute(
        """
        INSERT INTO repository_snapshots (snapshot_digest, repository_id, commit_oid, archive_uri, tree_digest, submodule_digests, lock_digests, licence, created_at)
        VALUES ('snap1_hash', 'repo1', 'oid1', 'file:///s', 'tree1', '[]', '[]', 'MIT', '2026-09-21T00:00:00Z')
        """
    )
    conn.execute(
        """
        INSERT INTO contracts (contract_hash, task_id, version, requirement_hashes, allowed_variation, unresolved_questions, evidence_digests, created_at)
        VALUES ('con1_hash', 'task1', 'v1', '[]', 'none', '[]', '[]', '2026-09-21T00:00:00Z')
        """
    )
    conn.execute(
        """
        INSERT INTO tasks (task_key, task_id, version, statement, adapter, contract_hash, snapshot_digest, environment_id, licence, provenance, eligibility, notes, created_at)
        VALUES ('task1@v1', 'task1', 'v1', 'statement', 'fixture', 'con1_hash', 'snap1_hash', 'env1', 'MIT', 'prov', 'eligible', '', '2026-09-21T00:00:00Z')
        """
    )
    conn.execute(
        """
        INSERT INTO patch_cases (case_id, task_key, diff_digest, base_snapshot_digest, source, parent_case_ids, family_id, role, provenance_digest, licence, created_at)
        VALUES ('case1', 'task1@v1', 'diff1_hash', 'snap1_hash', 'reference', '[]', 'fam1', 'challenge', 'prov1', 'MIT', '2026-09-21T00:00:00Z')
        """
    )
    conn.execute(
        """
        INSERT INTO adjudications (
            adjudication_id, case_id, contract_hash, version, label,
            review_status, votes, rationale, requirement_hashes, witness_ids,
            uncertainty, created_at
        ) VALUES (
            'adj1', 'case1', 'con1_hash', 1, 'valid',
            'independent', '[]', 'All checks pass', '[]', '[]',
            'none', '2026-09-21T00:00:00Z'
        )
        """
    )
    conn.execute(
        """
        INSERT INTO patch_panels (panel_key, panel_id, version, split, membership_digest, sampling_policy)
        VALUES ('assess_panel@1.0', 'p_assess', '1.0', 'assessment', 'mem_assess', 'fixed'),
               ('dev_panel@1.0', 'p_dev', '1.0', 'development', 'mem_dev', 'stratified')
        """
    )
    conn.execute(
        """
        INSERT INTO split_reservations (reservation_key, assessment_panel_key, reserved_at)
        VALUES ('case:task1@v1:diff1_hash', 'assess_panel@1.0', '2026-09-21T00:00:00Z')
        """
    )

    # 1. Tasks: immutable UPDATE and DELETE
    with pytest.raises(
        sqlite3.IntegrityError, match="immutable entity tasks cannot be updated"
    ):
        conn.execute(
            "UPDATE tasks SET statement = 'changed' WHERE task_key = 'task1@v1'"
        )
    with pytest.raises(
        sqlite3.IntegrityError, match="immutable entity tasks cannot be deleted"
    ):
        conn.execute("DELETE FROM tasks WHERE task_key = 'task1@v1'")

    # 2. Contracts: immutable UPDATE and DELETE
    with pytest.raises(
        sqlite3.IntegrityError, match="immutable entity contracts cannot be updated"
    ):
        conn.execute(
            "UPDATE contracts SET version = 'v2' WHERE contract_hash = 'con1_hash'"
        )
    with pytest.raises(
        sqlite3.IntegrityError, match="immutable entity contracts cannot be deleted"
    ):
        conn.execute("DELETE FROM contracts WHERE contract_hash = 'con1_hash'")

    # 3. Patch Cases: immutable UPDATE and DELETE
    with pytest.raises(
        sqlite3.IntegrityError, match="immutable entity patch_cases cannot be updated"
    ):
        conn.execute(
            "UPDATE patch_cases SET role = 'reference' WHERE case_id = 'case1'"
        )
    with pytest.raises(
        sqlite3.IntegrityError, match="immutable entity patch_cases cannot be deleted"
    ):
        conn.execute("DELETE FROM patch_cases WHERE case_id = 'case1'")

    # 4. Adjudications: immutable UPDATE and DELETE
    with pytest.raises(
        sqlite3.IntegrityError, match="immutable entity adjudications cannot be updated"
    ):
        conn.execute(
            "UPDATE adjudications SET label = 'invalid' WHERE adjudication_id = 'adj1'"
        )
    with pytest.raises(
        sqlite3.IntegrityError, match="immutable entity adjudications cannot be deleted"
    ):
        conn.execute("DELETE FROM adjudications WHERE adjudication_id = 'adj1'")

    # 5. Split Reservations: permanent immutability
    with pytest.raises(
        sqlite3.IntegrityError, match="assessment reservation is permanent"
    ):
        conn.execute(
            "UPDATE split_reservations SET reserved_at = 'changed' WHERE reservation_key = 'case:task1@v1:diff1_hash'"
        )
    with pytest.raises(
        sqlite3.IntegrityError, match="assessment reservation is permanent"
    ):
        conn.execute(
            "DELETE FROM split_reservations WHERE reservation_key = 'case:task1@v1:diff1_hash'"
        )

    # 6. Panel Reservation Guard: cannot add assessment-reserved case to development panel
    with pytest.raises(
        sqlite3.IntegrityError, match="assessment case or family is reserved"
    ):
        conn.execute(
            """
            INSERT INTO panel_memberships (panel_key, case_id, adjudication_id, ordinal, expected_control_outcomes)
            VALUES ('dev_panel@1.0', 'case1', 'adj1', 0, '[]')
            """
        )

    # 7. Sealed Patch Panel: once sealed, cannot update or delete
    conn.execute(
        """
        INSERT INTO patch_panels (panel_key, panel_id, version, split, membership_digest, sampling_policy, sealed_at)
        VALUES ('sealed_panel@1.0', 'p_seal', '1.0', 'assessment', 'mem_seal', 'fixed', '2026-09-21T00:00:00Z')
        """
    )
    with pytest.raises(
        sqlite3.IntegrityError, match="immutable entity patch_panels cannot be updated"
    ):
        conn.execute(
            "UPDATE patch_panels SET sampling_policy = 'other' WHERE panel_key = 'sealed_panel@1.0'"
        )
    with pytest.raises(
        sqlite3.IntegrityError, match="immutable entity patch_panels cannot be deleted"
    ):
        conn.execute("DELETE FROM patch_panels WHERE panel_key = 'sealed_panel@1.0'")


def test_authoritative_evaluation_attempt_immutability(tmp_path: Path) -> None:
    """Assert authoritative evaluation attempts cannot be updated or deleted."""
    db = Database(tmp_path / "attempts_immutability.db")
    db.migrate()
    conn = db.connection

    # Seed audit run & job
    conn.execute(
        """
        INSERT INTO artifacts (digest, kind, size_bytes, storage_uri, media_type, access_policy, available, created_at)
        VALUES ('snap1', 'snapshot', 10, 'file:///s', 'text/plain', 'public', 1, '2026-09-21T00:00:00Z'),
               ('pay1', 'payload', 10, 'file:///p', 'application/zip', 'public', 1, '2026-09-21T00:00:00Z')
        """
    )
    conn.execute(
        """
        INSERT INTO environments (environment_id, backend, platform, recipe_digest, lock_digests, service_manifests, resource_policy_hash, runtime_fingerprint, mirror_uris)
        VALUES ('env1', 'fixture', 'linux/arm64', 'rec1', '[]', '{}', 'p1', 'fp1', '[]')
        """
    )
    conn.execute(
        """
        INSERT INTO repository_snapshots (snapshot_digest, repository_id, commit_oid, archive_uri, tree_digest, submodule_digests, lock_digests, licence, created_at)
        VALUES ('snap1', 'repo1', 'oid1', 'file:///s', 'tree1', '[]', '[]', 'MIT', '2026-09-21T00:00:00Z')
        """
    )
    conn.execute(
        """
        INSERT INTO contracts (contract_hash, task_id, version, requirement_hashes, allowed_variation, unresolved_questions, evidence_digests, created_at)
        VALUES ('con1', 'task1', 'v1', '[]', 'none', '[]', '[]', '2026-09-21T00:00:00Z')
        """
    )
    conn.execute(
        """
        INSERT INTO tasks (task_key, task_id, version, statement, adapter, contract_hash, snapshot_digest, environment_id, licence, provenance, eligibility, notes, created_at)
        VALUES ('tkey1', 'task1', 'v1', 'statement', 'fixture', 'con1', 'snap1', 'env1', 'MIT', 'prov', 'eligible', '', '2026-09-21T00:00:00Z')
        """
    )
    conn.execute(
        """
        INSERT INTO patch_cases (case_id, task_key, diff_digest, base_snapshot_digest, source, parent_case_ids, family_id, role, provenance_digest, licence, created_at)
        VALUES ('case1', 'tkey1', 'snap1', 'snap1', 'reference', '[]', 'fam1', 'challenge', 'prov1', 'MIT', '2026-09-21T00:00:00Z')
        """
    )
    conn.execute(
        """
        INSERT INTO patch_panels (panel_key, panel_id, version, split, membership_digest, sampling_policy)
        VALUES ('panel1', 'p1', 'v1', 'development', 'mem1', 'policy1')
        """
    )
    conn.execute(
        """
        INSERT INTO verifier_manifests (manifest_hash, mode, command, build_command, expected_collection, parser_id, report_path, payload_digest, allowed_edit_paths, required_pass_ids, permitted_skips, timeout_seconds)
        VALUES ('vman1', 'compatibility', '["pytest"]', '["true"]', '["test_1"]', 'pytest', 'report.json', 'pay1', '["*"]', '[]', '[]', 30)
        """
    )
    conn.execute(
        """
        INSERT INTO verifier_versions (verifier_key, verifier_id, version, manifest_hash, payload_digest, compatible_contract_hashes, created_at)
        VALUES ('vkey1', 'verifier1', 'v1', 'vman1', 'pay1', '["con1"]', '2026-09-21T00:00:00Z')
        """
    )
    conn.execute(
        """
        INSERT INTO audit_manifests (manifest_hash, run_id, benchmark_version, task_pins, panel_key, adjudication_version, evaluation_harness_version, config_hash, policy_hash, timestamp, host_fingerprint, max_repetitions, max_attempts_per_job, timeout_seconds, resource_policy, expansion_digest)
        VALUES ('man1', 'run1', 'bench1', '[]', 'panel1', 'adj1', 'harn1', 'conf1', 'pol1', '2026-09-21T00:00:00Z', 'host1', 1, 3, 30, 'pol', 'exp1')
        """
    )
    conn.execute(
        """
        INSERT INTO audit_runs (run_id, manifest_hash, state, cancel_requested, created_at)
        VALUES ('run1', 'man1', 'RUNNING', 0, '2026-09-21T00:00:00Z')
        """
    )
    conn.execute(
        """
        INSERT INTO jobs (job_id, run_id, task_key, case_id, verifier_key, repetition, state, fence, attempts_started)
        VALUES ('job1', 'run1', 'tkey1', 'case1', 'vkey1', 0, 'RUNNING', 1, 1)
        """
    )

    # Active attempt can be updated to authoritative
    conn.execute(
        """
        INSERT INTO evaluation_attempts (
            attempt_id, job_id, fence, outcome, evaluation_validity,
            error_code, disposition, started_at, test_collection, resources,
            artifact_digests, capture_truncated
        ) VALUES (
            'att_authoritative', 'job1', 1, NULL, 'pending',
            NULL, 'active', '2026-09-21T00:00:00Z', '[]', '{}',
            '[]', 0
        )
        """
    )

    conn.execute(
        """
        UPDATE evaluation_attempts
        SET disposition = 'authoritative',
            outcome = 'accept',
            evaluation_validity = 'valid',
            finished_at = '2026-09-21T00:01:00Z'
        WHERE attempt_id = 'att_authoritative'
        """
    )

    # Now authoritative: UPDATE must fail
    with pytest.raises(
        sqlite3.IntegrityError,
        match="authoritative evaluation attempt cannot be updated",
    ):
        conn.execute(
            """
            UPDATE evaluation_attempts
            SET outcome = 'reject'
            WHERE attempt_id = 'att_authoritative'
            """
        )

    # Deletion must also fail
    with pytest.raises(
        sqlite3.IntegrityError,
        match="authoritative evaluation attempt cannot be deleted",
    ):
        conn.execute(
            "DELETE FROM evaluation_attempts WHERE attempt_id = 'att_authoritative'"
        )


def test_artifact_store_stream_writes_enforce_byte_quota(tmp_path: Path) -> None:
    """Assert stream writes enforce byte quotas and abort without partial files."""
    store = ArtifactStore(tmp_path / "artifacts")
    data = b"X" * 1500

    # Stream exceeding max_bytes
    stream = io.BytesIO(data)
    with pytest.raises(ValidationError) as exc_info:
        store.put_stream(
            stream,
            max_bytes=1000,
            kind="log",
            access_policy="public",
            media_type="text/plain",
        )
    assert exc_info.value.code == ErrorCode.ARTIFACT_LIMIT.value

    # Verify no file survived in sha256 or tmp
    sha_dir = tmp_path / "artifacts" / "sha256"
    tmp_dir = tmp_path / "artifacts" / "tmp"
    if sha_dir.exists():
        assert len(list(sha_dir.rglob("*"))) == 0
    if tmp_dir.exists():
        assert len(list(tmp_dir.iterdir())) == 0


def test_artifact_store_prefixed_paths_and_verified_reading(tmp_path: Path) -> None:
    """Assert artifact storage writes to sha256/xx/xxxx... and re-verifies SHA-256 on read."""
    store = ArtifactStore(tmp_path / "artifacts")
    payload = b"deterministic content-addressed storage verification payload"

    artifact = store.put_bytes(
        payload,
        max_bytes=10_000,
        kind="evidence",
        access_policy="public",
        media_type="application/octet-stream",
    )

    digest = artifact.digest
    expected_path = tmp_path / "artifacts" / "sha256" / digest[:2] / digest[2:]
    assert expected_path.is_file()

    # Read verified
    with store.open_verified(digest) as f:
        read_bytes = f.read()
    assert read_bytes == payload

    # Tamper with file on disk to simulate corruption / bit-rot
    with open(expected_path, "wb") as f:
        f.write(payload + b"_corrupted_bytes")

    # open_verified must detect mismatch
    with (
        pytest.raises(InfrastructureError) as exc_info,
        store.open_verified(digest) as f,
    ):
        f.read()
    assert exc_info.value.code == ErrorCode.DIGEST_MISMATCH.value


def test_artifact_store_rejects_symlinks_and_path_traversal(tmp_path: Path) -> None:
    """Assert artifact store rejects symlink target creation and path traversal lookups."""
    store = ArtifactStore(tmp_path / "artifacts")
    valid_art = store.put_bytes(
        b"valid",
        max_bytes=100,
        kind="diff",
        access_policy="public",
    )

    # Attempt path traversal digest: exists returns False, get_path and open_verified raise ValidationError
    assert store.exists("../../etc/passwd") is False

    with pytest.raises(ValidationError) as exc_info:
        store.get_path("../../etc/passwd")
    assert exc_info.value.code == ErrorCode.VALIDATION_ERROR.value

    with pytest.raises(ValidationError) as exc_info_open_trav:
        store.open_verified("../../etc/passwd")
    assert exc_info_open_trav.value.code == ErrorCode.VALIDATION_ERROR.value

    # Symlink attack: replace an artifact file with a symlink to outside
    art_path = store.get_path(valid_art.digest)
    art_path.unlink()
    target_secret = tmp_path / "outside_secret.txt"
    target_secret.write_text("secret_data")
    art_path.symlink_to(target_secret)

    # open_verified, exists, and read_bytes must refuse to follow symlink
    assert store.exists(valid_art.digest) is False

    with pytest.raises(ProtectionError) as exc_info_read:
        store.read_bytes(valid_art.digest)
    assert exc_info_read.value.code == ErrorCode.PROTECTION_ERROR.value

    with (
        pytest.raises(ProtectionError) as exc_info_open,
        store.open_verified(valid_art.digest) as f,
    ):
        f.read()
    assert exc_info_open.value.code == ErrorCode.PROTECTION_ERROR.value


def test_artifact_store_sqlite_registration_and_garbage_collection(
    tmp_path: Path,
) -> None:
    """Verify SQLite metadata registration and retention GC integration."""
    db = Database(tmp_path / "artifacts_gc.db")
    db.migrate()
    conn = db.connection
    store = ArtifactStore(tmp_path / "artifacts")

    # Ingest 1: Sealed artifact (never GC-eligible)
    sealed_art = store.put_bytes(
        b"sealed evidence",
        max_bytes=1000,
        kind="evidence",
        access_policy="sealed",
        conn=conn,
    )
    # Ingest 2: Expired unreferenced artifact (GC-eligible)
    expired_time = datetime.now(UTC) - timedelta(days=7)
    expired_art = store.put_bytes(
        b"expired ephemeral log",
        max_bytes=1000,
        kind="stdout",
        access_policy="public",
        retention_until=expired_time,
        conn=conn,
    )
    # Ingest 3: Active retained artifact
    future_time = datetime.now(UTC) + timedelta(days=7)
    active_art = store.put_bytes(
        b"active retained payload",
        max_bytes=1000,
        kind="payload",
        access_policy="public",
        retention_until=future_time,
        conn=conn,
    )

    # Assert registered in SQLite
    row_count = conn.execute(
        "SELECT COUNT(*) FROM artifacts WHERE available = 1"
    ).fetchone()[0]
    assert row_count == 3

    # Run garbage collection
    now = datetime.now(UTC)
    deleted_digests = store.garbage_collect(conn=conn, now=now, dry_run=False)
    assert expired_art.digest in deleted_digests
    assert sealed_art.digest not in deleted_digests
    assert active_art.digest not in deleted_digests

    # Verify expired artifact is removed from disk and marked available=0
    assert not store.exists(expired_art.digest)
    assert store.exists(sealed_art.digest)
    assert store.exists(active_art.digest)

    expired_row = conn.execute(
        "SELECT available FROM artifacts WHERE digest = ?", (expired_art.digest,)
    ).fetchone()
    assert expired_row["available"] == 0
