"""Unit tests for SQLite database layer and schema migrations.

SDD Section 4.1 & Section 4.4.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest

from verifierci.errors import (
    ErrorCode,
    IdentityConflict,
    InfrastructureError,
    ValidationError,
)
from verifierci.storage.db import (
    Database,
    backup_database,
    connect,
    migrate,
    transaction,
)


def test_connect_pragmas_memory() -> None:
    conn = connect(":memory:")
    try:
        fk = conn.execute("PRAGMA foreign_keys").fetchone()[0]
        sync = conn.execute("PRAGMA synchronous").fetchone()[0]
        busy = conn.execute("PRAGMA busy_timeout").fetchone()[0]
        assert fk == 1
        assert sync == 2  # FULL
        assert busy == 5000
    finally:
        conn.close()


def test_connect_pragmas_disk(tmp_path: Path) -> None:
    db_file = tmp_path / "test.db"
    conn = connect(db_file)
    try:
        journal = conn.execute("PRAGMA journal_mode").fetchone()[0]
        fk = conn.execute("PRAGMA foreign_keys").fetchone()[0]
        sync = conn.execute("PRAGMA synchronous").fetchone()[0]
        busy = conn.execute("PRAGMA busy_timeout").fetchone()[0]
        assert journal.lower() == "wal"
        assert fk == 1
        assert sync == 2
        assert busy == 5000
    finally:
        conn.close()


def test_transaction_commit_and_rollback() -> None:
    conn = connect(":memory:")
    try:
        conn.execute("CREATE TABLE items (id INT PRIMARY KEY, name TEXT)")
        # Successful commit
        with transaction(conn, immediate=True):
            conn.execute("INSERT INTO items VALUES (1, 'apple')")

        row = conn.execute("SELECT name FROM items WHERE id = 1").fetchone()
        assert row is not None and row[0] == "apple"

        # Rollback on exception
        with (
            pytest.raises(ValueError, match="fail transaction"),
            transaction(conn, immediate=True),
        ):
            conn.execute("INSERT INTO items VALUES (2, 'banana')")
            raise ValueError("fail transaction")

        assert conn.execute("SELECT COUNT(*) FROM items").fetchone()[0] == 1
        assert conn.execute("SELECT name FROM items WHERE id = 2").fetchone() is None
    finally:
        conn.close()


def test_transaction_deferred() -> None:
    conn = connect(":memory:")
    try:
        conn.execute("CREATE TABLE items (id INT PRIMARY KEY, name TEXT)")
        with transaction(conn, immediate=False):
            conn.execute("INSERT INTO items VALUES (10, 'cherry')")
        assert conn.execute("SELECT COUNT(*) FROM items").fetchone()[0] == 1
    finally:
        conn.close()


def test_transaction_busy_timeout(tmp_path: Path) -> None:
    db_file = tmp_path / "busy.db"
    conn1 = connect(db_file)
    conn2 = connect(db_file)
    try:
        conn1.execute("CREATE TABLE items (x INT)")
        conn1.execute("BEGIN EXCLUSIVE")

        # conn2 attempting BEGIN IMMEDIATE with very short timeout should fail
        with (
            pytest.raises(InfrastructureError) as exc_info,
            transaction(conn2, immediate=True, timeout=0.05),
        ):
            conn2.execute("INSERT INTO items VALUES (1)")
        assert exc_info.value.code == ErrorCode.DATABASE_ERROR.value
    finally:
        conn1.close()
        conn2.close()


def test_migrations_initial_and_idempotent() -> None:
    conn = connect(":memory:")
    try:
        ver = migrate(conn)
        assert ver == 2

        # Re-running is idempotent
        ver2 = migrate(conn)
        assert ver2 == 2

        # Verify tables exist
        tables = {
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert "tasks" in tables
        assert "contracts" in tables
        assert "patch_cases" in tables
        assert "jobs" in tables
        assert "evaluation_attempts" in tables
        assert "artifacts" in tables
        assert "schema_migrations" in tables
    finally:
        conn.close()


def test_migration_target_version_and_incremental() -> None:
    conn = connect(":memory:")
    try:
        ver1 = migrate(conn, target_version=1)
        assert ver1 == 1

        row = conn.execute(
            "SELECT version, checksum FROM schema_migrations WHERE version = 1"
        ).fetchone()
        assert row is not None
        assert row["version"] == 1

        # Now migrate to latest (version 2)
        ver2 = migrate(conn)
        assert ver2 == 2

        rows = conn.execute(
            "SELECT version FROM schema_migrations ORDER BY version ASC"
        ).fetchall()
        assert [r["version"] for r in rows] == [1, 2]
    finally:
        conn.close()


def test_migrations_checksum_mismatch(tmp_path: Path) -> None:
    # Setup custom migrations directory
    mig_dir = tmp_path / "migrations"
    mig_dir.mkdir()
    (mig_dir / "001_test.sql").write_text("CREATE TABLE t1 (x INT);", encoding="utf-8")

    conn = connect(":memory:")
    try:
        ver = migrate(conn, migrations_dir=mig_dir)
        assert ver == 1

        # Modify migration file
        (mig_dir / "001_test.sql").write_text(
            "CREATE TABLE t1 (x INT, y INT);", encoding="utf-8"
        )

        with pytest.raises(IdentityConflict) as exc_info:
            migrate(conn, migrations_dir=mig_dir)
        assert exc_info.value.code == ErrorCode.IDENTITY_CONFLICT.value
    finally:
        conn.close()


def test_migrations_target_version(tmp_path: Path) -> None:
    mig_dir = tmp_path / "migrations"
    mig_dir.mkdir()
    (mig_dir / "001_first.sql").write_text("CREATE TABLE t1 (x INT);", encoding="utf-8")
    (mig_dir / "002_second.sql").write_text(
        "CREATE TABLE t2 (x INT);", encoding="utf-8"
    )

    conn = connect(":memory:")
    try:
        ver = migrate(conn, target_version=1, migrations_dir=mig_dir)
        assert ver == 1

        tables = {
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert "t1" in tables
        assert "t2" not in tables
    finally:
        conn.close()


def test_database_class_context_manager(tmp_path: Path) -> None:
    db_file = tmp_path / "app.db"
    with Database(db_file) as db:
        assert db.migrate() == 2
        with db.transaction(immediate=True) as conn:
            conn.execute(
                """
                INSERT INTO environments (
                    environment_id, backend, platform, recipe_digest,
                    lock_digests, service_manifests, resource_policy_hash,
                    runtime_fingerprint, mirror_uris
                ) VALUES (
                    'env1', 'fixture', 'linux/arm64', 'recipe1',
                    '[]', '{}', 'policy1',
                    'fp1', '[]'
                )
                """
            )
            count = conn.execute("SELECT COUNT(*) FROM environments").fetchone()[0]
            assert count == 1


def test_immutable_triggers_tasks_contracts_requirements() -> None:
    conn = connect(":memory:")
    try:
        migrate(conn)

        # 1. Insert prerequisites
        conn.execute(
            """
            INSERT INTO artifacts (digest, kind, size_bytes, storage_uri, media_type, access_policy, available, created_at)
            VALUES ('art1', 'evidence', 10, 'file:///art1', 'text/plain', 'sealed', 1, '2026-09-21T00:00:00Z')
            """
        )
        conn.execute(
            """
            INSERT INTO environments (environment_id, backend, platform, recipe_digest, lock_digests, service_manifests, resource_policy_hash, runtime_fingerprint, mirror_uris)
            VALUES ('env1', 'fixture', 'linux/arm64', 'recipe1', '[]', '{}', 'policy1', 'fp1', '[]')
            """
        )
        conn.execute(
            """
            INSERT INTO repository_snapshots (snapshot_digest, repository_id, commit_oid, archive_uri, tree_digest, submodule_digests, lock_digests, licence, created_at)
            VALUES ('art1', 'repo1', 'oid1', 'file:///repo', 'tree1', '[]', '[]', 'MIT', '2026-09-21T00:00:00Z')
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
            VALUES ('tkey1', 'task1', 'v1', 'solve this', 'fixture', 'con1', 'art1', 'env1', 'MIT', 'origin', 'eligible', 'notes', '2026-09-21T00:00:00Z')
            """
        )

        # Trigger check: tasks cannot be updated or deleted
        with pytest.raises(
            sqlite3.DatabaseError, match="immutable entity tasks cannot be updated"
        ):
            conn.execute(
                "UPDATE tasks SET statement = 'changed' WHERE task_key = 'tkey1'"
            )

        with pytest.raises(
            sqlite3.DatabaseError, match="immutable entity tasks cannot be deleted"
        ):
            conn.execute("DELETE FROM tasks WHERE task_key = 'tkey1'")

        # Trigger check: contracts cannot be updated or deleted
        with pytest.raises(
            sqlite3.DatabaseError, match="immutable entity contracts cannot be updated"
        ):
            conn.execute(
                "UPDATE contracts SET allowed_variation = 'any' WHERE contract_hash = 'con1'"
            )

        with pytest.raises(
            sqlite3.DatabaseError, match="immutable entity contracts cannot be deleted"
        ):
            conn.execute("DELETE FROM contracts WHERE contract_hash = 'con1'")

        # Trigger check: sealed artifact cannot be deleted
        with pytest.raises(
            sqlite3.DatabaseError, match="sealed artifacts cannot be deleted"
        ):
            conn.execute("DELETE FROM artifacts WHERE digest = 'art1'")

        # Artifact core metadata cannot be updated
        with pytest.raises(
            sqlite3.DatabaseError,
            match="immutable artifact core metadata cannot be updated",
        ):
            conn.execute("UPDATE artifacts SET size_bytes = 999 WHERE digest = 'art1'")

        # But updating artifact availability IS permitted (operational update)
        conn.execute("UPDATE artifacts SET available = 0 WHERE digest = 'art1'")
        assert (
            conn.execute(
                "SELECT available FROM artifacts WHERE digest = 'art1'"
            ).fetchone()[0]
            == 0
        )

    finally:
        conn.close()


def test_split_reservation_and_guard_development_membership() -> None:
    conn = connect(":memory:")
    try:
        migrate(conn)

        # Base prerequisites
        conn.execute(
            """
            INSERT INTO artifacts (digest, kind, size_bytes, storage_uri, media_type, access_policy, available, created_at)
            VALUES ('art_snap', 'snapshot', 10, 'file:///snap', 'text/plain', 'public', 1, '2026-09-21T00:00:00Z'),
                   ('art_diff', 'diff', 5, 'file:///diff', 'text/x-diff', 'public', 1, '2026-09-21T00:00:00Z')
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
            VALUES ('art_snap', 'repo1', 'oid1', 'file:///repo', 'tree1', '[]', '[]', 'MIT', '2026-09-21T00:00:00Z')
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
            VALUES ('tkey1', 'task1', 'v1', 'statement', 'fixture', 'con1', 'art_snap', 'env1', 'MIT', 'prov', 'eligible', '', '2026-09-21T00:00:00Z')
            """
        )
        conn.execute(
            """
            INSERT INTO patch_cases (case_id, task_key, diff_digest, base_snapshot_digest, source, parent_case_ids, family_id, role, provenance_digest, licence, created_at)
            VALUES ('case_res', 'tkey1', 'art_diff', 'art_snap', 'reference', '[]', 'fam_res', 'challenge', 'prov1', 'MIT', '2026-09-21T00:00:00Z')
            """
        )
        conn.execute(
            """
            INSERT INTO adjudications (adjudication_id, case_id, contract_hash, version, label, review_status, votes, rationale, requirement_hashes, witness_ids, uncertainty, created_at)
            VALUES ('adj1', 'case_res', 'con1', 1, 'valid', 'provisional', '[]', 'ok', '[]', '[]', 'none', '2026-09-21T00:00:00Z')
            """
        )
        conn.execute(
            """
            INSERT INTO patch_panels (panel_key, panel_id, version, split, membership_digest, sampling_policy)
            VALUES ('panel_assessment', 'p_assess', 'v1', 'assessment', 'm1', 's1'),
                   ('panel_dev', 'p_dev', 'v1', 'development', 'm2', 's2')
            """
        )

        # Reserve family for assessment
        conn.execute(
            """
            INSERT INTO split_reservations (reservation_key, assessment_panel_key, reserved_at)
            VALUES ('family:fam_res', 'panel_assessment', '2026-09-21T00:00:00Z')
            """
        )

        # split_reservations cannot be updated or deleted
        with pytest.raises(
            sqlite3.DatabaseError, match="assessment reservation is permanent"
        ):
            conn.execute(
                "UPDATE split_reservations SET reserved_at = '2026-09-22T00:00:00Z'"
            )

        with pytest.raises(
            sqlite3.DatabaseError, match="assessment reservation is permanent"
        ):
            conn.execute("DELETE FROM split_reservations")

        # guard_development_membership trigger should block inserting reserved case into development panel
        with pytest.raises(
            sqlite3.DatabaseError, match="assessment case or family is reserved"
        ):
            conn.execute(
                """
                INSERT INTO panel_memberships (panel_key, case_id, adjudication_id, ordinal, expected_control_outcomes)
                VALUES ('panel_dev', 'case_res', 'adj1', 0, '{}')
                """
            )

        # But inserting into assessment panel is permitted
        conn.execute(
            """
            INSERT INTO panel_memberships (panel_key, case_id, adjudication_id, ordinal, expected_control_outcomes)
            VALUES ('panel_assessment', 'case_res', 'adj1', 0, '{}')
            """
        )
        assert conn.execute("SELECT COUNT(*) FROM panel_memberships").fetchone()[0] == 1

    finally:
        conn.close()


def test_migrations_missing_dir(tmp_path: Path) -> None:
    conn = connect(":memory:")
    try:
        assert migrate(conn, migrations_dir=tmp_path / "not_there") == 0
    finally:
        conn.close()


def test_migrations_syntax_error_rolls_back(tmp_path: Path) -> None:
    mig_dir = tmp_path / "migrations"
    mig_dir.mkdir()
    (mig_dir / "001_bad.sql").write_text(
        "CREATE TABLE t1 (x INT); INVALID SQL SYNTAX;", encoding="utf-8"
    )

    conn = connect(":memory:")
    try:
        with pytest.raises(sqlite3.OperationalError):
            migrate(conn, migrations_dir=mig_dir)
        # Verify t1 was not created due to rollback
        assert (
            conn.execute("SELECT name FROM sqlite_master WHERE name='t1'").fetchone()
            is None
        )
    finally:
        conn.close()


def test_migrations_foreign_key_violation(tmp_path: Path) -> None:
    mig_dir = tmp_path / "migrations"
    mig_dir.mkdir()
    (mig_dir / "001_fk.sql").write_text(
        """
        CREATE TABLE parent (id INT PRIMARY KEY);
        CREATE TABLE child (id INT PRIMARY KEY, parent_id INT REFERENCES parent(id));
        INSERT INTO child VALUES (1, 999);
        """,
        encoding="utf-8",
    )

    conn = connect(":memory:")
    conn.execute("PRAGMA foreign_keys = OFF;")
    try:
        with pytest.raises(ValidationError) as exc_info:
            migrate(conn, migrations_dir=mig_dir)
        assert exc_info.value.code == ErrorCode.DATABASE_ERROR.value
    finally:
        conn.close()


def test_database_disk_methods(tmp_path: Path) -> None:
    db_file = tmp_path / "disk_test.db"
    db = Database(db_file)
    try:
        c1 = db.connection
        c2 = db.connect()
        assert c1 is not c2
        c2.close()
    finally:
        db.close()


def test_database_memory_connect() -> None:
    db = Database(":memory:")
    try:
        c1 = db.connection
        c2 = db.connect()
        assert c1 is c2
    finally:
        db.close()


def test_environments_docker_image_digest_check() -> None:
    conn = connect(":memory:")
    try:
        migrate(conn)

        # backend == 'docker' without image_digest should fail CHECK constraint
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """
                INSERT INTO environments (
                    environment_id, backend, platform, recipe_digest,
                    lock_digests, service_manifests, resource_policy_hash,
                    runtime_fingerprint, mirror_uris, image_digest
                ) VALUES (
                    'env_docker_null', 'docker', 'linux/amd64', 'rec1',
                    '[]', '{}', 'p1', 'fp1', '[]', NULL
                )
                """
            )

        # backend == 'docker' without '@sha256:' in image_digest should fail
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """
                INSERT INTO environments (
                    environment_id, backend, platform, recipe_digest,
                    lock_digests, service_manifests, resource_policy_hash,
                    runtime_fingerprint, mirror_uris, image_digest
                ) VALUES (
                    'env_docker_bad', 'docker', 'linux/amd64', 'rec1',
                    '[]', '{}', 'p1', 'fp1', '[]', 'ubuntu:latest'
                )
                """
            )

        # backend == 'docker' with valid image_digest should succeed
        conn.execute(
            """
            INSERT INTO environments (
                environment_id, backend, platform, recipe_digest,
                lock_digests, service_manifests, resource_policy_hash,
                runtime_fingerprint, mirror_uris, image_digest
            ) VALUES (
                'env_docker_ok', 'docker', 'linux/amd64', 'rec1',
                '[]', '{}', 'p1', 'fp1', '[]', 'ubuntu@sha256:abcdef123456'
            )
            """
        )

        # backend == 'fixture' with image_digest NULL should succeed
        conn.execute(
            """
            INSERT INTO environments (
                environment_id, backend, platform, recipe_digest,
                lock_digests, service_manifests, resource_policy_hash,
                runtime_fingerprint, mirror_uris, image_digest
            ) VALUES (
                'env_fixture_ok', 'fixture', 'linux/amd64', 'rec1',
                '[]', '{}', 'p1', 'fp1', '[]', NULL
            )
            """
        )
        assert conn.execute("SELECT COUNT(*) FROM environments").fetchone()[0] == 2
    finally:
        conn.close()


def test_artifacts_immutable_columns() -> None:
    conn = connect(":memory:")
    try:
        migrate(conn)
        conn.execute(
            """
            INSERT INTO artifacts (
                digest, kind, size_bytes, storage_uri, media_type,
                access_policy, available, retention_until, created_at
            ) VALUES (
                'art_meta', 'evidence', 10, 'file:///art', 'text/plain',
                'restricted', 1, '2026-10-01T00:00:00Z', '2026-09-21T00:00:00Z'
            )
            """
        )

        # storage_uri cannot be updated
        with pytest.raises(
            sqlite3.DatabaseError,
            match="immutable artifact core metadata cannot be updated",
        ):
            conn.execute(
                "UPDATE artifacts SET storage_uri = 'file:///new' WHERE digest = 'art_meta'"
            )

        # access_policy cannot be updated
        with pytest.raises(
            sqlite3.DatabaseError,
            match="immutable artifact core metadata cannot be updated",
        ):
            conn.execute(
                "UPDATE artifacts SET access_policy = 'public' WHERE digest = 'art_meta'"
            )

        # retention_until cannot be updated
        with pytest.raises(
            sqlite3.DatabaseError,
            match="immutable artifact core metadata cannot be updated",
        ):
            conn.execute(
                "UPDATE artifacts SET retention_until = '2027-01-01T00:00:00Z' WHERE digest = 'art_meta'"
            )

        # available CAN be updated
        conn.execute("UPDATE artifacts SET available = 0 WHERE digest = 'art_meta'")
        assert (
            conn.execute(
                "SELECT available FROM artifacts WHERE digest = 'art_meta'"
            ).fetchone()[0]
            == 0
        )
    finally:
        conn.close()


def test_transaction_busy_timeout_setting_and_restoration(tmp_path: Path) -> None:
    db_file = tmp_path / "timeout.db"
    conn = connect(db_file)
    try:
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 5000

        with transaction(conn, timeout=0.2):
            # Inside transaction, busy_timeout is set to timeout in ms (200)
            assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 200

        # After clean exit, restored to 5000
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 5000

        # After exception exit, restored to 5000
        with pytest.raises(RuntimeError), transaction(conn, timeout=0.1):
            assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 100
            raise RuntimeError("boom")

        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 5000
    finally:
        conn.close()


def test_transaction_busy_retry_success(tmp_path: Path) -> None:
    import threading
    import time

    db_file = tmp_path / "retry_busy.db"
    conn1 = connect(db_file)
    conn2 = connect(db_file)
    try:
        conn1.execute("CREATE TABLE t (x INT)")
        conn1.execute("BEGIN EXCLUSIVE")

        def release_lock() -> None:
            time.sleep(0.05)
            conn1.execute("COMMIT")

        thread = threading.Thread(target=release_lock)
        thread.start()

        # conn2 should retry during the 0.05s lock and succeed once conn1 commits
        with transaction(conn2, immediate=True, timeout=2.0):
            conn2.execute("INSERT INTO t VALUES (42)")

        thread.join()
        assert conn2.execute("SELECT x FROM t").fetchone()[0] == 42
    finally:
        conn1.close()
        conn2.close()


def test_transaction_retry_on_busy_loop() -> None:
    real_conn = connect(":memory:")
    try:

        class MockConn:
            def __init__(self, real: sqlite3.Connection) -> None:
                self.real = real
                self.calls = 0

            @property
            def in_transaction(self) -> bool:
                return self.real.in_transaction

            def execute(self, sql: str, *args: Any, **kwargs: Any) -> Any:
                if sql.startswith("BEGIN"):
                    self.calls += 1
                    if self.calls == 1:
                        raise sqlite3.OperationalError("database is locked")
                return self.real.execute(sql, *args, **kwargs)  # type: ignore[arg-type]

        mock = MockConn(real_conn)
        with transaction(mock, immediate=True, timeout=1.0):  # type: ignore[arg-type]
            pass
        assert mock.calls == 2
    finally:
        real_conn.close()


def test_migrations_skips_non_integer_filenames(tmp_path: Path) -> None:
    mig_dir = tmp_path / "migrations"
    mig_dir.mkdir()
    (mig_dir / "README.sql").write_text("-- Just documentation", encoding="utf-8")
    (mig_dir / "001_initial.sql").write_text(
        "CREATE TABLE t1 (x INT);", encoding="utf-8"
    )

    conn = connect(":memory:")
    try:
        ver = migrate(conn, migrations_dir=mig_dir)
        assert ver == 1
    finally:
        conn.close()


def test_connect_creates_missing_parent_directories(tmp_path: Path) -> None:
    nested_dir = tmp_path / "deeply" / "nested" / "dir"
    db_file = nested_dir / "target.db"
    assert not nested_dir.exists()

    conn = connect(db_file)
    try:
        assert nested_dir.exists()
        conn.execute("CREATE TABLE t (id INT);")
        conn.execute("INSERT INTO t VALUES (1);")
        row = conn.execute("SELECT id FROM t;").fetchone()
        assert row is not None and row[0] == 1
    finally:
        conn.close()
    assert db_file.is_file()


def test_migrate_creates_backup_pre_migration(tmp_path: Path) -> None:
    mig_dir = tmp_path / "migrations"
    mig_dir.mkdir()
    (mig_dir / "001_initial.sql").write_text(
        "CREATE TABLE t1 (x INT, name TEXT); INSERT INTO t1 VALUES (1, 'initial');",
        encoding="utf-8",
    )
    (mig_dir / "002_next.sql").write_text(
        "CREATE TABLE t2 (y INT); INSERT INTO t2 VALUES (2);",
        encoding="utf-8",
    )

    db_file = tmp_path / "data.db"
    bak_file = tmp_path / "data.db.bak"

    conn = connect(db_file)
    try:
        # 1. Apply only migration 1
        ver1 = migrate(conn, target_version=1, migrations_dir=mig_dir)
        assert ver1 == 1
        assert bak_file.is_file()

        # In conn, add custom pre-migration-2 data to t1
        conn.execute("INSERT INTO t1 VALUES (42, 'pre-mig2');")

        # Apply migration 2
        ver2 = migrate(conn, target_version=2, migrations_dir=mig_dir)
        assert ver2 == 2

        # Verify bak_file contains state BEFORE migration 2:
        # - t1 has (1, 'initial') and (42, 'pre-mig2')
        # - t2 does NOT exist
        # - schema_migrations only has version 1
        bak_conn = connect(bak_file)
        try:
            bak_tables = {
                r[0]
                for r in bak_conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table';"
                ).fetchall()
            }
            assert "t1" in bak_tables
            assert "t2" not in bak_tables
            rows = bak_conn.execute("SELECT x, name FROM t1 ORDER BY x;").fetchall()
            assert [(r[0], r[1]) for r in rows] == [(1, "initial"), (42, "pre-mig2")]
            mig_versions = [
                r[0]
                for r in bak_conn.execute(
                    "SELECT version FROM schema_migrations ORDER BY version;"
                ).fetchall()
            ]
            assert mig_versions == [1]
        finally:
            bak_conn.close()

        # Verify active conn has both t1 and t2
        active_tables = {
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table';"
            ).fetchall()
        }
        assert "t1" in active_tables
        assert "t2" in active_tables

        # Calling migrate again when no pending migrations exist should not alter backup
        bak_mtime = bak_file.stat().st_mtime_ns
        ver_repeat = migrate(conn, migrations_dir=mig_dir)
        assert ver_repeat == 2
        assert bak_file.stat().st_mtime_ns == bak_mtime
    finally:
        conn.close()


def test_migrate_backup_disabled(tmp_path: Path) -> None:
    mig_dir = tmp_path / "migrations"
    mig_dir.mkdir()
    (mig_dir / "001_initial.sql").write_text(
        "CREATE TABLE t1 (x INT);",
        encoding="utf-8",
    )
    db_file = tmp_path / "nobackup.db"
    bak_file = tmp_path / "nobackup.db.bak"

    conn = connect(db_file)
    try:
        ver = migrate(conn, migrations_dir=mig_dir, backup=False)
        assert ver == 1
        assert not bak_file.exists()
    finally:
        conn.close()


def test_migrate_custom_backup_path(tmp_path: Path) -> None:
    mig_dir = tmp_path / "migrations"
    mig_dir.mkdir()
    (mig_dir / "001_initial.sql").write_text(
        "CREATE TABLE t1 (x INT);",
        encoding="utf-8",
    )
    db_file = tmp_path / "custom.db"
    custom_bak = tmp_path / "backups" / "snapshot.bak"

    conn = connect(db_file)
    try:
        ver = migrate(conn, migrations_dir=mig_dir, backup_path=custom_bak)
        assert ver == 1
        assert custom_bak.is_file()
    finally:
        conn.close()


def test_backup_database_rejects_identical_target(tmp_path: Path) -> None:
    db_file = tmp_path / "same.db"
    conn = connect(db_file)
    try:
        conn.execute("CREATE TABLE t (x INT);")
        with pytest.raises(ValidationError) as exc_info:
            backup_database(conn, db_file)
        assert exc_info.value.code == ErrorCode.VALIDATION_ERROR.value
    finally:
        conn.close()


def test_database_class_migrate_backup(tmp_path: Path) -> None:
    db_file = tmp_path / "db_class.db"
    bak_file = tmp_path / "db_class.db.bak"

    with Database(db_file) as db:
        assert db.migrate() == 2
        assert bak_file.is_file()


def test_immutable_triggers_patch_panels() -> None:
    conn = connect(":memory:")
    try:
        migrate(conn)
        conn.execute(
            """
            INSERT INTO patch_panels (
                panel_key, panel_id, version, split, membership_digest, sampling_policy, sealed_at
            ) VALUES (
                'p_unsealed', 'panel1', 'v1', 'development', 'mdigest1', 'policy1', NULL
            )
            """
        )

        # 1. Modifying core metadata on unsealed panel is blocked
        with pytest.raises(
            sqlite3.DatabaseError,
            match="immutable entity patch_panels cannot be updated",
        ):
            conn.execute(
                "UPDATE patch_panels SET split = 'assessment' WHERE panel_key = 'p_unsealed'"
            )

        with pytest.raises(
            sqlite3.DatabaseError,
            match="immutable entity patch_panels cannot be updated",
        ):
            conn.execute(
                "UPDATE patch_panels SET membership_digest = 'm2' WHERE panel_key = 'p_unsealed'"
            )

        # 2. Deleting any panel is blocked
        with pytest.raises(
            sqlite3.DatabaseError,
            match="immutable entity patch_panels cannot be deleted",
        ):
            conn.execute("DELETE FROM patch_panels WHERE panel_key = 'p_unsealed'")

        # 3. Sealing an unsealed panel is permitted
        conn.execute(
            "UPDATE patch_panels SET sealed_at = '2026-09-22T00:00:00Z' WHERE panel_key = 'p_unsealed'"
        )
        assert (
            conn.execute(
                "SELECT sealed_at FROM patch_panels WHERE panel_key = 'p_unsealed'"
            ).fetchone()[0]
            == "2026-09-22T00:00:00Z"
        )

        # 4. Once sealed, updating retired_at is permitted
        conn.execute(
            "UPDATE patch_panels SET retired_at = '2026-10-01T00:00:00Z' WHERE panel_key = 'p_unsealed'"
        )
        assert (
            conn.execute(
                "SELECT retired_at FROM patch_panels WHERE panel_key = 'p_unsealed'"
            ).fetchone()[0]
            == "2026-10-01T00:00:00Z"
        )

        # But updating sealed_at or core metadata on sealed panel is blocked
        with pytest.raises(
            sqlite3.DatabaseError,
            match="immutable entity patch_panels cannot be updated",
        ):
            conn.execute(
                "UPDATE patch_panels SET sealed_at = NULL WHERE panel_key = 'p_unsealed'"
            )

        with pytest.raises(
            sqlite3.DatabaseError,
            match="immutable entity patch_panels cannot be updated",
        ):
            conn.execute(
                "UPDATE patch_panels SET split = 'assessment' WHERE panel_key = 'p_unsealed'"
            )

        # 5. INSERT OR REPLACE on existing panel triggers DELETE and is blocked
        with pytest.raises(
            sqlite3.DatabaseError,
            match="immutable entity patch_panels cannot be deleted",
        ):
            conn.execute(
                """
                INSERT OR REPLACE INTO patch_panels (
                    panel_key, panel_id, version, split, membership_digest, sampling_policy, sealed_at
                ) VALUES (
                    'p_unsealed', 'panel1_replaced', 'v2', 'assessment', 'mdigest2', 'policy2', NULL
                )
                """
            )
    finally:
        conn.close()


def test_recursive_triggers_reject_insert_or_replace_on_protected_tables() -> None:
    """Verify recursive triggers ensure REPLACE fires DELETE triggers on protected tables."""
    conn = connect(":memory:")
    try:
        migrate(conn)
        conn.execute(
            """
            INSERT INTO patch_panels (
                panel_key, panel_id, version, split, membership_digest, sampling_policy, sealed_at
            ) VALUES (
                'p_unsealed', 'panel1', 'v1', 'development', 'mdigest1', 'policy1', NULL
            )
            """
        )
        conn.execute(
            """
            INSERT INTO artifacts (digest, kind, size_bytes, storage_uri, media_type, access_policy, available, created_at)
            VALUES ('art1', 'diff', 10, 'file:///diff', 'text/x-diff', 'sealed', 1, '2026-09-21T00:00:00Z')
            """
        )
        conn.execute(
            """
            INSERT INTO worker_requests (request_id, operation, request_digest, response_json, completed_at)
            VALUES ('wr1', 'heartbeat', 'd1', '{}', '2026-09-21T00:00:00Z')
            """
        )
        conn.execute(
            """
            INSERT INTO split_reservations (reservation_key, assessment_panel_key, reserved_at)
            VALUES ('res1', 'p_unsealed', '2026-09-21T00:00:00Z')
            """
        )

        # 1. REPLACE INTO patch_panels is blocked by patch_panels_no_delete
        with pytest.raises(
            sqlite3.DatabaseError,
            match="immutable entity patch_panels cannot be deleted",
        ):
            conn.execute(
                """
                INSERT OR REPLACE INTO patch_panels (
                    panel_key, panel_id, version, split, membership_digest, sampling_policy, sealed_at
                ) VALUES (
                    'p_unsealed', 'panel1_hacked', 'v2', 'assessment', 'mdigest2', 'policy2', NULL
                )
                """
            )

        # 2. REPLACE INTO artifacts is blocked by artifacts_no_delete
        with pytest.raises(
            sqlite3.DatabaseError,
            match="sealed artifacts cannot be deleted",
        ):
            conn.execute(
                """
                REPLACE INTO artifacts (digest, kind, size_bytes, storage_uri, media_type, access_policy, available, created_at)
                VALUES ('art1', 'diff', 20, 'file:///diff2', 'text/x-diff', 'public', 1, '2026-09-21T00:00:00Z')
                """
            )

        # 3. REPLACE INTO worker_requests is blocked by worker_requests_no_delete
        with pytest.raises(
            sqlite3.DatabaseError,
            match="immutable entity worker_requests cannot be deleted",
        ):
            conn.execute(
                """
                REPLACE INTO worker_requests (request_id, operation, request_digest, response_json, completed_at)
                VALUES ('wr1', 'cancelled', 'd2', '{}', '2026-09-21T00:00:00Z')
                """
            )

        # 4. REPLACE INTO split_reservations is blocked by reserve_no_delete
        with pytest.raises(
            sqlite3.DatabaseError,
            match="assessment reservation is permanent",
        ):
            conn.execute(
                """
                REPLACE INTO split_reservations (reservation_key, assessment_panel_key, reserved_at)
                VALUES ('res1', 'p_unsealed', '2026-09-21T00:00:00Z')
                """
            )

        # 5. Verify transaction() also enforces recursive triggers even on a raw connection
        raw_conn = sqlite3.connect(":memory:", isolation_level=None)
        try:
            # Without connect(), raw_conn has recursive_triggers = OFF by default
            migrate(raw_conn)
            raw_conn.execute(
                """
                INSERT INTO artifacts (digest, kind, size_bytes, storage_uri, media_type, access_policy, available, created_at)
                VALUES ('art_raw', 'diff', 10, 'file:///raw', 'text/x-diff', 'sealed', 1, '2026-09-21T00:00:00Z')
                """
            )
            with (
                transaction(raw_conn, immediate=True),
                pytest.raises(
                    sqlite3.DatabaseError,
                    match="sealed artifacts cannot be deleted",
                ),
            ):
                raw_conn.execute(
                    """
                    REPLACE INTO artifacts (digest, kind, size_bytes, storage_uri, media_type, access_policy, available, created_at)
                    VALUES ('art_raw', 'diff', 20, 'file:///raw2', 'text/x-diff', 'public', 1, '2026-09-21T00:00:00Z')
                    """
                )
        finally:
            raw_conn.close()
    finally:
        conn.close()


def test_immutable_triggers_adjudications_and_witnesses() -> None:
    conn = connect(":memory:")
    try:
        migrate(conn)
        conn.execute(
            """
            INSERT INTO artifacts (digest, kind, size_bytes, storage_uri, media_type, access_policy, available, created_at)
            VALUES ('art_diff', 'diff', 10, 'file:///diff', 'text/x-diff', 'public', 1, '2026-09-21T00:00:00Z'),
                   ('art_snap', 'snapshot', 10, 'file:///snap', 'text/plain', 'public', 1, '2026-09-21T00:00:00Z'),
                   ('art_in', 'input', 5, 'file:///in', 'text/plain', 'public', 1, '2026-09-21T00:00:00Z'),
                   ('art_exp', 'expected', 5, 'file:///exp', 'text/plain', 'public', 1, '2026-09-21T00:00:00Z'),
                   ('art_obs', 'observed', 5, 'file:///obs', 'text/plain', 'public', 1, '2026-09-21T00:00:00Z')
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
            VALUES ('art_snap', 'repo1', 'oid1', 'file:///repo', 'tree1', '[]', '[]', 'MIT', '2026-09-21T00:00:00Z')
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
            VALUES ('tkey1', 'task1', 'v1', 'stmt', 'fixture', 'con1', 'art_snap', 'env1', 'MIT', 'prov', 'eligible', '', '2026-09-21T00:00:00Z')
            """
        )
        conn.execute(
            """
            INSERT INTO patch_cases (case_id, task_key, diff_digest, base_snapshot_digest, source, parent_case_ids, family_id, role, provenance_digest, licence, created_at)
            VALUES ('case1', 'tkey1', 'art_diff', 'art_snap', 'reference', '[]', 'fam1', 'challenge', 'prov1', 'MIT', '2026-09-21T00:00:00Z')
            """
        )
        conn.execute(
            """
            INSERT INTO adjudications (adjudication_id, case_id, contract_hash, version, label, review_status, votes, rationale, requirement_hashes, witness_ids, uncertainty, created_at)
            VALUES ('adj1', 'case1', 'con1', 1, 'valid', 'provisional', '[]', 'ok', '[]', '[]', 'none', '2026-09-21T00:00:00Z')
            """
        )
        conn.execute(
            """
            INSERT INTO witnesses (witness_id, case_id, contract_hash, requirement_hashes, input_digest, expected_digest, observed_digest, reproducer_command, environment_id, reviewed_by, reproduced_at)
            VALUES ('wit1', 'case1', 'con1', '[]', 'art_in', 'art_exp', 'art_obs', '[]', 'env1', '[]', '2026-09-21T00:00:00Z')
            """
        )

        # Adjudications cannot be updated or deleted
        with pytest.raises(
            sqlite3.DatabaseError,
            match="immutable entity adjudications cannot be updated",
        ):
            conn.execute(
                "UPDATE adjudications SET label = 'invalid' WHERE adjudication_id = 'adj1'"
            )

        with pytest.raises(
            sqlite3.DatabaseError,
            match="immutable entity adjudications cannot be deleted",
        ):
            conn.execute("DELETE FROM adjudications WHERE adjudication_id = 'adj1'")

        # Witnesses cannot be updated or deleted
        with pytest.raises(
            sqlite3.DatabaseError,
            match="immutable entity witnesses cannot be updated",
        ):
            conn.execute(
                "UPDATE witnesses SET reproducer_command = '[\"echo\"]' WHERE witness_id = 'wit1'"
            )

        with pytest.raises(
            sqlite3.DatabaseError,
            match="immutable entity witnesses cannot be deleted",
        ):
            conn.execute("DELETE FROM witnesses WHERE witness_id = 'wit1'")
    finally:
        conn.close()


def test_immutable_triggers_authoritative_evaluation_attempts() -> None:
    conn = connect(":memory:")
    try:
        migrate(conn)
        conn.execute(
            """
            INSERT INTO artifacts (digest, kind, size_bytes, storage_uri, media_type, access_policy, available, created_at)
            VALUES ('art_snap', 'snapshot', 10, 'file:///snap', 'text/plain', 'public', 1, '2026-09-21T00:00:00Z'),
                   ('art_diff', 'diff', 10, 'file:///diff', 'text/x-diff', 'public', 1, '2026-09-21T00:00:00Z'),
                   ('art_pay', 'payload', 10, 'file:///pay', 'text/plain', 'public', 1, '2026-09-21T00:00:00Z')
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
            VALUES ('art_snap', 'repo1', 'oid1', 'file:///repo', 'tree1', '[]', '[]', 'MIT', '2026-09-21T00:00:00Z')
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
            VALUES ('tkey1', 'task1', 'v1', 'stmt', 'fixture', 'con1', 'art_snap', 'env1', 'MIT', 'prov', 'eligible', '', '2026-09-21T00:00:00Z')
            """
        )
        conn.execute(
            """
            INSERT INTO patch_cases (case_id, task_key, diff_digest, base_snapshot_digest, source, parent_case_ids, family_id, role, provenance_digest, licence, created_at)
            VALUES ('case1', 'tkey1', 'art_diff', 'art_snap', 'reference', '[]', 'fam1', 'challenge', 'prov1', 'MIT', '2026-09-21T00:00:00Z')
            """
        )
        conn.execute(
            """
            INSERT INTO verifier_manifests (manifest_hash, mode, command, build_command, expected_collection, parser_id, report_path, payload_digest, allowed_edit_paths, required_pass_ids, permitted_skips, timeout_seconds)
            VALUES ('man1', 'compatibility', '[]', '[]', '[]', 'p1', 'out.json', 'art_pay', '[]', '[]', '[]', 60)
            """
        )
        conn.execute(
            """
            INSERT INTO verifier_versions (verifier_key, verifier_id, version, manifest_hash, payload_digest, compatible_contract_hashes, created_at)
            VALUES ('vkey1', 'v1', '1.0', 'man1', 'art_pay', '[]', '2026-09-21T00:00:00Z')
            """
        )
        conn.execute(
            """
            INSERT INTO patch_panels (panel_key, panel_id, version, split, membership_digest, sampling_policy)
            VALUES ('pkey1', 'p1', '1.0', 'assessment', 'm1', 's1')
            """
        )
        conn.execute(
            """
            INSERT INTO audit_manifests (manifest_hash, run_id, benchmark_version, task_pins, panel_key, adjudication_version, evaluation_harness_version, config_hash, policy_hash, timestamp, host_fingerprint, max_repetitions, max_attempts_per_job, timeout_seconds, resource_policy, expansion_digest)
            VALUES ('aman1', 'run1', 'bench1', '[]', 'pkey1', 'adjv1', 'harn1', 'conf1', 'pol1', '2026-09-21T00:00:00Z', 'host1', 1, 1, 60, 'res1', 'exp1')
            """
        )
        conn.execute(
            """
            INSERT INTO audit_runs (run_id, manifest_hash, state, cancel_requested, created_at)
            VALUES ('run1', 'aman1', 'RUNNING', 0, '2026-09-21T00:00:00Z')
            """
        )
        conn.execute(
            """
            INSERT INTO jobs (job_id, run_id, task_key, case_id, verifier_key, repetition, state, fence)
            VALUES ('job1', 'run1', 'tkey1', 'case1', 'vkey1', 0, 'RUNNING', 1)
            """
        )

        # Insert active attempt
        conn.execute(
            """
            INSERT INTO evaluation_attempts (
                attempt_id, job_id, fence, outcome, evaluation_validity, disposition,
                started_at, test_collection, resources, artifact_digests, capture_truncated
            ) VALUES (
                'att1', 'job1', 1, NULL, 'pending', 'active',
                '2026-09-21T00:00:00Z', '[]', '{}', '[]', 0
            )
            """
        )

        # Active attempt can be updated
        conn.execute(
            "UPDATE evaluation_attempts SET tests_passed = 1 WHERE attempt_id = 'att1'"
        )
        assert (
            conn.execute(
                "SELECT tests_passed FROM evaluation_attempts WHERE attempt_id = 'att1'"
            ).fetchone()[0]
            == 1
        )

        # Finalise to authoritative
        conn.execute(
            """
            UPDATE evaluation_attempts SET
                outcome = 'accept',
                evaluation_validity = 'valid',
                disposition = 'authoritative',
                finished_at = '2026-09-21T00:01:00Z',
                exit_code = 0
            WHERE attempt_id = 'att1'
            """
        )

        # Authoritative attempt CANNOT be updated
        with pytest.raises(
            sqlite3.DatabaseError,
            match="authoritative evaluation attempt cannot be updated",
        ):
            conn.execute(
                "UPDATE evaluation_attempts SET exit_code = 1 WHERE attempt_id = 'att1'"
            )

        # Authoritative attempt CANNOT be deleted
        with pytest.raises(
            sqlite3.DatabaseError,
            match="authoritative evaluation attempt cannot be deleted",
        ):
            conn.execute("DELETE FROM evaluation_attempts WHERE attempt_id = 'att1'")
    finally:
        conn.close()


def test_immutable_triggers_auxiliary_tables() -> None:
    conn = connect(":memory:")
    try:
        migrate(conn)

        # 1. analysis_plans
        conn.execute(
            """
            INSERT INTO analysis_plans (
                plan_hash, registered_at, cohort_digest, verifier_candidates, primary_outcomes,
                min_iar_improvement, vrr_noninferiority_margin, alpha, bootstrap_draws, seed,
                budgets, exclusions, secondary_hypotheses, stopping_rule
            ) VALUES (
                'plan1', '2026-09-21T00:00:00Z', 'cohort1', '[]', '[]',
                0.05, 0.02, 0.05, 1000, 42,
                '{}', '[]', '[]', 'standard'
            )
            """
        )
        with pytest.raises(
            sqlite3.DatabaseError,
            match="immutable entity analysis_plans cannot be updated",
        ):
            conn.execute(
                "UPDATE analysis_plans SET seed = 99 WHERE plan_hash = 'plan1'"
            )
        with pytest.raises(
            sqlite3.DatabaseError,
            match="immutable entity analysis_plans cannot be deleted",
        ):
            conn.execute("DELETE FROM analysis_plans WHERE plan_hash = 'plan1'")

        # 2. benchmark_versions
        conn.execute(
            """
            INSERT INTO benchmark_versions (benchmark_key, task_keys, panel_keys, release_digest, created_at)
            VALUES ('bench1', '[]', '[]', 'rel1', '2026-09-21T00:00:00Z')
            """
        )
        with pytest.raises(
            sqlite3.DatabaseError,
            match="immutable entity benchmark_versions cannot be updated",
        ):
            conn.execute(
                "UPDATE benchmark_versions SET release_digest = 'rel2' WHERE benchmark_key = 'bench1'"
            )
        with pytest.raises(
            sqlite3.DatabaseError,
            match="immutable entity benchmark_versions cannot be deleted",
        ):
            conn.execute(
                "DELETE FROM benchmark_versions WHERE benchmark_key = 'bench1'"
            )

        # 3. worker_requests
        conn.execute(
            """
            INSERT INTO worker_requests (request_id, operation, request_digest, response_json, completed_at)
            VALUES ('req1', 'claim', 'digest1', '{}', '2026-09-21T00:00:00Z')
            """
        )
        with pytest.raises(
            sqlite3.DatabaseError,
            match="immutable entity worker_requests cannot be updated",
        ):
            conn.execute(
                "UPDATE worker_requests SET operation = 'heartbeat' WHERE request_id = 'req1'"
            )
        with pytest.raises(
            sqlite3.DatabaseError,
            match="immutable entity worker_requests cannot be deleted",
        ):
            conn.execute("DELETE FROM worker_requests WHERE request_id = 'req1'")
    finally:
        conn.close()
