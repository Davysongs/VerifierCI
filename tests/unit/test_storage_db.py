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
        assert ver == 1

        # Re-running is idempotent
        ver2 = migrate(conn)
        assert ver2 == 1

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
        assert db.migrate() == 1
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
