"""Unit tests for Python execution worker.

SDD Section 7.1 and 7.5.
Tests end-to-end execution worker:
- Fenced claim and transition to RUNNING
- Subprocess execution in isolated workspace
- Output collection and artifact store integration
- Structured test report parsing and outcome classification
- Authoritative attempt commit through lease fence
- Workspace cleanup in finally
- Queue draining via run_until_terminal
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from verifierci.errors import ErrorCode
from verifierci.execution.worker import Worker
from verifierci.models.verifier import VerifierManifest
from verifierci.storage.artifacts import ArtifactStore
from verifierci.storage.db import Database


@pytest.fixture
def setup_env(tmp_path: Path) -> tuple[Database, Path, Path]:
    root = tmp_path
    snap_dir = root / "snapshot"
    snap_dir.mkdir()
    (snap_dir / "app.py").write_text("def run(): return 42\n")

    db = Database(":memory:")
    db.migrate()
    conn = db.connection

    # Seed required relational hierarchy
    conn.execute(
        """
        INSERT INTO artifacts (digest, kind, size_bytes, storage_uri, media_type, access_policy, available, created_at)
        VALUES ('snap1' || x'00', 'snapshot', 10, 'file:///s', 'text/plain', 'public', 1, '2026-09-21T00:00:00Z'),
               ('diff1' || x'00', 'diff', 10, 'file:///d', 'text/x-diff', 'public', 1, '2026-09-21T00:00:00Z'),
               ('pay1' || x'00', 'payload', 10, 'file:///p', 'application/zip', 'public', 1, '2026-09-21T00:00:00Z')
        """
    )
    # We update digests to 64 chars
    d_snap = "a" * 64
    d_diff = "b" * 64
    d_pay = "c" * 64
    d_conf = "d" * 64
    d_pol = "e" * 64
    d_res = "f" * 64
    d_man = "1" * 64
    d_con = "2" * 64
    d_vman = "3" * 64

    conn.execute(
        """
        INSERT INTO artifacts (digest, kind, size_bytes, storage_uri, media_type, access_policy, available, created_at)
        VALUES (?, 'snapshot', 10, 'file:///s', 'text/plain', 'public', 1, '2026-09-21T00:00:00Z'),
               (?, 'diff', 10, 'file:///d', 'text/x-diff', 'public', 1, '2026-09-21T00:00:00Z'),
               (?, 'payload', 10, 'file:///p', 'application/zip', 'public', 1, '2026-09-21T00:00:00Z')
        """,
        (d_snap, d_diff, d_pay),
    )
    conn.execute(
        """
        INSERT INTO environments (environment_id, backend, platform, recipe_digest, lock_digests, service_manifests, resource_policy_hash, runtime_fingerprint, mirror_uris)
        VALUES ('env1', 'fixture', 'darwin/arm64', 'rec1', '[]', '{}', ?, 'fp1', '[]')
        """,
        (d_res,),
    )
    conn.execute(
        """
        INSERT INTO repository_snapshots (snapshot_digest, repository_id, commit_oid, archive_uri, tree_digest, submodule_digests, lock_digests, licence, created_at)
        VALUES (?, 'repo1', 'oid1', ?, 'tree1', '[]', '[]', 'MIT', '2026-09-21T00:00:00Z')
        """,
        (d_snap, f"file://{snap_dir}"),
    )
    conn.execute(
        """
        INSERT INTO contracts (contract_hash, task_id, version, requirement_hashes, allowed_variation, unresolved_questions, evidence_digests, created_at)
        VALUES (?, 'task1', 'v1', '[]', 'none', '[]', '[]', '2026-09-21T00:00:00Z')
        """,
        (d_con,),
    )
    conn.execute(
        """
        INSERT INTO tasks (task_key, task_id, version, statement, adapter, contract_hash, snapshot_digest, environment_id, licence, provenance, eligibility, notes, created_at)
        VALUES ('task1@1.0', 'task1', '1.0', 'statement', 'fixture', ?, ?, 'env1', 'MIT', 'prov', 'eligible', '', '2026-09-21T00:00:00Z')
        """,
        (d_con, d_snap),
    )
    conn.execute(
        """
        INSERT INTO patch_cases (case_id, task_key, diff_digest, base_snapshot_digest, source, parent_case_ids, family_id, role, provenance_digest, licence, created_at)
        VALUES ('case1', 'task1@1.0', ?, ?, 'reference', '[]', 'fam1', 'challenge', 'prov1', 'MIT', '2026-09-21T00:00:00Z')
        """,
        (d_diff, d_snap),
    )
    db_cmd_json = json.dumps(
        [
            sys.executable,
            "-c",
            "import json, sys; from pathlib import Path; (Path(sys.argv[1]) / 'report.json').write_text(json.dumps(dict(tests=[dict(nodeid='t1', outcome='passed')])))",
            "{out}",
        ]
    )
    conn.execute(
        """
        INSERT INTO verifier_manifests (manifest_hash, mode, command, build_command, expected_collection, parser_id, report_path, payload_digest, allowed_edit_paths, required_pass_ids, permitted_skips, timeout_seconds)
        VALUES (?, 'compatibility', ?, '[]', '["t1"]', 'pytest-report-v1', 'report.json', ?, '["*"]', '[]', '[]', 30)
        """,
        (d_vman, db_cmd_json, d_pay),
    )
    conn.execute(
        """
        INSERT INTO verifier_versions (verifier_key, verifier_id, version, manifest_hash, payload_digest, compatible_contract_hashes, created_at)
        VALUES ('verifier@1.0', 'verifier1', '1.0', ?, ?, '[]', '2026-09-21T00:00:00Z')
        """,
        (d_vman, d_pay),
    )
    conn.execute(
        """
        INSERT INTO patch_panels (panel_key, panel_id, version, split, membership_digest, sampling_policy)
        VALUES ('panel1', 'p1', 'v1', 'development', 'mem1', 'policy1')
        """
    )
    conn.execute(
        """
        INSERT INTO audit_manifests (manifest_hash, run_id, benchmark_version, task_pins, panel_key, adjudication_version, evaluation_harness_version, config_hash, policy_hash, timestamp, host_fingerprint, max_repetitions, max_attempts_per_job, timeout_seconds, resource_policy, expansion_digest)
        VALUES (?, 'run1', 'v1', '[]', 'panel1', 'adj1', 'harn1', ?, ?, '2026-09-21T00:00:00Z', 'host1', 3, 3, 30, ?, 'exp1')
        """,
        (d_man, d_conf, d_pol, d_res),
    )
    conn.execute(
        """
        INSERT INTO audit_runs (run_id, manifest_hash, state, cancel_requested, created_at)
        VALUES ('run1', ?, 'PLANNED', 0, '2026-09-21T00:00:00Z')
        """,
        (d_man,),
    )
    return db, snap_dir, root


def test_worker_run_one_success(setup_env: tuple[Database, Path, Path]) -> None:
    db, snap_dir, root = setup_env
    conn = db.connection

    # Insert a job
    conn.execute(
        """
        INSERT INTO jobs (job_id, run_id, task_key, case_id, verifier_key, repetition, state, fence, attempts_started)
        VALUES ('j1', 'run1', 'task1@1.0', 'case1', 'verifier@1.0', 0, 'PENDING', 0, 0)
        """
    )

    # Command that writes a valid report.json
    script = (
        "import json, sys\n"
        "from pathlib import Path\n"
        "out = Path(sys.argv[1])\n"
        "data = {'tests': [{'nodeid': 'test_app.py::test_run', 'outcome': 'passed'}]}\n"
        "(out / 'report.json').write_text(json.dumps(data))\n"
    )
    py_script = root / "runner.py"
    py_script.write_text(script)

    manifest = VerifierManifest(
        manifest_hash="3" * 64,
        mode="compatibility",
        command=(sys.executable, str(py_script), "{out}"),
        build_command=(),
        expected_collection=("test_app.py::test_run",),
        parser_id="pytest-report-v1",
        report_path="report.json",
        payload_digest="c" * 64,
        allowed_edit_paths=("*",),
        required_pass_ids=("test_app.py::test_run",),
        permitted_skips=(),
        timeout_seconds=30,
    )

    worker = Worker(
        work_dir=root / "work",
        snapshot_resolver={"task1@1.0": snap_dir},
        diff_resolver={"case1": b""},
        manifest_resolver={"verifier@1.0": manifest},
    )

    executed = worker.run_one(conn, run_id="run1")
    assert executed is True

    # Check job state in db
    row = conn.execute(
        "SELECT state, selected_attempt_id FROM jobs WHERE job_id = 'j1'"
    ).fetchone()
    assert row["state"] == "DONE"
    assert row["selected_attempt_id"] is not None

    # Check attempt in db
    att = conn.execute(
        "SELECT * FROM evaluation_attempts WHERE attempt_id = ?",
        (row["selected_attempt_id"],),
    ).fetchone()
    assert att["outcome"] == "accept"
    assert att["evaluation_validity"] == "valid"
    assert att["disposition"] == "authoritative"
    assert att["tests_passed"] == 1

    # Empty queue returns False
    assert worker.run_one(conn, run_id="run1") is False


def test_worker_run_until_terminal(setup_env: tuple[Database, Path, Path]) -> None:
    db, snap_dir, root = setup_env
    conn = db.connection

    # Insert 2 jobs
    conn.execute(
        """
        INSERT INTO jobs (job_id, run_id, task_key, case_id, verifier_key, repetition, state, fence, attempts_started)
        VALUES ('j10', 'run1', 'task1@1.0', 'case1', 'verifier@1.0', 0, 'PENDING', 0, 0),
               ('j11', 'run1', 'task1@1.0', 'case1', 'verifier@1.0', 1, 'PENDING', 0, 0)
        """
    )

    script = (
        "import json, sys\n"
        "from pathlib import Path\n"
        "out = Path(sys.argv[1])\n"
        "data = {'tests': [{'nodeid': 't1', 'outcome': 'passed'}]}\n"
        "(out / 'report.json').write_text(json.dumps(data))\n"
    )
    py_script = root / "runner2.py"
    py_script.write_text(script)

    manifest = VerifierManifest(
        manifest_hash="3" * 64,
        mode="compatibility",
        command=(sys.executable, str(py_script), "{out}"),
        build_command=(),
        expected_collection=("t1",),
        parser_id="pytest-report-v1",
        report_path="report.json",
        payload_digest="c" * 64,
        allowed_edit_paths=("*",),
        required_pass_ids=("t1",),
        permitted_skips=(),
        timeout_seconds=30,
    )

    worker = Worker(
        work_dir=root / "work2",
        snapshot_resolver={"task1@1.0": snap_dir},
        diff_resolver={"case1": b""},
        manifest_resolver={"verifier@1.0": manifest},
    )

    count = worker.run_until_terminal(conn, run_id="run1")
    assert count == 2

    # Both jobs terminal
    rows = conn.execute(
        "SELECT state FROM jobs WHERE job_id IN ('j10', 'j11')"
    ).fetchall()
    assert all(r["state"] == "DONE" for r in rows)


def test_worker_patch_failure(setup_env: tuple[Database, Path, Path]) -> None:
    db, snap_dir, root = setup_env
    conn = db.connection

    # Insert a job
    conn.execute(
        """
        INSERT INTO jobs (job_id, run_id, task_key, case_id, verifier_key, repetition, state, fence, attempts_started)
        VALUES ('j_patch_fail', 'run1', 'task1@1.0', 'case1', 'verifier@1.0', 0, 'PENDING', 0, 0)
        """
    )

    manifest = VerifierManifest(
        manifest_hash="3" * 64,
        mode="compatibility",
        command=(sys.executable, "-c", "pass"),
        build_command=(),
        expected_collection=("t1",),
        parser_id="pytest-report-v1",
        report_path="report.json",
        payload_digest="c" * 64,
        allowed_edit_paths=("src/*",),
        required_pass_ids=("t1",),
        permitted_skips=(),
        timeout_seconds=30,
    )

    # Disallowed patch touches disallowed path
    bad_diff = b"""--- a/disallowed.py
+++ b/disallowed.py
@@ -1 +1 @@
-old
+new
"""
    worker = Worker(
        work_dir=root / "work3",
        snapshot_resolver={"task1@1.0": snap_dir},
        diff_resolver={"case1": bad_diff},
        manifest_resolver={"verifier@1.0": manifest},
    )

    executed = worker.run_one(conn, run_id="run1")
    assert executed is True

    # Check job state in db
    row = conn.execute(
        "SELECT state, selected_attempt_id FROM jobs WHERE job_id = 'j_patch_fail'"
    ).fetchone()
    assert row["state"] == "DONE"
    assert row["selected_attempt_id"] is not None

    # Check attempt in db
    att = conn.execute(
        "SELECT * FROM evaluation_attempts WHERE attempt_id = ?",
        (row["selected_attempt_id"],),
    ).fetchone()
    assert att["outcome"] == "invalid_evaluation"
    assert att["evaluation_validity"] == "invalid"
    assert att["error_code"] in (
        ErrorCode.PATCH_ERROR.value,
        ErrorCode.PROTECTION_ERROR.value,
    )


def test_worker_db_resolvers(setup_env: tuple[Database, Path, Path]) -> None:
    db, _snap_dir, root = setup_env
    conn = db.connection

    # Worker with NO resolvers passed; relies on DB rows
    worker = Worker(
        work_dir=root / "work_db",
    )
    art = worker.artifact_store.put_bytes(
        b"", max_bytes=1024, kind="diff", access_policy="restricted"
    )
    conn.execute(
        """
        INSERT INTO artifacts (digest, kind, size_bytes, storage_uri, media_type, access_policy, available, created_at)
        VALUES (?, 'diff', ?, 'local', 'text/x-diff', 'restricted', 1, '2026-09-21T00:00:00Z')
        """,
        (art.digest, art.size_bytes),
    )
    d_snap = "a" * 64
    conn.execute(
        """
        INSERT INTO patch_cases (case_id, task_key, diff_digest, base_snapshot_digest, source, parent_case_ids, family_id, role, provenance_digest, licence, created_at)
        VALUES ('case_db_res', 'task1@1.0', ?, ?, 'reference', '[]', 'fam1', 'challenge', 'prov1', 'MIT', '2026-09-21T00:00:00Z')
        """,
        (art.digest, d_snap),
    )
    # Insert a job
    conn.execute(
        """
        INSERT INTO jobs (job_id, run_id, task_key, case_id, verifier_key, repetition, state, fence, attempts_started)
        VALUES ('j_db_res', 'run1', 'task1@1.0', 'case_db_res', 'verifier@1.0', 0, 'PENDING', 0, 0)
        """
    )

    executed = worker.run_one(conn, run_id="run1")
    assert executed is True

    row = conn.execute(
        "SELECT state, selected_attempt_id FROM jobs WHERE job_id = 'j_db_res'"
    ).fetchone()
    assert row["state"] == "DONE"


def test_worker_build_command_failure(setup_env: tuple[Database, Path, Path]) -> None:
    db, snap_dir, root = setup_env
    conn = db.connection

    conn.execute(
        """
        INSERT INTO jobs (job_id, run_id, task_key, case_id, verifier_key, repetition, state, fence, attempts_started)
        VALUES ('j_bld_fail', 'run1', 'task1@1.0', 'case1', 'verifier@1.0', 0, 'PENDING', 0, 0)
        """
    )

    manifest = VerifierManifest(
        manifest_hash="4" * 64,
        mode="compatibility",
        command=(sys.executable, "-c", "pass"),
        build_command=(sys.executable, "-c", "import sys; sys.exit(42)"),
        expected_collection=("t1",),
        parser_id="pytest-report-v1",
        report_path="report.json",
        payload_digest="c" * 64,
        allowed_edit_paths=("*",),
        required_pass_ids=("t1",),
        permitted_skips=(),
        timeout_seconds=30,
    )

    worker = Worker(
        work_dir=root / "work_bld",
        snapshot_resolver={"task1@1.0": snap_dir},
        diff_resolver={"case1": b""},
        manifest_resolver={"verifier@1.0": manifest},
    )

    executed = worker.run_one(conn, run_id="run1")
    assert executed is True

    row = conn.execute(
        "SELECT state, selected_attempt_id FROM jobs WHERE job_id = 'j_bld_fail'"
    ).fetchone()
    assert row["state"] == "DONE"

    att = conn.execute(
        "SELECT * FROM evaluation_attempts WHERE attempt_id = ?",
        (row["selected_attempt_id"],),
    ).fetchone()
    assert att["outcome"] == "invalid_evaluation"
    assert att["error_code"] == ErrorCode.BUILD_ERROR.value


def test_worker_callable_resolvers_and_stderr(
    setup_env: tuple[Database, Path, Path],
) -> None:
    db, snap_dir, root = setup_env
    conn = db.connection

    conn.execute(
        """
        INSERT INTO jobs (job_id, run_id, task_key, case_id, verifier_key, repetition, state, fence, attempts_started)
        VALUES ('j_call', 'run1', 'task1@1.0', 'case1', 'verifier@1.0', 0, 'PENDING', 0, 0)
        """
    )

    script = (
        "import json, sys\n"
        "from pathlib import Path\n"
        "sys.stderr.write('logged stderr info\\n')\n"
        "out = Path(sys.argv[1])\n"
        "data = {'tests': [{'nodeid': 't1', 'outcome': 'passed'}]}\n"
        "(out / 'report.json').write_text(json.dumps(data))\n"
    )
    py_script = root / "runner_call.py"
    py_script.write_text(script)

    manifest = VerifierManifest(
        manifest_hash="5" * 64,
        mode="compatibility",
        command=(sys.executable, str(py_script), "{out}"),
        build_command=(),
        expected_collection=("t1",),
        parser_id="pytest-report-v1",
        report_path="report.json",
        payload_digest="c" * 64,
        allowed_edit_paths=("*",),
        required_pass_ids=("t1",),
        permitted_skips=(),
        timeout_seconds=30,
    )

    worker = Worker(
        work_dir=root / "work_call",
        snapshot_resolver=lambda t: snap_dir,
        diff_resolver=lambda c: b"",
        manifest_resolver=lambda v: manifest,
    )

    executed = worker.run_one(conn, run_id="run1")
    assert executed is True

    row = conn.execute(
        "SELECT state, selected_attempt_id FROM jobs WHERE job_id = 'j_call'"
    ).fetchone()
    att = conn.execute(
        "SELECT * FROM evaluation_attempts WHERE attempt_id = ?",
        (row["selected_attempt_id"],),
    ).fetchone()
    assert att["outcome"] == "accept"
    assert att["stderr_hash"] is not None


def test_worker_unresolvable_manifest(setup_env: tuple[Database, Path, Path]) -> None:
    db, _snap_dir, root = setup_env
    conn = db.connection

    worker = Worker(
        work_dir=root / "work_err",
    )
    with pytest.raises(Exception) as exc:
        worker._resolve_manifest("nonexistent_verifier_key", conn)
    assert "Cannot resolve VerifierManifest" in str(exc.value)


def test_worker_artifact_store_diff_resolution(
    setup_env: tuple[Database, Path, Path],
) -> None:
    db, _snap_dir, root = setup_env
    conn = db.connection

    store = ArtifactStore(root / "art_store")
    art = store.put_bytes(
        b"diff content", max_bytes=1024, kind="diff", access_policy="restricted"
    )

    d_snap = "a" * 64
    conn.execute(
        """
        INSERT INTO artifacts (digest, kind, size_bytes, storage_uri, media_type, access_policy, available, created_at)
        VALUES (?, 'diff', ?, 'local', 'text/x-diff', 'restricted', 1, '2026-09-21T00:00:00Z')
        """,
        (art.digest, art.size_bytes),
    )
    conn.execute(
        """
        INSERT INTO patch_cases (case_id, task_key, diff_digest, base_snapshot_digest, source, parent_case_ids, family_id, role, provenance_digest, licence, created_at)
        VALUES ('case_art_diff', 'task1@1.0', ?, ?, 'reference', '[]', 'fam1', 'challenge', 'prov1', 'MIT', '2026-09-21T00:00:00Z')
        """,
        (art.digest, d_snap),
    )

    worker = Worker(
        work_dir=root / "work_art",
        artifact_store=store,
    )
    diff = worker._resolve_diff("case_art_diff", conn)
    assert diff == b"diff content"


def test_worker_heartbeat_and_stdout(setup_env: tuple[Database, Path, Path]) -> None:
    db, snap_dir, root = setup_env
    conn = db.connection

    d_snap2 = "e" * 64
    d_con = "2" * 64
    conn.execute(
        """
        INSERT INTO artifacts (digest, kind, size_bytes, storage_uri, media_type, access_policy, available, created_at)
        VALUES (?, 'snapshot', 10, 'file:///s2', 'text/plain', 'public', 1, '2026-09-21T00:00:00Z')
        """,
        (d_snap2,),
    )
    conn.execute(
        """
        INSERT INTO repository_snapshots (snapshot_digest, repository_id, commit_oid, archive_uri, tree_digest, submodule_digests, lock_digests, licence, created_at)
        VALUES (?, 'repo2', 'oid2', ?, 'tree2', '[]', '[]', 'MIT', '2026-09-21T00:00:00Z')
        """,
        (d_snap2, str(snap_dir)),
    )
    conn.execute(
        """
        INSERT INTO tasks (task_key, task_id, version, statement, adapter, contract_hash, snapshot_digest, environment_id, licence, provenance, eligibility, notes, created_at)
        VALUES ('task2@1.0', 'task2', '1.0', 'statement', 'fixture', ?, ?, 'env1', 'MIT', 'prov', 'eligible', '', '2026-09-21T00:00:00Z')
        """,
        (d_con, d_snap2),
    )

    conn.execute(
        """
        INSERT INTO jobs (job_id, run_id, task_key, case_id, verifier_key, repetition, state, fence, attempts_started)
        VALUES ('j_hb', 'run1', 'task2@1.0', 'case1', 'verifier@1.0', 0, 'PENDING', 0, 0)
        """
    )

    script = (
        "import json, sys, time\n"
        "from pathlib import Path\n"
        "print('stdout logging message', flush=True)\n"
        "time.sleep(0.12)\n"
        "out = Path(sys.argv[1])\n"
        "data = {'tests': [{'nodeid': 't1', 'outcome': 'passed'}]}\n"
        "(out / 'report.json').write_text(json.dumps(data))\n"
    )
    py_script = root / "runner_hb.py"
    py_script.write_text(script)

    manifest = VerifierManifest(
        manifest_hash="3" * 64,
        mode="compatibility",
        command=(sys.executable, str(py_script), "{out}"),
        build_command=(),
        expected_collection=("t1",),
        parser_id="pytest-report-v1",
        report_path="report.json",
        payload_digest="c" * 64,
        allowed_edit_paths=("*",),
        required_pass_ids=("t1",),
        permitted_skips=(),
        timeout_seconds=30,
    )

    # Use lease_duration_ms (50ms) shorter than execution duration (120ms)
    worker = Worker(
        work_dir=root / "work_hb",
        diff_resolver={"case1": b""},
        manifest_resolver={"verifier@1.0": manifest},
        heartbeat_interval_seconds=0.01,
        lease_duration_ms=50,
    )

    executed = worker.run_one(conn, run_id="run1")
    assert executed is True

    row = conn.execute(
        "SELECT state, selected_attempt_id FROM jobs WHERE job_id = 'j_hb'"
    ).fetchone()
    assert row["state"] == "DONE"
    att = conn.execute(
        "SELECT * FROM evaluation_attempts WHERE attempt_id = ?",
        (row["selected_attempt_id"],),
    ).fetchone()
    assert att["stdout_hash"] is not None
    assert att["outcome"] == "accept"
    assert att["disposition"] == "authoritative"


def test_worker_resolve_snapshot_missing(
    setup_env: tuple[Database, Path, Path],
) -> None:
    db, _snap_dir, root = setup_env
    conn = db.connection
    worker = Worker(
        work_dir=root / "work_snap_err",
        snapshot_resolver={"task1@1.0": root / "nonexistent_dir"},
    )
    from verifierci.errors import ValidationError

    with pytest.raises(ValidationError) as exc:
        worker._resolve_snapshot("task1@1.0", conn)
    assert "Resolved snapshot directory does not exist" in str(exc.value)


def test_worker_resolve_diff_missing_in_store(
    setup_env: tuple[Database, Path, Path],
) -> None:
    db, _snap_dir, root = setup_env
    conn = db.connection
    worker = Worker(
        work_dir=root / "work_diff_err",
    )
    from verifierci.errors import ValidationError

    # case1 in setup_env references d_diff which is not in worker's artifact_store
    with pytest.raises(ValidationError) as exc:
        worker._resolve_diff("case1", conn)
    assert "Diff artifact not found in store" in str(exc.value)


def test_worker_resolve_manifest_invalid_report_path(
    setup_env: tuple[Database, Path, Path],
) -> None:
    db, _snap_dir, root = setup_env
    conn = db.connection
    from verifierci.errors import ValidationError

    # Traversal in report_path
    bad_manifest1 = VerifierManifest(
        manifest_hash="3" * 64,
        mode="compatibility",
        command=("cmd",),
        build_command=(),
        expected_collection=(),
        parser_id="pytest-report-v1",
        report_path="../outside.json",
        payload_digest="c" * 64,
        allowed_edit_paths=("*",),
        required_pass_ids=(),
        permitted_skips=(),
        timeout_seconds=30,
    )
    worker1 = Worker(
        work_dir=root / "work_rep_err1",
        manifest_resolver={"v1": bad_manifest1},
    )
    with pytest.raises(ValidationError):
        worker1._resolve_manifest("v1", conn)

    # Absolute path in report_path
    bad_manifest2 = VerifierManifest(
        manifest_hash="3" * 64,
        mode="compatibility",
        command=("cmd",),
        build_command=(),
        expected_collection=(),
        parser_id="pytest-report-v1",
        report_path="/tmp/outside.json",
        payload_digest="c" * 64,
        allowed_edit_paths=("*",),
        required_pass_ids=(),
        permitted_skips=(),
        timeout_seconds=30,
    )
    worker2 = Worker(
        work_dir=root / "work_rep_err2",
        manifest_resolver={"v2": bad_manifest2},
    )
    with pytest.raises(ValidationError):
        worker2._resolve_manifest("v2", conn)
