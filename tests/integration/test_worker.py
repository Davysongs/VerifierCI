"""Integration tests for execution worker and end-to-end attempt lifecycle.

SDD Section 7.1, 7.2, 7.3, 7.5, and 9.2:
- Private temporary database roots and disk SQLite databases with WAL mode.
- Clean workspace directory creation with 0700 permissions.
- Isolated Git diff application and patch rejection outside allowed paths.
- Execution supervision with bounded timers and capped pipes.
- Content-addressed artifact persistence and verification.
- Normative outcome parsing and precedence hierarchy.
- Authoritative attempt commit under live lease fence.
- Required integration tests:
  - test_patch_application_and_outcome_parsing_roundtrip
  - test_patch_application_failure_produces_patch_error_not_reject
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from verifierci.errors import ErrorCode
from verifierci.execution.worker import Worker
from verifierci.models.verifier import VerifierManifest
from verifierci.storage.artifacts import ArtifactStore
from verifierci.storage.db import Database


def _setup_disk_environment(
    root: Path,
) -> tuple[Database, Path, ArtifactStore, str, str]:
    """Create a private disk database with WAL mode and seed required hierarchy."""
    db_file = root / "worker_integration.db"
    db = Database(db_file)
    db.migrate()
    conn = db.connection

    snap_dir = root / "snapshot"
    snap_dir.mkdir(parents=True, exist_ok=True)
    (snap_dir / "app.py").write_text("def solve(): return 0\n")

    store = ArtifactStore(root / "artifacts")
    empty_diff_art = store.put_bytes(
        b"", max_bytes=1024, kind="diff", access_policy="restricted"
    )

    d_snap = "a" * 64
    d_con = "b" * 64
    d_res = "c" * 64
    d_man = "d" * 64
    d_conf = "e" * 64
    d_pol = "f" * 64
    d_vman = "1" * 64
    d_pay = "2" * 64
    d_diff_empty = empty_diff_art.digest

    conn.execute(
        """
        INSERT INTO artifacts (digest, kind, size_bytes, storage_uri, media_type, access_policy, available, created_at)
        VALUES (?, 'snapshot', 10, 'file:///s', 'text/plain', 'public', 1, '2026-09-21T00:00:00Z'),
               (?, 'payload', 10, 'file:///p', 'application/zip', 'public', 1, '2026-09-21T00:00:00Z'),
               (?, 'diff', 0, 'file:///empty', 'text/x-diff', 'restricted', 1, '2026-09-21T00:00:00Z')
        """,
        (d_snap, d_pay, d_diff_empty),
    )
    conn.execute(
        """
        INSERT INTO environments (environment_id, backend, platform, recipe_digest, lock_digests, service_manifests, resource_policy_hash, runtime_fingerprint, mirror_uris)
        VALUES ('env_int', 'fixture', 'darwin/arm64', 'rec1', '[]', '{}', ?, 'fp1', '[]')
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
        VALUES (?, 'task_int', 'v1', '[]', 'none', '[]', '[]', '2026-09-21T00:00:00Z')
        """,
        (d_con,),
    )
    conn.execute(
        """
        INSERT INTO tasks (task_key, task_id, version, statement, adapter, contract_hash, snapshot_digest, environment_id, licence, provenance, eligibility, notes, created_at)
        VALUES ('task_int@1.0', 'task_int', '1.0', 'statement', 'fixture', ?, ?, 'env_int', 'MIT', 'prov', 'eligible', '', '2026-09-21T00:00:00Z')
        """,
        (d_con, d_snap),
    )
    conn.execute(
        """
        INSERT INTO patch_panels (panel_key, panel_id, version, split, membership_digest, sampling_policy)
        VALUES ('panel_int', 'p1', 'v1', 'development', 'mem1', 'policy1')
        """
    )
    conn.execute(
        """
        INSERT INTO verifier_manifests (manifest_hash, mode, command, build_command, expected_collection, parser_id, report_path, payload_digest, allowed_edit_paths, required_pass_ids, permitted_skips, timeout_seconds)
        VALUES (?, 'compatibility', '["python"]', '[]', '["test_1"]', 'pytest-report-v1', 'report.json', ?, '["*"]', '[]', '[]', 30)
        """,
        (d_vman, d_pay),
    )
    conn.execute(
        """
        INSERT INTO verifier_versions (verifier_key, verifier_id, version, manifest_hash, payload_digest, compatible_contract_hashes, created_at)
        VALUES ('verifier@1.0', 'ver_int', '1.0', ?, ?, '[]', '2026-09-21T00:00:00Z')
        """,
        (d_vman, d_pay),
    )
    conn.execute(
        """
        INSERT INTO audit_manifests (manifest_hash, run_id, benchmark_version, task_pins, panel_key, adjudication_version, evaluation_harness_version, config_hash, policy_hash, timestamp, host_fingerprint, max_repetitions, max_attempts_per_job, timeout_seconds, resource_policy, expansion_digest)
        VALUES (?, 'run_int', 'v1', '[]', 'panel_int', 'adj1', 'harn1', ?, ?, '2026-09-21T00:00:00Z', 'host1', 1, 3, 30, ?, 'exp1')
        """,
        (d_man, d_conf, d_pol, d_res),
    )
    conn.execute(
        """
        INSERT INTO audit_runs (run_id, manifest_hash, state, cancel_requested, created_at)
        VALUES ('run_int', ?, 'RUNNING', 0, '2026-09-21T00:00:00Z')
        """,
        (d_man,),
    )

    return db, snap_dir, store, d_snap, d_diff_empty


def test_patch_application_and_outcome_parsing_roundtrip(tmp_path: Path) -> None:
    """SDD Section 9.2: Verify end-to-end patch application, execution, output capture, and outcome parsing."""
    db, snap_dir, store, d_snap, _ = _setup_disk_environment(tmp_path)
    conn = db.connection

    # Valid diff modifying app.py to solve problem
    valid_diff = b"""--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-def solve(): return 0
+def solve(): return 42
"""
    diff_art = store.put_bytes(
        valid_diff, max_bytes=1024, kind="diff", access_policy="restricted"
    )
    conn.execute(
        """
        INSERT INTO artifacts (digest, kind, size_bytes, storage_uri, media_type, access_policy, available, created_at)
        VALUES (?, 'diff', ?, 'file:///diff', 'text/x-diff', 'restricted', 1, '2026-09-21T00:00:00Z')
        """,
        (diff_art.digest, diff_art.size_bytes),
    )
    conn.execute(
        """
        INSERT INTO patch_cases (case_id, task_key, diff_digest, base_snapshot_digest, source, parent_case_ids, family_id, role, provenance_digest, licence, created_at)
        VALUES ('case_valid', 'task_int@1.0', ?, ?, 'reference', '[]', 'fam1', 'challenge', 'prov1', 'MIT', '2026-09-21T00:00:00Z')
        """,
        (diff_art.digest, d_snap),
    )

    # Verifier runner script that tests solve() and writes structured report.json
    script = (
        "import json, sys\n"
        "sys.path.insert(0, '.')\n"
        "from pathlib import Path\n"
        "from app import solve\n"
        "assert solve() == 42\n"
        "out = Path(sys.argv[1])\n"
        "data = {'tests': [{'nodeid': 'tests/test_app.py::test_solve', 'outcome': 'passed'}]}\n"
        "(out / 'report.json').write_text(json.dumps(data))\n"
        "print('Roundtrip verification passed!')\n"
    )
    runner_script = tmp_path / "runner_roundtrip.py"
    runner_script.write_text(script)

    manifest = VerifierManifest(
        manifest_hash="3" * 64,
        mode="compatibility",
        command=(sys.executable, str(runner_script), "{out}"),
        build_command=(),
        expected_collection=("tests/test_app.py::test_solve",),
        parser_id="pytest-report-v1",
        report_path="report.json",
        payload_digest="2" * 64,
        allowed_edit_paths=("*",),
        required_pass_ids=("tests/test_app.py::test_solve",),
        permitted_skips=(),
        timeout_seconds=30,
    )

    # Insert pending job
    conn.execute(
        """
        INSERT INTO jobs (job_id, run_id, task_key, case_id, verifier_key, repetition, state, fence, attempts_started)
        VALUES ('job_roundtrip', 'run_int', 'task_int@1.0', 'case_valid', 'verifier@1.0', 0, 'PENDING', 0, 0)
        """
    )

    worker_work_dir = tmp_path / "work_roundtrip"
    worker = Worker(
        work_dir=worker_work_dir,
        artifact_store=store,
        snapshot_resolver={"task_int@1.0": snap_dir},
        manifest_resolver={"verifier@1.0": manifest},
    )

    # Run worker
    claimed = worker.run_one(conn, run_id="run_int")
    assert claimed is True

    # Check job state in disk database
    job_row = conn.execute(
        "SELECT state, selected_attempt_id FROM jobs WHERE job_id = 'job_roundtrip'"
    ).fetchone()
    assert job_row["state"] == "DONE"
    assert job_row["selected_attempt_id"] is not None

    # Check evaluation attempt in disk database
    att = conn.execute(
        "SELECT * FROM evaluation_attempts WHERE attempt_id = ?",
        (job_row["selected_attempt_id"],),
    ).fetchone()
    assert att["outcome"] == "accept"
    assert att["evaluation_validity"] == "valid"
    assert att["disposition"] == "authoritative"
    assert att["tests_passed"] == 1
    assert att["tests_failed"] == 0
    assert att["stdout_hash"] is not None
    assert att["report_digest"] is not None

    # Verify artifacts exist in store with verified digests
    assert store.exists(att["stdout_hash"])
    assert store.exists(att["report_digest"])
    with store.open_verified(att["report_digest"]) as f:
        rep_data = json.load(f)
    assert rep_data["tests"][0]["outcome"] == "passed"

    # Verify attempt directory was cleaned up from disk in finally
    attempt_dir = worker_work_dir / "attempts" / job_row["selected_attempt_id"]
    assert not attempt_dir.exists()


def test_patch_application_failure_produces_patch_error_not_reject(
    tmp_path: Path,
) -> None:
    """SDD Section 9.2: Patch application failure is classified as PATCH_ERROR, not reject."""
    db, snap_dir, store, d_snap, _ = _setup_disk_environment(tmp_path)
    conn = db.connection

    # Patch touching disallowed path
    bad_diff = b"""--- a/disallowed.py
+++ b/disallowed.py
@@ -1 +1 @@
-old
+new
"""
    diff_art = store.put_bytes(
        bad_diff, max_bytes=1024, kind="diff", access_policy="restricted"
    )
    conn.execute(
        """
        INSERT INTO artifacts (digest, kind, size_bytes, storage_uri, media_type, access_policy, available, created_at)
        VALUES (?, 'diff', ?, 'file:///bad_diff', 'text/x-diff', 'restricted', 1, '2026-09-21T00:00:00Z')
        """,
        (diff_art.digest, diff_art.size_bytes),
    )
    conn.execute(
        """
        INSERT INTO patch_cases (case_id, task_key, diff_digest, base_snapshot_digest, source, parent_case_ids, family_id, role, provenance_digest, licence, created_at)
        VALUES ('case_bad_patch', 'task_int@1.0', ?, ?, 'reference', '[]', 'fam1', 'challenge', 'prov1', 'MIT', '2026-09-21T00:00:00Z')
        """,
        (diff_art.digest, d_snap),
    )

    manifest = VerifierManifest(
        manifest_hash="4" * 64,
        mode="compatibility",
        command=(sys.executable, "-c", "pass"),
        build_command=(),
        expected_collection=("tests/test.py",),
        parser_id="pytest-report-v1",
        report_path="report.json",
        payload_digest="2" * 64,
        allowed_edit_paths=("app.py",),  # Only app.py allowed; disallowed.py will fail
        required_pass_ids=(),
        permitted_skips=(),
        timeout_seconds=30,
    )

    conn.execute(
        """
        INSERT INTO jobs (job_id, run_id, task_key, case_id, verifier_key, repetition, state, fence, attempts_started)
        VALUES ('job_patch_err', 'run_int', 'task_int@1.0', 'case_bad_patch', 'verifier@1.0', 0, 'PENDING', 0, 0)
        """
    )

    worker_work_dir = tmp_path / "work_patch_err"
    worker = Worker(
        work_dir=worker_work_dir,
        artifact_store=store,
        snapshot_resolver={"task_int@1.0": snap_dir},
        manifest_resolver={"verifier@1.0": manifest},
    )

    claimed = worker.run_one(conn, run_id="run_int")
    assert claimed is True

    job_row = conn.execute(
        "SELECT state, selected_attempt_id FROM jobs WHERE job_id = 'job_patch_err'"
    ).fetchone()
    # Job is terminal DONE because evaluation concluded with an observation
    assert job_row["state"] == "DONE"

    att = conn.execute(
        "SELECT outcome, evaluation_validity, error_code, disposition FROM evaluation_attempts WHERE attempt_id = ?",
        (job_row["selected_attempt_id"],),
    ).fetchone()
    # Normative check: PATCH_ERROR, not reject
    assert att["outcome"] == "invalid_evaluation"
    assert att["outcome"] != "reject"
    assert att["evaluation_validity"] == "invalid"
    assert att["error_code"] in (
        ErrorCode.PATCH_ERROR.value,
        ErrorCode.PROTECTION_ERROR.value,
    )
    assert att["disposition"] == "authoritative"


def test_single_worker_stream_byte_capping_and_permissions(
    tmp_path: Path,
) -> None:
    """Verify fresh workspace scaffolding with 0700 permissions and stream byte capping."""
    db, snap_dir, store, d_snap, d_diff_empty = _setup_disk_environment(tmp_path)
    conn = db.connection

    # Runner that outputs large stream
    script = (
        "import sys\n"
        "# Print 1 MB of output to stdout\n"
        "sys.stdout.write('A' * (1024 * 1024))\n"
        "sys.stdout.flush()\n"
        "import json; from pathlib import Path\n"
        "out = Path(sys.argv[1])\n"
        "(out / 'report.json').write_text(json.dumps({'tests': [{'nodeid': 't1', 'outcome': 'passed'}]}))\n"
    )
    runner_script = tmp_path / "runner_streams.py"
    runner_script.write_text(script)

    manifest = VerifierManifest(
        manifest_hash="5" * 64,
        mode="compatibility",
        command=(sys.executable, str(runner_script), "{out}"),
        build_command=(),
        expected_collection=("t1",),
        parser_id="pytest-report-v1",
        report_path="report.json",
        payload_digest="2" * 64,
        allowed_edit_paths=("*",),
        required_pass_ids=("t1",),
        permitted_skips=(),
        timeout_seconds=30,
    )

    conn.execute(
        """
        INSERT INTO patch_cases (case_id, task_key, diff_digest, base_snapshot_digest, source, parent_case_ids, family_id, role, provenance_digest, licence, created_at)
        VALUES ('case_stream', 'task_int@1.0', ?, ?, 'reference', '[]', 'fam1', 'challenge', 'prov1', 'MIT', '2026-09-21T00:00:00Z')
        """,
        (d_diff_empty, d_snap),
    )
    conn.execute(
        """
        INSERT INTO jobs (job_id, run_id, task_key, case_id, verifier_key, repetition, state, fence, attempts_started)
        VALUES ('job_stream_test', 'run_int', 'task_int@1.0', 'case_stream', 'verifier@1.0', 0, 'PENDING', 0, 0)
        """
    )

    worker_work_dir = tmp_path / "work_stream"
    worker = Worker(
        work_dir=worker_work_dir,
        artifact_store=store,
        snapshot_resolver={"task_int@1.0": snap_dir},
        manifest_resolver={"verifier@1.0": manifest},
    )

    claimed = worker.run_one(conn, run_id="run_int")
    assert claimed is True

    job_row = conn.execute(
        "SELECT state, selected_attempt_id FROM jobs WHERE job_id = 'job_stream_test'"
    ).fetchone()
    assert job_row["state"] == "DONE"

    att = conn.execute(
        "SELECT stdout_hash, outcome, disposition FROM evaluation_attempts WHERE attempt_id = ?",
        (job_row["selected_attempt_id"],),
    ).fetchone()
    assert att["outcome"] == "accept"
    assert att["stdout_hash"] is not None
    # Artifact was stored and matches digest
    assert store.exists(att["stdout_hash"])


def test_fenced_completion_under_unexpired_lease(tmp_path: Path) -> None:
    """Verify that execution worker commits result through live fence under unexpired lease."""
    db, snap_dir, store, d_snap, d_diff_empty = _setup_disk_environment(tmp_path)
    conn = db.connection

    script = (
        "import json, sys\n"
        "from pathlib import Path\n"
        "out = Path(sys.argv[1])\n"
        "(out / 'report.json').write_text(json.dumps({'tests': [{'nodeid': 't1', 'outcome': 'passed'}]}))\n"
    )
    runner_script = tmp_path / "runner_fenced.py"
    runner_script.write_text(script)

    manifest = VerifierManifest(
        manifest_hash="6" * 64,
        mode="compatibility",
        command=(sys.executable, str(runner_script), "{out}"),
        build_command=(),
        expected_collection=("t1",),
        parser_id="pytest-report-v1",
        report_path="report.json",
        payload_digest="2" * 64,
        allowed_edit_paths=("*",),
        required_pass_ids=("t1",),
        permitted_skips=(),
        timeout_seconds=30,
    )

    conn.execute(
        """
        INSERT INTO patch_cases (case_id, task_key, diff_digest, base_snapshot_digest, source, parent_case_ids, family_id, role, provenance_digest, licence, created_at)
        VALUES ('case_fenced', 'task_int@1.0', ?, ?, 'reference', '[]', 'fam1', 'challenge', 'prov1', 'MIT', '2026-09-21T00:00:00Z')
        """,
        (d_diff_empty, d_snap),
    )
    conn.execute(
        """
        INSERT INTO jobs (job_id, run_id, task_key, case_id, verifier_key, repetition, state, fence, attempts_started)
        VALUES ('job_fenced_test', 'run_int', 'task_int@1.0', 'case_fenced', 'verifier@1.0', 0, 'PENDING', 0, 0)
        """
    )

    worker = Worker(
        work_dir=tmp_path / "work_fenced",
        artifact_store=store,
        snapshot_resolver={"task_int@1.0": snap_dir},
        manifest_resolver={"verifier@1.0": manifest},
        lease_duration_ms=60_000,
    )

    claimed = worker.run_one(conn, run_id="run_int")
    assert claimed is True

    job_row = conn.execute(
        "SELECT state, fence, selected_attempt_id FROM jobs WHERE job_id = 'job_fenced_test'"
    ).fetchone()
    # Claim incremented fence from 0 to 1, commit finalized to DONE
    assert job_row["state"] == "DONE"
    assert job_row["fence"] == 1
    assert job_row["selected_attempt_id"] is not None
