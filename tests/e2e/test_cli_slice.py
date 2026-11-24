"""End-to-end Phase 1 Vertical Slice & CLI tests (SDD §3.3, §9.3, §13).

Validates:
- `task import` and `panel validate` CLI invocations, exit codes, and JSON envelopes.
- Full Phase 1 acceptance command via both Click `CliRunner` and real subprocess
  execution (`verifierci` entry-point / `python -m verifierci.cli`).
- Completion of all 30 scheduled evaluation jobs producing 10 deterministic
  matrix cells matching hand-calculated fixture observations, exit status 0,
  and `gate` remaining `null` (unevaluated).
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from verifierci.cli import CLI_SCHEMA_VERSION, cli
from verifierci.errors import ErrorCode

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
RETRY_DIR = REPO_ROOT / "examples" / "retry-contract"

EXPECTED_CELL_OUTCOMES: dict[tuple[str, str], str] = {
    ("case-reference", "retry-contract-v1@1.0.0"): "accept",
    ("case-reference", "retry-contract-v2@1.0.0"): "accept",
    ("case-valid-alternative", "retry-contract-v1@1.0.0"): "accept",
    ("case-valid-alternative", "retry-contract-v2@1.0.0"): "reject",
    ("case-retries-permanent", "retry-contract-v1@1.0.0"): "accept",
    ("case-retries-permanent", "retry-contract-v2@1.0.0"): "reject",
    ("case-exceeds-retry-count", "retry-contract-v1@1.0.0"): "accept",
    ("case-exceeds-retry-count", "retry-contract-v2@1.0.0"): "reject",
    ("case-noop", "retry-contract-v1@1.0.0"): "accept",
    ("case-noop", "retry-contract-v2@1.0.0"): "accept",
}


def _cli_executable() -> list[str]:
    """Return installed `verifierci` console script when present, else `python -m`."""
    sibling = Path(sys.executable).parent / "verifierci"
    if sibling.is_file() and os.access(sibling, os.X_OK):
        return [str(sibling)]
    found = shutil.which("verifierci")
    if found:
        return [found]
    return [sys.executable, "-m", "verifierci.cli"]


def _subprocess_env() -> dict[str, str]:
    env = dict(os.environ)
    src_path = str(REPO_ROOT / "src")
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{src_path}:{existing}" if existing else src_path
    return env


def _assert_slice_result(
    payload: dict[str, object],
    *,
    db_path: Path,
    out_dir: Path,
) -> None:
    """Assert canonical 30-job, 10-cell Phase 1 vertical slice AuditResult."""
    assert payload["schema_version"] == CLI_SCHEMA_VERSION
    assert payload["kind"] == "AuditResult"

    data = payload["data"]
    assert isinstance(data, dict)
    assert data["gate"] is None
    assert data["metrics"] == []

    matrix = data["matrix"]
    assert isinstance(matrix, dict)
    assert matrix["complete"] is True
    raw_cells = matrix["cells"]
    assert isinstance(raw_cells, list)
    assert len(raw_cells) == 10

    cells_by_key = {(c["case_id"], c["verifier_key"]): c for c in raw_cells}
    assert set(cells_by_key) == set(EXPECTED_CELL_OUTCOMES)
    for key, exp_outcome in EXPECTED_CELL_OUTCOMES.items():
        cell = cells_by_key[key]
        assert cell["task_key"] == "retry-contract@1.0.0"
        assert cell["outcome"] == exp_outcome
        assert cell["evaluation_validity"] == "valid"
        assert cell["planned_repetitions"] == 3
        assert cell["repetition_outcomes"] == [exp_outcome] * 3
        assert len(cell["selected_attempt_ids"]) == 3
        assert cell["excluded_attempt_ids"] == []

    # Verify SQLite persistence: 30 DONE jobs and 30 evaluation attempts
    run_id = data["manifest"]["run_id"]
    conn = sqlite3.connect(db_path)
    try:
        done_jobs = conn.execute(
            "SELECT COUNT(*) FROM jobs WHERE run_id = ? AND state = 'DONE'",
            (run_id,),
        ).fetchone()[0]
        attempts = conn.execute(
            "SELECT COUNT(*) FROM evaluation_attempts a "
            "JOIN jobs j ON a.job_id = j.job_id WHERE j.run_id = ?",
            (run_id,),
        ).fetchone()[0]
        assert done_jobs == 30
        assert attempts == 30
    finally:
        conn.close()

    # Verify atomic output files on disk
    report_path = out_dir / "report.json"
    summary_path = out_dir / "summary.txt"
    manifest_path = out_dir / "manifest.json"
    assert report_path.is_file()
    assert summary_path.is_file()
    assert manifest_path.is_file()

    disk_report = json.loads(report_path.read_text(encoding="utf-8"))
    assert disk_report["data"]["gate"] is None
    assert disk_report["data"]["matrix"]["matrix_id"] == matrix["matrix_id"]


def test_cli_task_import_and_panel_validate_e2e(tmp_path: Path) -> None:
    runner = CliRunner()
    db_path = tmp_path / "cli.sqlite"
    art_dir = tmp_path / "artifacts"
    out_dir = tmp_path / "imported"

    # 1. `task import --dry-run` (read-only, exit 0, JSON envelope)
    dry_res = runner.invoke(
        cli,
        [
            "--db",
            str(db_path),
            "--artifact-dir",
            str(art_dir),
            "--json",
            "task",
            "import",
            "--adapter",
            "local",
            "--instance",
            "retry-contract",
            "--source",
            str(RETRY_DIR / "task.yaml"),
            "--source-revision",
            "1.0.0",
            "--output-dir",
            str(out_dir),
            "--dry-run",
        ],
    )
    assert dry_res.exit_code == 0, dry_res.stderr
    dry_payload = json.loads(dry_res.stdout)
    assert dry_payload["schema_version"] == CLI_SCHEMA_VERSION
    assert dry_payload["kind"] == "TaskImportResult"
    assert dry_payload["data"]["dry_run"] is True
    assert dry_payload["data"]["task_key"] == "retry-contract@1.0.0"
    assert not db_path.exists()

    # 2. Persistent `task import` (exit 0, writes DB and materialized files)
    imp_res = runner.invoke(
        cli,
        [
            "--db",
            str(db_path),
            "--artifact-dir",
            str(art_dir),
            "--json",
            "task",
            "import",
            "--adapter",
            "local",
            "--instance",
            "retry-contract",
            "--source",
            str(RETRY_DIR / "task.yaml"),
            "--source-revision",
            "1.0.0",
            "--output-dir",
            str(out_dir),
        ],
    )
    assert imp_res.exit_code == 0, imp_res.stderr
    imp_payload = json.loads(imp_res.stdout)
    assert imp_payload["kind"] == "TaskImportResult"
    assert imp_payload["data"]["requirements_count"] == 4
    assert db_path.is_file()

    # 3. `panel validate` success & error exit codes
    val_ok = runner.invoke(
        cli,
        [
            "--json",
            "panel",
            "validate",
            str(RETRY_DIR / "panel.jsonl"),
            "--expected-split",
            "development",
            "--verify-artifacts",
        ],
    )
    assert val_ok.exit_code == 0, val_ok.stderr
    val_payload = json.loads(val_ok.stdout)
    assert val_payload["schema_version"] == CLI_SCHEMA_VERSION
    assert val_payload["kind"] == "PanelValidationResult"
    assert val_payload["data"]["panel_key"] == "retry-contract-panel@1.0.0"
    assert val_payload["data"]["case_count"] == 5
    assert val_payload["data"]["valid"] is True

    # Exit 1: split mismatch (ProtectionError)
    val_split = runner.invoke(
        cli,
        [
            "--json",
            "panel",
            "validate",
            str(RETRY_DIR / "panel.jsonl"),
            "--expected-split",
            "assessment",
        ],
    )
    assert val_split.exit_code == 1
    assert ErrorCode.PROTECTION_ERROR.value in val_split.stderr

    # Exit 2: provisional panel with --require-independent (ValidationError)
    val_ind = runner.invoke(
        cli,
        [
            "--json",
            "panel",
            "validate",
            str(RETRY_DIR / "panel.jsonl"),
            "--require-independent",
        ],
    )
    assert val_ind.exit_code == 2
    assert ErrorCode.VALIDATION_ERROR.value in val_ind.stderr


def test_phase1_slice_click_runner(tmp_path: Path) -> None:
    runner = CliRunner()
    db_path = tmp_path / "slice_click.sqlite"
    art_dir = tmp_path / "artifacts"
    out_dir = tmp_path / "out"

    res = runner.invoke(
        cli,
        [
            "--db",
            str(db_path),
            "--artifact-dir",
            str(art_dir),
            "--json",
            "audit",
            "--task",
            str(RETRY_DIR / "task.yaml"),
            "--panel",
            str(RETRY_DIR / "panel.jsonl"),
            "--baseline",
            str(RETRY_DIR / "v1.yaml"),
            "--candidate",
            str(RETRY_DIR / "v2.yaml"),
            "--backend",
            "fixture",
            "--trusted-fixture",
            "--diagnostic",
            "--collect-only",
            "--repetitions",
            "3",
            "--output-dir",
            str(out_dir),
        ],
    )
    assert res.exit_code == 0, res.stderr
    payload = json.loads(res.stdout)
    _assert_slice_result(payload, db_path=db_path, out_dir=out_dir)

    # Without --trusted-fixture -> exit 1 (ProtectionError)
    untrusted_res = runner.invoke(
        cli,
        [
            "--db",
            str(tmp_path / "u.sqlite"),
            "--artifact-dir",
            str(tmp_path / "u_art"),
            "--json",
            "audit",
            "--task",
            str(RETRY_DIR / "task.yaml"),
            "--panel",
            str(RETRY_DIR / "panel.jsonl"),
            "--baseline",
            str(RETRY_DIR / "v1.yaml"),
            "--candidate",
            str(RETRY_DIR / "v2.yaml"),
            "--backend",
            "fixture",
            "--diagnostic",
            "--collect-only",
            "--repetitions",
            "3",
        ],
    )
    assert untrusted_res.exit_code == 1
    assert ErrorCode.PROTECTION_ERROR.value in untrusted_res.stderr


def test_phase1_slice_subprocess_cli(tmp_path: Path) -> None:
    db_path = tmp_path / "slice_subproc.sqlite"
    art_dir = tmp_path / "artifacts"
    out_dir = tmp_path / "out"
    env = _subprocess_env()
    exe = _cli_executable()

    # Subprocess `task import`
    imp_proc = subprocess.run(
        exe
        + [
            "--db",
            str(db_path),
            "--artifact-dir",
            str(art_dir),
            "--json",
            "task",
            "import",
            "--adapter",
            "local",
            "--instance",
            "retry-contract",
            "--source",
            str(RETRY_DIR / "task.yaml"),
            "--source-revision",
            "1.0.0",
            "--output-dir",
            str(tmp_path / "imported"),
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert imp_proc.returncode == 0, imp_proc.stderr
    assert json.loads(imp_proc.stdout)["kind"] == "TaskImportResult"

    # Subprocess `panel validate`
    pan_proc = subprocess.run(
        exe
        + [
            "--json",
            "panel",
            "validate",
            str(RETRY_DIR / "panel.jsonl"),
            "--expected-split",
            "development",
            "--verify-artifacts",
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert pan_proc.returncode == 0, pan_proc.stderr
    assert json.loads(pan_proc.stdout)["kind"] == "PanelValidationResult"

    # Subprocess Phase 1 acceptance `audit` command
    audit_proc = subprocess.run(
        exe
        + [
            "--db",
            str(db_path),
            "--artifact-dir",
            str(art_dir),
            "--json",
            "audit",
            "--task",
            str(RETRY_DIR / "task.yaml"),
            "--panel",
            str(RETRY_DIR / "panel.jsonl"),
            "--baseline",
            str(RETRY_DIR / "v1.yaml"),
            "--candidate",
            str(RETRY_DIR / "v2.yaml"),
            "--backend",
            "fixture",
            "--trusted-fixture",
            "--diagnostic",
            "--collect-only",
            "--repetitions",
            "3",
            "--output-dir",
            str(out_dir),
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert audit_proc.returncode == 0, audit_proc.stderr
    payload = json.loads(audit_proc.stdout)
    _assert_slice_result(payload, db_path=db_path, out_dir=out_dir)


@pytest.mark.parametrize("flag_args", [["--version"], ["--help"]])
def test_subprocess_cli_metadata_flags(flag_args: list[str]) -> None:
    env = _subprocess_env()
    for runner_cmd in (
        _cli_executable(),
        [sys.executable, "-m", "verifierci.cli"],
        [sys.executable, "-m", "verifierci"],
    ):
        proc = subprocess.run(
            runner_cmd + flag_args,
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.strip()
