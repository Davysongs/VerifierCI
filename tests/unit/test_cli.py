"""Unit tests for Click CLI entrypoint and Phase 1 commands (verifierci.cli).

SDD Section 5, Section 6.1, 6.2, 6.5, 6.9, and ADR 0009.
Tests global flags (--db, --artifact-dir, --config, --json, --help, --version),
task import, panel validate, audit group (invoke_without_command=True),
strict 0/1/2/3 exit code mapping, stdout JSON envelopes, and stderr diagnostics.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from verifierci import __version__
from verifierci.cli import audit_command, cli, main, render_diagnostic
from verifierci.errors import (
    ErrorCode,
    IdentityConflict,
    InfrastructureError,
    LeaseLost,
    ProtectionError,
    ValidationError,
)
from verifierci.models.protocol import AuditOptions

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
RETRY_PANEL = REPO_ROOT / "examples" / "retry-contract" / "panel.jsonl"


def _create_cli_task_fixture(root: Path, *, script_body: str = "") -> dict[str, Path]:
    """Create a complete local task, contract, snapshot, verifiers, and panel in root."""
    task_dir = root / "fixture_task"
    snap_dir = task_dir / "source"
    snap_dir.mkdir(parents=True)
    (snap_dir / "app.py").write_text("VALUE = 1\n", encoding="utf-8")

    runner_script = task_dir / "run_check.py"
    runner_script.write_text(
        script_body
        or (
            "import json, sys\n"
            "from pathlib import Path\n"
            "out = Path(sys.argv[1])\n"
            "data = {'tests': [{'nodeid': 'tests/test_app.py::test_ok', 'outcome': 'passed'}]}\n"
            "(out / 'report.json').write_text(json.dumps(data))\n"
        ),
        encoding="utf-8",
    )

    (task_dir / "contract.yaml").write_text(
        "schema_version: '1.0.0'\n"
        "task_id: cli-task\n"
        "version: '1.0.0'\n"
        "requirements:\n"
        "  - requirement_id: REQ-1\n"
        "    text: Return expected value\n",
        encoding="utf-8",
    )
    (task_dir / "environment.yaml").write_text(
        "schema_version: '1.0.0'\n"
        "environment_id: cli-env\n"
        "backend: fixture\n"
        "platform: darwin/arm64\n",
        encoding="utf-8",
    )
    (task_dir / "v1.yaml").write_text(
        f"verifier_id: cli-v1\n"
        f"version: '1.0.0'\n"
        f"mode: compatibility\n"
        f"command: ['{sys.executable}', '{runner_script}', '{{out}}']\n"
        f"expected_collection: ['tests/test_app.py::test_ok']\n"
        f"required_pass_ids: ['tests/test_app.py::test_ok']\n"
        f"allowed_edit_paths: ['*']\n"
        f"report_path: 'report.json'\n"
        f"timeout_seconds: 30\n",
        encoding="utf-8",
    )
    (task_dir / "v2.yaml").write_text(
        f"verifier_id: cli-v2\n"
        f"version: '1.0.0'\n"
        f"mode: compatibility\n"
        f"command: ['{sys.executable}', '{runner_script}', '{{out}}']\n"
        f"expected_collection: ['tests/test_app.py::test_ok']\n"
        f"required_pass_ids: ['tests/test_app.py::test_ok']\n"
        f"allowed_edit_paths: ['*']\n"
        f"report_path: 'report.json'\n"
        f"timeout_seconds: 30\n",
        encoding="utf-8",
    )
    task_file = task_dir / "task.yaml"
    task_file.write_text(
        "schema_version: '1.0.0'\n"
        "task_id: cli-task\n"
        "version: '1.0.0'\n"
        "statement: Simple CLI test task\n"
        "contract: contract.yaml\n"
        "environment: environment.yaml\n"
        "snapshot: source/\n"
        "verifier: v1.yaml\n",
        encoding="utf-8",
    )

    panel_file = root / "panel.jsonl"
    panel_file.write_text(
        json.dumps(
            {
                "panel_id": "cli-panel",
                "version": "1.0.0",
                "split": "development",
                "sampling_policy": "synthetic test panel",
                "cases": [
                    {
                        "case_id": "case-ref",
                        "role": "reference",
                        "source": "reference",
                        "diff": "",
                        "family_id": "fam-ref",
                        "adjudication": {
                            "label": "valid",
                            "review_status": "provisional",
                            "rationale": "reference case",
                        },
                    },
                    {
                        "case_id": "case-noop",
                        "role": "noop",
                        "source": "noop",
                        "diff": "",
                        "family_id": "fam-noop",
                        "adjudication": {
                            "label": "valid",
                            "review_status": "provisional",
                            "rationale": "noop control",
                        },
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    return {
        "task": task_file,
        "v1": task_dir / "v1.yaml",
        "v2": task_dir / "v2.yaml",
        "panel": panel_file,
    }


def test_cli_help_and_version_do_not_open_db(tmp_path: Path) -> None:
    runner = CliRunner()
    db_path = tmp_path / "should_not_exist.sqlite"

    res_help = runner.invoke(cli, ["--db", str(db_path), "--help"])
    assert res_help.exit_code == 0
    assert "audit" in res_help.output
    assert not db_path.exists()

    res_ver = runner.invoke(cli, ["--db", str(db_path), "--version"])
    assert res_ver.exit_code == 0
    assert f"verifierci {__version__}" in res_ver.output
    assert not db_path.exists()

    res_audit_help = runner.invoke(cli, ["audit", "--help"])
    assert res_audit_help.exit_code == 0
    assert "--trusted-fixture" in res_audit_help.output


def test_cli_syntax_error_maps_to_exit_2() -> None:
    runner = CliRunner()
    res = runner.invoke(cli, ["--nonexistent-global-flag"])
    assert res.exit_code == 2

    assert main(["--nonexistent-global-flag"]) == 2


def test_cli_missing_explicit_config_returns_exit_2(tmp_path: Path) -> None:
    runner = CliRunner()
    res = runner.invoke(
        cli,
        [
            "--config",
            str(tmp_path / "missing_config.yaml"),
            "--json",
            "panel",
            "validate",
            str(RETRY_PANEL),
        ],
    )
    assert res.exit_code == 2
    assert ErrorCode.VALIDATION_ERROR.value in res.stderr


def test_cli_task_import_dry_run_and_persist(tmp_path: Path) -> None:
    fixtures = _create_cli_task_fixture(tmp_path)
    runner = CliRunner()
    db_path = tmp_path / "state.sqlite"
    art_dir = tmp_path / "artifacts"
    out_dir = tmp_path / "tasks_out"

    # Dry run emits JSON and creates neither DB nor output files
    res_dry = runner.invoke(
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
            "cli-task",
            "--source",
            str(fixtures["task"]),
            "--source-revision",
            "v1",
            "--output-dir",
            str(out_dir),
            "--dry-run",
        ],
    )
    assert res_dry.exit_code == 0, res_dry.stderr
    dry_payload = json.loads(res_dry.stdout)
    assert dry_payload["schema_version"] == "1.0.0"
    assert dry_payload["kind"] == "TaskImportResult"
    assert dry_payload["data"]["task_key"] == "cli-task@1.0.0"
    assert dry_payload["data"]["dry_run"] is True
    assert not db_path.exists()
    assert not out_dir.exists()

    # Real import writes normalized outputs and DB
    res_real = runner.invoke(
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
            "cli-task",
            "--source",
            str(fixtures["task"]),
            "--source-revision",
            "v1",
            "--output-dir",
            str(out_dir),
        ],
    )
    assert res_real.exit_code == 0, res_real.stderr
    assert db_path.is_file()
    assert (out_dir / "cli-task" / "1.0.0" / "task.yaml").is_file()
    assert (out_dir / "cli-task" / "1.0.0" / "contract.json").is_file()
    assert (out_dir / "cli-task" / "1.0.0" / "snapshot-manifest.json").is_file()
    assert (out_dir / "cli-task" / "1.0.0" / "environment.json").is_file()


def test_cli_task_import_error_exit_codes(tmp_path: Path) -> None:
    fixtures = _create_cli_task_fixture(tmp_path)
    runner = CliRunner()

    # Unsupported adapter -> exit 2
    res_adapter = runner.invoke(
        cli,
        [
            "--json",
            "task",
            "import",
            "--adapter",
            "swebench",
            "--instance",
            "cli-task",
            "--source",
            str(fixtures["task"]),
            "--source-revision",
            "v1",
        ],
    )
    assert res_adapter.exit_code == 2
    assert ErrorCode.VALIDATION_ERROR.value in res_adapter.stderr

    # Symlink source -> exit 1 (ProtectionError)
    sym_task = tmp_path / "sym_task.yaml"
    sym_task.symlink_to(fixtures["task"])
    res_sym = runner.invoke(
        cli,
        [
            "--json",
            "task",
            "import",
            "--adapter",
            "local",
            "--instance",
            "cli-task",
            "--source",
            str(sym_task),
            "--source-revision",
            "v1",
        ],
    )
    assert res_sym.exit_code == 1
    assert ErrorCode.PROTECTION_ERROR.value in res_sym.stderr


def test_cli_panel_validate_modes(tmp_path: Path) -> None:
    runner = CliRunner()
    db_path = tmp_path / "panel_check.sqlite"

    # Valid panel with --json emits PanelValidationResult on stdout without creating DB
    res_ok = runner.invoke(
        cli,
        ["--db", str(db_path), "--json", "panel", "validate", str(RETRY_PANEL)],
    )
    assert res_ok.exit_code == 0, res_ok.stderr
    payload = json.loads(res_ok.stdout)
    assert payload["schema_version"] == "1.0.0"
    assert payload["kind"] == "PanelValidationResult"
    assert payload["data"]["panel_key"] == "retry-contract-panel@1.0.0"
    assert payload["data"]["case_count"] == 5
    assert payload["data"]["valid"] is True
    assert not db_path.exists()

    # Split mismatch -> exit 1 (ProtectionError)
    res_split = runner.invoke(
        cli,
        [
            "panel",
            "validate",
            str(RETRY_PANEL),
            "--expected-split",
            "assessment",
        ],
    )
    assert res_split.exit_code == 1
    assert ErrorCode.PROTECTION_ERROR.value in res_split.stderr

    # Provisional panel with --require-independent -> exit 2 (ValidationError)
    res_ind = runner.invoke(
        cli,
        ["panel", "validate", str(RETRY_PANEL), "--require-independent"],
    )
    assert res_ind.exit_code == 2
    assert ErrorCode.VALIDATION_ERROR.value in res_ind.stderr

    # Missing referenced artifacts with --verify-artifacts -> exit 3 (InfrastructureError)
    res_art = runner.invoke(
        cli,
        ["panel", "validate", str(RETRY_PANEL), "--verify-artifacts"],
    )
    assert res_art.exit_code == 3
    assert ErrorCode.INFRASTRUCTURE_ERROR.value in res_art.stderr

    # Lineage cycle -> exit 2
    cyclic_panel = tmp_path / "cyclic.jsonl"
    cyclic_panel.write_text(
        json.dumps(
            {
                "panel_id": "cyc",
                "version": "1.0.0",
                "split": "development",
                "cases": [
                    {
                        "case_id": "c1",
                        "role": "challenge",
                        "source": "human",
                        "family_id": "f1",
                        "parent_case_ids": ["c2"],
                        "adjudication": {
                            "label": "valid",
                            "review_status": "independent",
                            "rationale": "ok",
                        },
                    },
                    {
                        "case_id": "c2",
                        "role": "challenge",
                        "source": "human",
                        "family_id": "f1",
                        "parent_case_ids": ["c1"],
                        "adjudication": {
                            "label": "valid",
                            "review_status": "independent",
                            "rationale": "ok",
                        },
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    res_cyc = runner.invoke(cli, ["panel", "validate", str(cyclic_panel)])
    assert res_cyc.exit_code == 2


def test_cli_audit_validation_and_dry_run(tmp_path: Path) -> None:
    fixtures = _create_cli_task_fixture(tmp_path)
    runner = CliRunner()
    db_path = tmp_path / "audit_dry.sqlite"

    # Fixture backend without --trusted-fixture -> exit 1
    res_untrusted = runner.invoke(
        cli,
        [
            "audit",
            "--task",
            str(fixtures["task"]),
            "--panel",
            str(fixtures["panel"]),
            "--baseline",
            str(fixtures["v1"]),
            "--candidate",
            str(fixtures["v2"]),
            "--backend",
            "fixture",
            "--diagnostic",
            "--collect-only",
        ],
    )
    assert res_untrusted.exit_code == 1
    assert ErrorCode.PROTECTION_ERROR.value in res_untrusted.stderr

    # Docker backend in Phase 1 -> exit 2
    res_docker = runner.invoke(
        cli,
        [
            "audit",
            "--task",
            str(fixtures["task"]),
            "--panel",
            str(fixtures["panel"]),
            "--baseline",
            str(fixtures["v1"]),
            "--candidate",
            str(fixtures["v2"]),
            "--backend",
            "docker",
            "--collect-only",
        ],
    )
    assert res_docker.exit_code == 2

    # Dry run with --json emits AuditDryRun without DB creation
    res_dry = runner.invoke(
        cli,
        [
            "--db",
            str(db_path),
            "--json",
            "audit",
            "--task",
            str(fixtures["task"]),
            "--panel",
            str(fixtures["panel"]),
            "--baseline",
            str(fixtures["v1"]),
            "--candidate",
            str(fixtures["v2"]),
            "--backend",
            "fixture",
            "--trusted-fixture",
            "--diagnostic",
            "--collect-only",
            "--repetitions",
            "2",
            "--dry-run",
        ],
    )
    assert res_dry.exit_code == 0, res_dry.stderr
    dry_data = json.loads(res_dry.stdout)
    assert dry_data["schema_version"] == "1.0.0"
    assert dry_data["kind"] == "AuditDryRun"
    assert dry_data["data"]["max_repetitions"] == 2
    assert dry_data["data"]["gate_state"] is None
    assert not db_path.exists()


def test_cli_audit_end_to_end_collect_only(tmp_path: Path) -> None:
    fixtures = _create_cli_task_fixture(tmp_path)
    runner = CliRunner()
    db_path = tmp_path / "state.sqlite"
    art_dir = tmp_path / "artifacts"
    out_dir = tmp_path / "run_out"

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
            str(fixtures["task"]),
            "--panel",
            str(fixtures["panel"]),
            "--baseline",
            str(fixtures["v1"]),
            "--candidate",
            str(fixtures["v2"]),
            "--backend",
            "fixture",
            "--trusted-fixture",
            "--diagnostic",
            "--collect-only",
            "--repetitions",
            "2",
            "--output-dir",
            str(out_dir),
        ],
    )
    assert res.exit_code == 0, res.stderr

    payload = json.loads(res.stdout)
    assert payload["schema_version"] == "1.0.0"
    assert payload["kind"] == "AuditResult"
    assert payload["data"]["gate"] is None
    assert payload["data"]["matrix"]["complete"] is True
    # 1 task * 2 cases * 2 verifiers = 4 cells, each with 2 repetitions
    cells = payload["data"]["matrix"]["cells"]
    assert len(cells) == 4
    assert all(c["outcome"] == "accept" for c in cells)
    assert (out_dir / "report.json").is_file()
    assert (out_dir / "summary.txt").is_file()
    assert (out_dir / "manifest.json").is_file()


def test_audit_command_exit_category_mapping_and_diagnostics() -> None:
    opts = AuditOptions(
        task_files=("t.yaml",),
        benchmark_file=None,
        panel_file="p.jsonl",
        baseline_file="b.yaml",
        candidate_file="c.yaml",
        repetitions=3,
        backend="fixture",
        trusted_fixture=True,
        sandbox_policy_file="s.yaml",
        max_attempts=3,
        offline=True,
        output_dir=None,
        dry_run=True,
        resume_run_id=None,
        parent_run_id=None,
        policy_file="p.yaml",
        analysis_plan_file=None,
        max_jobs=100,
        concurrency=1,
        timeout_seconds=60,
        seed=None,
        collect_only=True,
        diagnostic=True,
    )

    for exc, expected_exit in (
        (ProtectionError("blocked"), 1),
        (ValidationError("bad input"), 2),
        (IdentityConflict("conflict"), 2),
        (InfrastructureError("io fail"), 3),
        (LeaseLost("lost"), 3),
        (RuntimeError("unexpected"), 3),
    ):
        with patch("verifierci.cli.execute_audit_pipeline", side_effect=exc):
            assert audit_command(opts, json_output=True) == expected_exit

    diag_json = json.loads(
        render_diagnostic("VALIDATION_ERROR", "bad flag", json_output=True)
    )
    assert diag_json["kind"] == "Diagnostic"
    assert diag_json["data"] == {"code": "VALIDATION_ERROR", "message": "bad flag"}
    assert (
        render_diagnostic("VALIDATION_ERROR", "bad flag", json_output=False)
        == "[VALIDATION_ERROR] bad flag"
    )
