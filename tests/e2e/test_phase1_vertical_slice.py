"""End-to-end verification of the Phase 1 Minimal Vertical Slice (SDD §1.3 & §13).

Exercises the complete canonical retry-contract fixture (1 task × 5 patch cases ×
2 verifiers × 3 repetitions = 30 scheduled evaluations) through the CLI:
1. task import
2. panel validate --verify-artifacts
3. audit --backend fixture --trusted-fixture --diagnostic --collect-only --repetitions 3
4. Trusted fixture digest tampering rejection via SnapshotRegistry
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from click.testing import CliRunner

from verifierci.cli import cli
from verifierci.errors import ErrorCode, ProtectionError
from verifierci.snapshots.registry import SnapshotRegistry

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
RETRY_DIR = REPO_ROOT / "examples" / "retry-contract"
SAMPLE_PANEL = REPO_ROOT / "datasets" / "sample-panels" / "sample-five-case.jsonl"


def test_phase1_retry_contract_vertical_slice_e2e(tmp_path: Path) -> None:
    runner = CliRunner()
    db_path = tmp_path / "phase1.sqlite"
    art_dir = tmp_path / "artifacts"
    import_dir = tmp_path / "imported_tasks"
    out_dir = tmp_path / "audit_out"

    # 1. Task import
    res_import = runner.invoke(
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
            str(import_dir),
        ],
    )
    assert res_import.exit_code == 0, res_import.stderr
    imp_payload = json.loads(res_import.stdout)
    assert imp_payload["kind"] == "TaskImportResult"
    assert imp_payload["data"]["task_key"] == "retry-contract@1.0.0"
    assert imp_payload["data"]["requirements_count"] == 4

    # 2. Panel validate with artifact verification (and sample panel check)
    for panel_path in (RETRY_DIR / "panel.jsonl", SAMPLE_PANEL):
        res_panel = runner.invoke(
            cli,
            [
                "--json",
                "panel",
                "validate",
                str(panel_path),
                "--expected-split",
                "development",
                "--verify-artifacts",
            ],
        )
        assert res_panel.exit_code == 0, res_panel.stderr
        p_payload = json.loads(res_panel.stdout)
        assert p_payload["kind"] == "PanelValidationResult"
        assert p_payload["data"]["valid"] is True
        assert p_payload["data"]["case_count"] == 5

    # 3. Full 30-job audit vertical slice
    res_audit = runner.invoke(
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
    assert res_audit.exit_code == 0, res_audit.stderr

    audit_payload = json.loads(res_audit.stdout)
    assert audit_payload["kind"] == "AuditResult"
    data = audit_payload["data"]
    assert data["gate"] is None
    assert data["matrix"]["complete"] is True
    assert any("synthetic=True" in d or "provisional" in d for d in data["diagnostics"])

    # Verify exact 10 cells (5 cases * 2 verifiers) and 3 repetitions per cell = 30 jobs
    cells = {(c["case_id"], c["verifier_key"]): c for c in data["matrix"]["cells"]}
    assert len(cells) == 10
    expected_outcomes = {
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
    for key, exp_outcome in expected_outcomes.items():
        cell = cells[key]
        assert cell["outcome"] == exp_outcome, f"Mismatch for {key}: {cell}"
        assert cell["evaluation_validity"] == "valid"
        assert cell["planned_repetitions"] == 3
        assert cell["repetition_outcomes"] == [exp_outcome, exp_outcome, exp_outcome]

    # Verify SQLite job & attempt totals
    conn = sqlite3.connect(db_path)
    try:
        run_id = data["manifest"]["run_id"]
        job_count = conn.execute(
            "SELECT COUNT(*) FROM jobs WHERE run_id = ? AND state = 'DONE'",
            (run_id,),
        ).fetchone()[0]
        attempt_count = conn.execute(
            "SELECT COUNT(*) FROM evaluation_attempts a JOIN jobs j ON a.job_id = j.job_id WHERE j.run_id = ?",
            (run_id,),
        ).fetchone()[0]
        assert job_count == 30
        assert attempt_count == 30
    finally:
        conn.close()

    # Verify atomic report outputs on disk match stdout envelope
    report_disk = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
    assert report_disk["data"]["matrix"]["matrix_id"] == data["matrix"]["matrix_id"]
    assert (out_dir / "summary.txt").is_file()
    assert (out_dir / "manifest.json").is_file()


def test_trusted_fixture_registry_rejects_digest_mismatch() -> None:
    registry = SnapshotRegistry.from_manifests_dir()
    record = registry.get("retry-contract@1.0.0")
    assert record is not None
    assert record.synthetic is True
    assert record.review_status == "provisional"

    try:
        registry.verify_fixture(
            task_key=record.task_key,
            contract_hash=record.contract_hash,
            snapshot_digest="f" * 64,
            panel_key=record.panel_key,
            verifier_digests={},
            case_diff_digests={},
        )
        raise AssertionError("Expected ProtectionError on snapshot digest mismatch")
    except ProtectionError as exc:
        assert exc.code == ErrorCode.DIGEST_MISMATCH.value
