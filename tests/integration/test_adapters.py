"""Integration tests for LocalAdapter.

SDD Section 4.3, 4.4, and 7:
Tests LocalAdapter integration on:
- Valid manifests and full ImportBundle construction
- Missing file and reference detection
- Oversized manifest and reference file bounds (2 MiB limit)
- Symlink rejections across manifest, contracts, verifiers, requirements, and snapshots
- Directory traversal defenses
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from verifierci.adapters.local import LocalAdapter
from verifierci.errors import ErrorCode, ProtectionError, ValidationError
from verifierci.models.protocol import ImportBundle, ImportRequest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CONTRACT_TASK_YAML = REPO_ROOT / "examples" / "retry-contract" / "task.yaml"


def _create_minimal_task_dir(root: Path) -> Path:
    """Create a minimal valid task manifest and referenced files in root."""
    task_file = root / "task.yaml"
    contract_file = root / "contract.yaml"
    env_file = root / "environment.yaml"
    ver_file = root / "verifier.yaml"
    snap_dir = root / "snapshot"
    snap_dir.mkdir(parents=True, exist_ok=True)
    (snap_dir / "main.py").write_text("print('hello')\n")

    task_file.write_text(
        """schema_version: '1.0.0'
task:
  task_id: test-task
  version: 1.0.0
  statement: Test task statement
  licence: Apache-2.0
  provenance: native-local
  eligibility: eligible
contract: contract.yaml
environment: environment.yaml
snapshot: snapshot
verifier: verifier.yaml
"""
    )

    contract_file.write_text(
        """schema_version: '1.0.0'
task_id: test-task
version: 1.0.0
allowed_variation: none
unresolved_questions: []
requirements:
  - requirement_id: req-1
    statement: Requirement 1
"""
    )

    env_file.write_text(
        """schema_version: '1.0.0'
environment_id: env-test
backend: fixture
platform: darwin/arm64
recipe: "base"
lock_digests: []
service_manifests: {}
resource_policy: {}
mirror_uris: []
"""
    )

    ver_file.write_text(
        """schema_version: '1.0.0'
verifier_id: ver-test
version: 1.0.0
manifest:
  mode: compatibility
  command: ["python", "-m", "pytest"]
  build_command: []
  expected_collection: ["test_1"]
  parser_id: pytest-report-v1
  report_path: report.json
  payload: snapshot
  allowed_edit_paths: ["*"]
  required_pass_ids: []
  permitted_skips: []
  timeout_seconds: 30
compatible_contract_hashes: []
"""
    )

    return task_file


def test_local_adapter_valid_manifest_import(tmp_path: Path) -> None:
    """Test importing a valid local manifest produces a complete typed ImportBundle."""
    adapter = LocalAdapter()

    # 1. Test example contract task
    req_example = ImportRequest(
        adapter="local",
        instance="retry-contract",
        source=str(CONTRACT_TASK_YAML),
        source_revision="v1",
        environment_manifest=None,
        output_dir=str(tmp_path / "out1"),
        dry_run=True,
    )
    bundle_example = adapter.import_task(req_example)
    assert isinstance(bundle_example, ImportBundle)
    assert bundle_example.task.task_id == "retry-contract"
    assert len(bundle_example.requirements) == 4
    assert bundle_example.verifier.verifier_id == "retry-contract-v1"

    # 2. Test generated minimal task
    task_file = _create_minimal_task_dir(tmp_path / "pkg")
    req_pkg = ImportRequest(
        adapter="local",
        instance="test-task",
        source=str(task_file),
        source_revision="1.0.0",
        environment_manifest=None,
        output_dir=str(tmp_path / "out2"),
        dry_run=True,
    )
    bundle_pkg = adapter.import_task(req_pkg)
    assert isinstance(bundle_pkg, ImportBundle)
    assert bundle_pkg.task.task_id == "test-task"
    assert bundle_pkg.contract.task_id == "test-task"
    assert len(bundle_pkg.requirements) == 1
    assert bundle_pkg.requirements[0].requirement_id == "req-1"
    assert bundle_pkg.verifier.verifier_id == "ver-test"
    assert bundle_pkg.verifier_manifest.parser_id == "pytest-report-v1"


def test_local_adapter_missing_references(tmp_path: Path) -> None:
    """Test that missing referenced files raise ValidationError."""
    adapter = LocalAdapter()
    task_dir = tmp_path / "missing_refs"
    task_dir.mkdir()
    task_file = _create_minimal_task_dir(task_dir)

    # Missing contract
    (task_dir / "contract.yaml").unlink()
    req = ImportRequest(
        adapter="local",
        instance="test-task",
        source=str(task_file),
        source_revision="1.0.0",
        environment_manifest=None,
        output_dir=str(tmp_path / "out"),
        dry_run=True,
    )
    with pytest.raises(ValidationError) as exc:
        adapter.import_task(req)
    assert exc.value.code == ErrorCode.VALIDATION_ERROR.value
    assert "contract.yaml" in str(exc.value)

    # Re-create contract, but delete verifier
    task_file = _create_minimal_task_dir(task_dir)
    (task_dir / "verifier.yaml").unlink()
    with pytest.raises(ValidationError) as exc:
        adapter.import_task(req)
    assert exc.value.code == ErrorCode.VALIDATION_ERROR.value
    assert "verifier.yaml" in str(exc.value)

    # Re-create, but delete environment
    task_file = _create_minimal_task_dir(task_dir)
    (task_dir / "environment.yaml").unlink()
    with pytest.raises(ValidationError) as exc:
        adapter.import_task(req)
    assert exc.value.code == ErrorCode.VALIDATION_ERROR.value
    assert "environment.yaml" in str(exc.value)


def test_local_adapter_oversized_files(tmp_path: Path) -> None:
    """Test that files exceeding 2 MiB bound raise ValidationError with ARTIFACT_LIMIT."""
    adapter = LocalAdapter()
    task_dir = tmp_path / "oversized"
    task_dir.mkdir()
    task_file = _create_minimal_task_dir(task_dir)

    # Oversized task.yaml (> 2 MiB)
    with task_file.open("ab") as f:
        f.write(b"# padding\n" + b"# " * (2 * 1024 * 1024))

    req = ImportRequest(
        adapter="local",
        instance="test-task",
        source=str(task_file),
        source_revision="1.0.0",
        environment_manifest=None,
        output_dir=str(tmp_path / "out"),
        dry_run=True,
    )
    with pytest.raises(ValidationError) as exc:
        adapter.import_task(req)
    assert exc.value.code == ErrorCode.ARTIFACT_LIMIT.value

    # Reset task.yaml, make contract.yaml oversized
    task_file = _create_minimal_task_dir(task_dir)
    contract_file = task_dir / "contract.yaml"
    with contract_file.open("ab") as f:
        f.write(b"# padding\n" + b"# " * (2 * 1024 * 1024))

    with pytest.raises(ValidationError) as exc:
        adapter.import_task(req)
    assert exc.value.code == ErrorCode.ARTIFACT_LIMIT.value


def test_local_adapter_symlink_rejections(tmp_path: Path) -> None:
    """Test that symlinks across manifests, contracts, verifiers, and snapshots are rejected."""
    adapter = LocalAdapter()
    task_dir = tmp_path / "symlinks"
    task_dir.mkdir()
    task_file = _create_minimal_task_dir(task_dir)

    # 1. Manifest itself is a symlink
    symlink_task = task_dir / "symlink_task.yaml"
    os.symlink(task_file, symlink_task)
    req_symlink = ImportRequest(
        adapter="local",
        instance="test-task",
        source=str(symlink_task),
        source_revision="1.0.0",
        environment_manifest=None,
        output_dir=str(tmp_path / "out"),
        dry_run=True,
    )
    with pytest.raises(ProtectionError) as exc:
        adapter.import_task(req_symlink)
    assert exc.value.code == ErrorCode.PROTECTION_ERROR.value
    assert "Symlink rejected" in str(exc.value)

    # 2. Referenced contract is a symlink
    req_normal = ImportRequest(
        adapter="local",
        instance="test-task",
        source=str(task_file),
        source_revision="1.0.0",
        environment_manifest=None,
        output_dir=str(tmp_path / "out"),
        dry_run=True,
    )
    contract_file = task_dir / "contract.yaml"
    target_contract = task_dir / "real_contract.yaml"
    contract_file.rename(target_contract)
    os.symlink(target_contract, contract_file)

    with pytest.raises(ProtectionError) as exc:
        adapter.import_task(req_normal)
    assert exc.value.code == ErrorCode.PROTECTION_ERROR.value

    # 3. Referenced verifier is a symlink
    _create_minimal_task_dir(task_dir)
    verifier_file = task_dir / "verifier.yaml"
    target_ver = task_dir / "real_verifier.yaml"
    verifier_file.rename(target_ver)
    os.symlink(target_ver, verifier_file)

    with pytest.raises(ProtectionError) as exc:
        adapter.import_task(req_normal)
    assert exc.value.code == ErrorCode.PROTECTION_ERROR.value

    # 4. Referenced snapshot is a symlink
    _create_minimal_task_dir(task_dir)
    snap_dir = task_dir / "snapshot"
    target_snap = task_dir / "real_snapshot"
    snap_dir.rename(target_snap)
    os.symlink(target_snap, snap_dir)

    with pytest.raises(ProtectionError) as exc:
        adapter.import_task(req_normal)
    assert exc.value.code == ErrorCode.PROTECTION_ERROR.value


def test_local_adapter_directory_traversal_rejections(tmp_path: Path) -> None:
    """Test that path traversal attempts escaping the root directory are rejected."""
    adapter = LocalAdapter()
    task_dir = tmp_path / "traversal"
    task_dir.mkdir()
    task_file = _create_minimal_task_dir(task_dir)

    # Escape via contract reference: ../outside_contract.yaml
    task_file.write_text(
        """schema_version: '1.0.0'
task:
  task_id: test-task
  version: 1.0.0
  statement: Test task statement
  licence: Apache-2.0
  provenance: native-local
  eligibility: eligible
contract: ../outside_contract.yaml
environment: environment.yaml
snapshot: snapshot
verifier: verifier.yaml
"""
    )
    req = ImportRequest(
        adapter="local",
        instance="test-task",
        source=str(task_file),
        source_revision="1.0.0",
        environment_manifest=None,
        output_dir=str(tmp_path / "out"),
        dry_run=True,
    )
    with pytest.raises(ProtectionError) as exc:
        adapter.import_task(req)
    assert exc.value.code == ErrorCode.PROTECTION_ERROR.value
    assert "Directory traversal" in str(exc.value)
