"""Unit tests for task adapters (LocalAdapter, RestrictedSafeLoader).

SDD Section 4.4 and Section 7.
Tests YAML parsing safety, depth limits, alias rejection, manifest import,
and bundle construction.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from verifierci.adapters.base import TaskAdapter
from verifierci.adapters.local import (
    LocalAdapter,
    _safe_load_yaml,
    read_local_manifest,
)
from verifierci.errors import ErrorCode, ProtectionError, ValidationError
from verifierci.models.protocol import ImportBundle, ImportRequest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CONTRACT_TASK_YAML = REPO_ROOT / "examples" / "retry-contract" / "task.yaml"


def test_local_adapter_satisfies_protocol() -> None:
    adapter = LocalAdapter()
    assert isinstance(adapter, TaskAdapter)
    assert adapter.name == "local"


def test_import_task_success() -> None:
    adapter = LocalAdapter()
    req = ImportRequest(
        adapter="local",
        instance="retry-contract",
        source=str(CONTRACT_TASK_YAML),
        source_revision="v1",
        environment_manifest=None,
        output_dir="/tmp/out",
        dry_run=True,
    )
    bundle = adapter.import_task(req)
    assert isinstance(bundle, ImportBundle)
    assert bundle.task.task_id == "retry-contract"
    assert bundle.contract.task_id == "retry-contract"
    assert len(bundle.requirements) == 4
    assert isinstance(bundle.controls, tuple)
    assert bundle.verifier.verifier_id == "retry-contract-v1"
    assert bundle.verifier_manifest.parser_id == "pytest-report-v1"


def test_read_manifest_missing_file() -> None:
    with pytest.raises(ValidationError) as exc:
        read_local_manifest(Path("/nonexistent/path/task.yaml"))
    assert exc.value.code == ErrorCode.VALIDATION_ERROR.value


def test_yaml_size_limit() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        big_file = Path(tmpdir) / "big.yaml"
        # Write over 2 MiB
        big_file.write_bytes(b"a: 1\n" * 600_000)
        with pytest.raises(ValidationError) as exc:
            _safe_load_yaml(big_file)
        assert exc.value.code == ErrorCode.ARTIFACT_LIMIT.value


def test_yaml_alias_rejected() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        alias_file = Path(tmpdir) / "alias.yaml"
        alias_file.write_text("item: &anchor val\nref: *anchor\n")
        with pytest.raises(ValidationError) as exc:
            _safe_load_yaml(alias_file)
        assert exc.value.code == ErrorCode.VALIDATION_ERROR.value
        assert "anchors" in str(exc.value)


def test_yaml_depth_limit() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        depth_file = Path(tmpdir) / "deep.yaml"
        # 35 levels of nesting
        content = (
            "a:\n" + "".join("  " * i + "a:\n" for i in range(1, 35)) + "    val: 1\n"
        )
        depth_file.write_text(content)
        with pytest.raises(ValidationError) as exc:
            _safe_load_yaml(depth_file)
        assert exc.value.code == ErrorCode.VALIDATION_ERROR.value
        assert "depth" in str(exc.value)


def test_manifest_missing_task_section() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        bad_file = Path(tmpdir) / "task.yaml"
        bad_file.write_text("schema_version: '1.0.0'\n")
        with pytest.raises(ValidationError) as exc:
            read_local_manifest(bad_file)
        assert "task" in str(exc.value)


def test_manifest_path_traversal() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        bad_file = Path(tmpdir) / "task.yaml"
        bad_file.write_text(
            """schema_version: '1.0.0'
task:
  task_id: test
  version: 1.0.0
  statement: statement
  licence: MIT
  provenance: local
  eligibility: eligible
contract: ../outside_contract.json
snapshot: snapshot.json
environment: environment.json
verifier: verifier.json
"""
        )
        with pytest.raises(ProtectionError) as exc:
            read_local_manifest(bad_file)
        assert exc.value.code == ErrorCode.PROTECTION_ERROR.value


def test_adapter_supports_and_versions() -> None:
    adapter = LocalAdapter()
    assert adapter.supports("my-task") is True
    assert adapter.supports("") is False
    assert adapter.supported_source_version("1.0") is True
    assert adapter.supported_source_version("1.0.0") is True
    assert adapter.supported_source_version("2.0.0") is False


def test_adapter_validate_environment() -> None:
    adapter = LocalAdapter()
    req = ImportRequest(
        adapter="local",
        instance="retry-contract",
        source=str(CONTRACT_TASK_YAML),
        source_revision="v1",
        environment_manifest=None,
        output_dir="/tmp/out",
        dry_run=True,
    )
    bundle = adapter.import_task(req)
    # Valid environment passes
    adapter.validate_environment(bundle)

    # Corrupt environment backend
    import dataclasses

    bad_env = dataclasses.replace(bundle.environment, backend="invalid_backend")  # type: ignore[arg-type]
    bad_bundle = dataclasses.replace(bundle, environment=bad_env)
    with pytest.raises(ValidationError):
        adapter.validate_environment(bad_bundle)


def test_manifest_non_dict() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir) / "list.yaml"
        p.write_text("- item1\n- item2\n")
        with pytest.raises(ValidationError) as exc:
            read_local_manifest(p)
        assert exc.value.code == ErrorCode.VALIDATION_ERROR.value


def test_manifest_yaml_syntax_error() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir) / "syntax.yaml"
        p.write_text("key: [unclosed list\n")
        with pytest.raises(ValidationError) as exc:
            read_local_manifest(p)
        assert exc.value.code == ErrorCode.VALIDATION_ERROR.value


def test_manifest_symlink_rejected() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        real_file = Path(tmpdir) / "real.yaml"
        real_file.write_text("schema_version: '1.0.0'\n")
        link_file = Path(tmpdir) / "link.yaml"
        link_file.symlink_to(real_file)
        with pytest.raises(ProtectionError) as exc:
            _safe_load_yaml(link_file)
        assert exc.value.code == ErrorCode.PROTECTION_ERROR.value


def test_import_task_with_control_files() -> None:
    adapter = LocalAdapter()
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        snap = root / "source"
        snap.mkdir()
        (snap / "f.py").write_text("a = 1\n")

        req_dir = root / "requirements"
        req_dir.mkdir()
        (req_dir / "r1.yaml").write_text(
            "requirement_id: r1\ntext: test\nsource_kind: explicit\nsource_locator: loc\nallowed_variation: none\n"
        )

        ctrl_dir = root / "controls"
        ctrl_dir.mkdir()
        (ctrl_dir / "c1.diff").write_text(
            "--- a/f.py\n+++ b/f.py\n@@ -1 +1 @@\n-a = 1\n+a = 2\n"
        )

        (root / "contract.yaml").write_text(
            "version: '1.0.0'\nrequirement_files: [requirements/r1.yaml]\nallowed_variation: none\n"
        )
        (root / "environment.yaml").write_text(
            "backend: fixture\nplatform: darwin/arm64\nrecipe: none\nruntime_fingerprint: py\nresource_policy: pol\n"
        )
        (root / "v1.yaml").write_text(
            "mode: compatibility\ncommand: [python]\nparser_id: pytest-report-v1\nreport_path: rep.json\nallowed_edit_paths: ['*']\ntimeout_seconds: 30\n"
        )

        task_yaml = root / "task.yaml"
        task_yaml.write_text(
            """schema_version: '1.0.0'
task_id: sample-task
version: '1.0.0'
statement: do something
licence: MIT
provenance: local
eligibility: eligible
contract_file: contract.yaml
snapshot_file: source/
environment_file: environment.yaml
verifier_file: v1.yaml
control_files:
  - controls/c1.diff
"""
        )
        req = ImportRequest(
            adapter="local",
            instance="sample-task",
            source=str(task_yaml),
            source_revision="v1",
            environment_manifest=None,
            output_dir=str(root / "out"),
            dry_run=True,
        )
        bundle = adapter.import_task(req)
        assert len(bundle.controls) == 1
        assert bundle.controls[0].case_id == "sample-task-ctrl-c1"


def test_import_task_invalid_requirements() -> None:
    adapter = LocalAdapter()
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        snap = root / "source"
        snap.mkdir()

        # contract with non-list requirements
        (root / "contract.yaml").write_text(
            "version: '1.0.0'\nrequirements: not-a-list\n"
        )
        (root / "v1.yaml").write_text(
            "mode: compatibility\ncommand: [python]\nparser_id: pytest-report-v1\nreport_path: rep.json\n"
        )
        task_yaml = root / "task.yaml"
        task_yaml.write_text(
            """schema_version: '1.0.0'
task_id: req-task
version: '1.0.0'
statement: do something
licence: MIT
provenance: local
eligibility: eligible
contract_file: contract.yaml
snapshot_file: source/
verifier_file: v1.yaml
"""
        )
        req = ImportRequest(
            adapter="local",
            instance="req-task",
            source=str(task_yaml),
            source_revision="v1",
            environment_manifest=None,
            output_dir=str(root / "out"),
            dry_run=True,
        )
        with pytest.raises(ValidationError) as exc:
            adapter.import_task(req)
        assert "requirements' must be a list" in str(exc.value)

        # contract with non-mapping requirement entry
        (root / "contract.yaml").write_text(
            "version: '1.0.0'\nrequirements: ['not-a-map']\n"
        )
        with pytest.raises(ValidationError) as exc2:
            adapter.import_task(req)
        assert "Each requirement entry must be a mapping" in str(exc2.value)


def test_import_task_environment_file_fallback() -> None:
    adapter = LocalAdapter()
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        snap = root / "source"
        snap.mkdir()
        (root / "contract.yaml").write_text("version: '1.0.0'\nrequirements: []\n")
        (root / "env.yaml").write_text("backend: fixture\nplatform: linux/amd64\n")
        (root / "v1.yaml").write_text(
            "mode: compatibility\ncommand: [python]\nparser_id: pytest-report-v1\nreport_path: rep.json\n"
        )
        task_yaml = root / "task.yaml"
        # Inline environment is not a mapping (e.g., string or None)
        task_yaml.write_text(
            """schema_version: '1.0.0'
task_id: env-task
version: '1.0.0'
statement: do something
licence: MIT
provenance: local
eligibility: eligible
contract_file: contract.yaml
snapshot_file: source/
environment: "invalid-string-not-map"
environment_file: env.yaml
verifier_file: v1.yaml
"""
        )
        req = ImportRequest(
            adapter="local",
            instance="env-task",
            source=str(task_yaml),
            source_revision="v1",
            environment_manifest=None,
            output_dir=str(root / "out"),
            dry_run=True,
        )
        bundle = adapter.import_task(req)
        assert bundle.environment.platform == "linux/amd64"


def test_import_task_unsupported_backend() -> None:
    adapter = LocalAdapter()
    with tempfile.TemporaryDirectory() as tmpdir:
        td = Path(tmpdir)
        task_f = td / "task.yaml"
        task_f.write_text(
            "task_id: t1\n"
            "version: '1.0'\n"
            "environment:\n"
            "  backend: custom_backend\n"
            "contract: contract.yaml\n"
            "snapshot: source/\n"
            "verifier: v1.yaml\n"
        )
        (td / "contract.yaml").write_text("requirements: []\n")
        (td / "source").mkdir()
        (td / "v1.yaml").write_text("command: [pytest]\n")
        req = ImportRequest(
            adapter="local",
            instance="t1",
            source=str(task_f),
            source_revision="v1",
            environment_manifest=None,
            output_dir=str(td / "out"),
            dry_run=True,
        )
        with pytest.raises(ValidationError) as exc:
            adapter.import_task(req)
        assert "custom_backend" in str(exc.value)


def test_manifest_absolute_path_rejected() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        td = Path(tmpdir)
        bad_file = td / "task.yaml"
        bad_file.write_text(
            """schema_version: '1.0.0'
task_id: test
version: 1.0.0
statement: statement
licence: MIT
provenance: local
eligibility: eligible
contract: /etc/passwd
snapshot: source/
environment: environment.yaml
verifier: v1.yaml
"""
        )
        with pytest.raises(ProtectionError) as exc:
            read_local_manifest(bad_file)
        assert exc.value.code == ErrorCode.PROTECTION_ERROR.value
        assert "Absolute paths are prohibited" in str(exc.value)


def test_manifest_intermediate_symlink_rejected() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        td = Path(tmpdir)
        real_sub = td / "real_sub"
        real_sub.mkdir()
        (real_sub / "c.yaml").write_text("requirements: []\n")

        sym_sub = td / "sym_sub"
        sym_sub.symlink_to(real_sub)

        bad_file = td / "task.yaml"
        bad_file.write_text(
            """schema_version: '1.0.0'
task_id: test
version: 1.0.0
statement: statement
licence: MIT
provenance: local
eligibility: eligible
contract: sym_sub/c.yaml
snapshot: source/
environment: environment.yaml
verifier: v1.yaml
"""
        )
        with pytest.raises(ProtectionError) as exc:
            read_local_manifest(bad_file)
        assert exc.value.code == ErrorCode.PROTECTION_ERROR.value
        assert "Symlinks are prohibited" in str(exc.value)


def test_import_task_symlink_manifest_rejected() -> None:
    adapter = LocalAdapter()
    with tempfile.TemporaryDirectory() as tmpdir:
        td = Path(tmpdir)
        real_manifest = td / "real_task.yaml"
        real_manifest.write_text(
            "schema_version: '1.0.0'\ntask_id: t1\nstatement: s\ncontract: c.yaml\nsnapshot: s/\nverifier: v.yaml\n"
        )
        link_manifest = td / "link_task.yaml"
        link_manifest.symlink_to(real_manifest)

        req = ImportRequest(
            adapter="local",
            instance="t1",
            source=str(link_manifest),
            source_revision="v1",
            environment_manifest=None,
            output_dir=str(td / "out"),
            dry_run=True,
        )
        with pytest.raises(ProtectionError) as exc:
            adapter.import_task(req)
        assert exc.value.code == ErrorCode.PROTECTION_ERROR.value


def test_import_task_snapshot_symlink_rejected() -> None:
    adapter = LocalAdapter()
    with tempfile.TemporaryDirectory() as tmpdir:
        td = Path(tmpdir)
        snap = td / "source"
        snap.mkdir()
        outside_file = td / "outside.txt"
        outside_file.write_text("sensitive data\n")
        (snap / "link.txt").symlink_to(outside_file)

        (td / "contract.yaml").write_text("requirements: []\n")
        (td / "environment.yaml").write_text("backend: fixture\n")
        (td / "v1.yaml").write_text("command: [pytest]\n")
        task_f = td / "task.yaml"
        task_f.write_text(
            "schema_version: '1.0.0'\n"
            "task_id: t_snap\n"
            "version: '1.0.0'\n"
            "statement: s\n"
            "licence: MIT\n"
            "provenance: local\n"
            "contract: contract.yaml\n"
            "snapshot: source/\n"
            "verifier: v1.yaml\n"
        )

        req = ImportRequest(
            adapter="local",
            instance="t_snap",
            source=str(task_f),
            source_revision="v1",
            environment_manifest=None,
            output_dir=str(td / "out"),
            dry_run=True,
        )
        with pytest.raises(ProtectionError) as exc:
            adapter.import_task(req)
        assert exc.value.code == ErrorCode.PROTECTION_ERROR.value
        assert "Symlinks are prohibited in snapshot files" in str(exc.value)


def test_import_task_missing_and_oversized_control_file() -> None:
    adapter = LocalAdapter()
    with tempfile.TemporaryDirectory() as tmpdir:
        td = Path(tmpdir)
        (td / "source").mkdir()
        (td / "contract.yaml").write_text("requirements: []\n")
        (td / "environment.yaml").write_text("backend: fixture\n")
        (td / "v1.yaml").write_text("command: [pytest]\n")
        task_f = td / "task.yaml"
        task_f.write_text(
            "schema_version: '1.0.0'\n"
            "task_id: t_ctrl\n"
            "version: '1.0.0'\n"
            "statement: s\n"
            "contract: contract.yaml\n"
            "snapshot: source/\n"
            "verifier: v1.yaml\n"
            "control_files:\n"
            "  - missing.diff\n"
        )

        req = ImportRequest(
            adapter="local",
            instance="t_ctrl",
            source=str(task_f),
            source_revision="v1",
            environment_manifest=None,
            output_dir=str(td / "out"),
            dry_run=True,
        )
        with pytest.raises(ValidationError) as exc:
            adapter.import_task(req)
        assert "Control file not found" in str(exc.value)

        # Oversized control file (> 2 MiB)
        (td / "big.diff").write_bytes(b"diff content\n" * 200_000)
        task_f.write_text(
            "schema_version: '1.0.0'\n"
            "task_id: t_ctrl\n"
            "version: '1.0.0'\n"
            "statement: s\n"
            "contract: contract.yaml\n"
            "snapshot: source/\n"
            "verifier: v1.yaml\n"
            "control_files:\n"
            "  - big.diff\n"
        )
        with pytest.raises(ValidationError) as exc2:
            adapter.import_task(req)
        assert exc2.value.code == ErrorCode.ARTIFACT_LIMIT.value


def test_read_manifest_unsupported_schema_version() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        td = Path(tmpdir)
        task_f = td / "task.yaml"
        task_f.write_text(
            "schema_version: '9.9.9'\ntask_id: t1\nstatement: s\ncontract: c.yaml\nsnapshot: s/\nverifier: v.yaml\n"
        )
        with pytest.raises(ValidationError) as exc:
            read_local_manifest(task_f)
        assert "Unsupported local manifest schema version" in str(exc.value)


def test_import_task_modular_requirement_files() -> None:
    adapter = LocalAdapter()
    with tempfile.TemporaryDirectory() as tmpdir:
        td = Path(tmpdir)
        (td / "source").mkdir()
        reqs_dir = td / "requirements"
        reqs_dir.mkdir()
        (reqs_dir / "r1.yaml").write_text(
            "requirement_id: REQ-1\ntext: Must succeed\nsource_kind: explicit\n"
        )
        (reqs_dir / "r2.yaml").write_text(
            "requirement_id: REQ-2\ntext: Must be fast\nsource_kind: explicit\n"
        )
        (td / "contract.yaml").write_text(
            "requirements:\n"
            "  - requirement_id: REQ-0\n    text: Base req\n"
            "requirement_files:\n"
            "  - requirements/r1.yaml\n"
            "  - requirements/r2.yaml\n"
        )
        (td / "environment.yaml").write_text("backend: fixture\n")
        (td / "v1.yaml").write_text("command: [pytest]\n")
        task_f = td / "task.yaml"
        task_f.write_text(
            "schema_version: '1.0.0'\n"
            "task_id: t_reqs\n"
            "version: '1.0.0'\n"
            "statement: s\n"
            "contract: contract.yaml\n"
            "snapshot: source/\n"
            "verifier: v1.yaml\n"
        )

        req = ImportRequest(
            adapter="local",
            instance="t_reqs",
            source=str(task_f),
            source_revision="v1",
            environment_manifest=None,
            output_dir=str(td / "out"),
            dry_run=True,
        )
        bundle = adapter.import_task(req)
        assert len(bundle.requirements) == 3
        req_ids = [r.requirement_id for r in bundle.requirements]
        assert req_ids == ["REQ-0", "REQ-1", "REQ-2"]
