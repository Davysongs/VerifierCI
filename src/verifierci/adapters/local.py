"""Local task adapter for native VerifierCI tasks (Phase 1).

SDD Section 5: verifierci.adapters.local.
Imports the native manifest used by the retry fixture and hand-authored tasks.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

from verifierci.adapters.base import TaskAdapter
from verifierci.errors import (
    ErrorCode,
    ProtectionError,
    ValidationError,
)
from verifierci.models.panel import PatchCase
from verifierci.models.protocol import ImportBundle, ImportRequest, LocalImportManifest
from verifierci.models.result import Artifact
from verifierci.models.task import (
    Contract,
    Environment,
    RepositorySnapshot,
    Requirement,
    Task,
    contract_hash,
    requirement_hash,
    validate_task,
)
from verifierci.models.verifier import (
    VerifierManifest,
    VerifierVersion,
    manifest_hash,
)

MAX_MANIFEST_BYTES = 2 * 1024 * 1024  # 2 MiB
MAX_YAML_DEPTH = 32
SUPPORTED_LOCAL_VERSIONS = frozenset({"1.0", "1.0.0"})


class RestrictedSafeLoader(yaml.SafeLoader):
    """YAML safe loader that strictly prohibits aliases and bounds nesting depth."""

    def __init__(self, stream: Any) -> None:
        super().__init__(stream)
        self._depth = 0

    def compose_node(self, parent: Any, index: Any) -> yaml.Node:
        if self.check_event(yaml.events.AliasEvent):
            raise ValidationError(
                "YAML aliases and anchors are prohibited in task manifests.",
                code=ErrorCode.VALIDATION_ERROR.value,
            )
        self._depth += 1
        if self._depth > MAX_YAML_DEPTH:
            raise ValidationError(
                f"YAML nesting depth exceeded maximum limit of {MAX_YAML_DEPTH}.",
                code=ErrorCode.VALIDATION_ERROR.value,
            )
        try:
            return super().compose_node(parent, index)
        finally:
            self._depth -= 1


def _safe_load_yaml(path: Path) -> dict[str, Any]:
    """Load and validate a YAML file with security constraints."""
    if path.is_symlink():
        raise ProtectionError(
            f"Symlink rejected in local manifest loading: {path}",
            code=ErrorCode.PROTECTION_ERROR.value,
        )
    if not path.is_file():
        raise ValidationError(
            f"Manifest file not found: {path}",
            code=ErrorCode.VALIDATION_ERROR.value,
        )
    if path.stat().st_size > MAX_MANIFEST_BYTES:
        raise ValidationError(
            f"Manifest size {path.stat().st_size} exceeds limit of {MAX_MANIFEST_BYTES} bytes.",
            code=ErrorCode.ARTIFACT_LIMIT.value,
        )

    content = path.read_text(encoding="utf-8")
    try:
        data = yaml.load(content, Loader=RestrictedSafeLoader)
    except yaml.YAMLError as exc:
        raise ValidationError(
            f"Failed to parse YAML manifest {path}: {exc}",
            code=ErrorCode.VALIDATION_ERROR.value,
        ) from exc

    if not isinstance(data, dict):
        raise ValidationError(
            f"Root of manifest {path} must be a mapping, got {type(data).__name__}.",
            code=ErrorCode.VALIDATION_ERROR.value,
        )
    return data


def _resolve_relative_path(root_dir: Path, rel_path_str: str) -> Path:
    """Resolve a relative path, rejecting symlinks and directory traversal."""
    norm_parts = rel_path_str.replace("\\", "/").split("/")
    if ".." in norm_parts:
        raise ProtectionError(
            f"Directory traversal detected in path: {rel_path_str}",
            code=ErrorCode.PROTECTION_ERROR.value,
        )
    p = root_dir / rel_path_str
    if p.is_symlink() or os.path.islink(p):
        raise ProtectionError(
            f"Symlinks are prohibited in task imports: {rel_path_str}",
            code=ErrorCode.PROTECTION_ERROR.value,
        )
    try:
        resolved = p.resolve()
        resolved_root = root_dir.resolve()
        if not resolved.is_relative_to(resolved_root):
            raise ProtectionError(
                f"Directory traversal detected in path: {rel_path_str}",
                code=ErrorCode.PROTECTION_ERROR.value,
            )
    except (ValueError, RuntimeError) as exc:
        raise ProtectionError(
            f"Invalid path {rel_path_str}: {exc}",
            code=ErrorCode.PROTECTION_ERROR.value,
        ) from exc
    return p


def read_local_manifest(
    path: Path, manifest_data: dict[str, Any] | None = None
) -> LocalImportManifest:
    """Read a local import manifest from a YAML file.

    Loads the task and resolves referenced contract, snapshot, environment,
    verifier, requirement, and control files.
    """
    data = manifest_data if manifest_data is not None else _safe_load_yaml(path)
    root_dir = path.parent

    if "task_id" not in data and "task" not in data:
        raise ValidationError(
            "Missing required task definition in manifest.",
            code=ErrorCode.VALIDATION_ERROR.value,
        )

    schema_version = str(data.get("schema_version", data.get("version", "1.0.0")))
    task_data = data.get("task", {})
    if isinstance(task_data, dict) and task_data:
        task_id = str(task_data.get("task_id", data.get("task_id", path.stem)))
        version = str(task_data.get("version", data.get("version", "1.0.0")))
        statement = str(task_data.get("statement", data.get("statement", "")))
        licence = str(task_data.get("licence", data.get("licence", "Apache-2.0")))
        provenance = str(task_data.get("provenance", data.get("provenance", str(path))))
        eligibility = task_data.get("eligibility", data.get("eligibility", "eligible"))
        notes = str(task_data.get("notes", data.get("notes", "")))
    else:
        task_id = str(data.get("task_id", path.stem))
        version = str(data.get("version", "1.0.0"))
        statement = str(data.get("statement", ""))
        licence = str(data.get("licence", "Apache-2.0"))
        provenance = str(data.get("provenance", str(path)))
        eligibility = data.get("eligibility", "eligible")
        notes = str(data.get("notes", ""))

    if eligibility not in ("eligible", "excluded", "pending"):
        eligibility = "eligible"
    adapter = str(data.get("adapter", "local"))

    contract_file = str(
        data.get("contract_file", data.get("contract", "contract.yaml"))
    )
    _resolve_relative_path(root_dir, contract_file)
    snapshot_file = str(data.get("snapshot_file", data.get("snapshot", "source/")))
    _resolve_relative_path(root_dir, snapshot_file)
    env_data = data.get("environment_file", data.get("environment", {}))
    environment_file = (
        str(env_data) if isinstance(env_data, str) else "environment.yaml"
    )
    _resolve_relative_path(root_dir, environment_file)
    req_files = data.get("requirement_files", ())
    requirement_files = tuple(str(x) for x in req_files)
    for rf in requirement_files:
        _resolve_relative_path(root_dir, rf)
    verifier_file = str(data.get("verifier_file", data.get("verifier", "v1.yaml")))
    _resolve_relative_path(root_dir, verifier_file)
    ctrl_files = data.get("control_files", ())
    control_files = tuple(str(x) for x in ctrl_files)
    for cf in control_files:
        _resolve_relative_path(root_dir, cf)

    task_key = f"{task_id}@{version}"
    task = Task(
        task_key=task_key,
        task_id=task_id,
        version=version,
        statement=statement,
        adapter=adapter,
        contract_hash="0" * 64,  # Computed when contract is loaded
        snapshot_digest="0" * 64,  # Computed when snapshot is loaded
        environment_id=f"{task_id}-env",
        licence=licence,
        provenance=provenance,
        eligibility=eligibility,
        notes=notes,
        created_at=datetime.now(UTC),
    )

    return LocalImportManifest(
        schema_version=schema_version,
        task=task,
        contract_file=contract_file,
        snapshot_file=snapshot_file,
        environment_file=environment_file,
        requirement_files=requirement_files,
        verifier_file=verifier_file,
        control_files=control_files,
    )


class LocalAdapter(TaskAdapter):
    """Adapter for importing native local tasks and fixtures."""

    name: str = "local"

    def supports(self, task_id: str) -> bool:
        return bool(task_id)

    def supported_source_version(self, version: str) -> bool:
        return version in SUPPORTED_LOCAL_VERSIONS

    def validate_environment(self, bundle: ImportBundle) -> None:
        backend = bundle.environment.backend
        if backend not in ("fixture", "docker"):
            raise ValidationError(
                f"Unsupported environment backend: '{backend}'. Expected 'fixture' or 'docker'.",
                code=ErrorCode.VALIDATION_ERROR.value,
            )
        if backend == "docker" and (
            not bundle.environment.image_digest
            or "@sha256:" not in bundle.environment.image_digest
        ):
            raise ValidationError(
                f"Docker environment requires '@sha256:' image_digest, got {bundle.environment.image_digest}",
                code=ErrorCode.VALIDATION_ERROR.value,
            )

    def import_task(self, request: ImportRequest) -> ImportBundle:
        """Import a native task from its local manifest path."""
        manifest_path = Path(request.source)
        if not manifest_path.is_file():
            raise ValidationError(
                f"Local task manifest not found: {request.source}",
                code=ErrorCode.VALIDATION_ERROR.value,
            )
        if manifest_path.stat().st_size > MAX_MANIFEST_BYTES:
            raise ValidationError(
                f"File exceeds maximum allowed size of {MAX_MANIFEST_BYTES} bytes",
                code=ErrorCode.VALIDATION_ERROR.value,
            )

        raw_bytes = manifest_path.read_bytes()
        upstream_digest = hashlib.sha256(raw_bytes).hexdigest()
        upstream_artifact = Artifact(
            digest=upstream_digest,
            kind="manifest",
            size_bytes=len(raw_bytes),
            storage_uri=str(manifest_path.resolve()),
            media_type="application/yaml",
            access_policy="public",
            retention_until=None,
            available=True,
            created_at=datetime.now(UTC),
        )

        manifest_data = _safe_load_yaml(manifest_path)
        local_manifest = read_local_manifest(manifest_path, manifest_data=manifest_data)
        root_dir = manifest_path.parent

        # 1. Parse Contract & Requirements
        contract_path = _resolve_relative_path(root_dir, local_manifest.contract_file)
        contract_data = (
            _safe_load_yaml(contract_path) if contract_path.is_file() else {}
        )

        raw_reqs = contract_data.get("requirements", [])
        if not isinstance(raw_reqs, list):
            raise ValidationError(
                "contract 'requirements' must be a list",
                code=ErrorCode.VALIDATION_ERROR.value,
            )
        requirements_list: list[Requirement] = []
        for r in raw_reqs:
            if not isinstance(r, Mapping):
                raise ValidationError(
                    "Each requirement entry must be a mapping",
                    code=ErrorCode.VALIDATION_ERROR.value,
                )
            req_id = str(r.get("requirement_id", "REQ"))
            text = str(r.get("text", "")).strip()
            source_kind = r.get("source_kind", "explicit")
            if source_kind not in ("explicit", "repository", "clarification"):
                source_kind = "explicit"
            source_locator = str(r.get("source_locator", "contract.yaml"))
            allowed_variation = str(r.get("allowed_variation", "None"))
            ev_digests = tuple(str(d) for d in r.get("evidence_digests", ()))

            req_obj = Requirement(
                requirement_hash="temp",
                requirement_id=req_id,
                text=text,
                source_kind=source_kind,
                evidence_digests=ev_digests,
                source_locator=source_locator,
                allowed_variation=allowed_variation,
            )
            req_hash = requirement_hash(req_obj)
            req_obj = Requirement(
                requirement_hash=req_hash,
                requirement_id=req_id,
                text=text,
                source_kind=source_kind,
                evidence_digests=ev_digests,
                source_locator=source_locator,
                allowed_variation=allowed_variation,
            )
            requirements_list.append(req_obj)

        requirements = tuple(requirements_list)
        contract_obj = Contract(
            contract_hash="temp",
            task_id=local_manifest.task.task_id,
            version=local_manifest.task.version,
            requirement_hashes=tuple(r.requirement_hash for r in requirements),
            allowed_variation=str(contract_data.get("allowed_variation", "None")),
            unresolved_questions=tuple(
                str(q) for q in contract_data.get("unresolved_questions", ())
            ),
            evidence_digests=(),
            created_at=datetime.now(UTC),
        )
        chash = contract_hash(contract_obj)
        contract = Contract(
            contract_hash=chash,
            task_id=local_manifest.task.task_id,
            version=local_manifest.task.version,
            requirement_hashes=tuple(r.requirement_hash for r in requirements),
            allowed_variation=str(contract_data.get("allowed_variation", "None")),
            unresolved_questions=tuple(
                str(q) for q in contract_data.get("unresolved_questions", ())
            ),
            evidence_digests=(),
            created_at=datetime.now(UTC),
        )

        # 2. Parse Environment
        raw_env = manifest_data.get("environment")
        env_raw_data = raw_env if isinstance(raw_env, Mapping) else {}
        if not env_raw_data and local_manifest.environment_file:
            env_p = _resolve_relative_path(root_dir, local_manifest.environment_file)
            if env_p.is_file():
                loaded_env = _safe_load_yaml(env_p)
                if isinstance(loaded_env, Mapping):
                    env_raw_data = loaded_env

        backend = env_raw_data.get("backend", "fixture")
        if backend not in ("fixture", "docker"):
            backend = "fixture"
        environment_id = f"{local_manifest.task.task_id}-env"
        environment = Environment(
            environment_id=environment_id,
            backend=backend,
            image_digest=env_raw_data.get("image_digest"),
            platform=env_raw_data.get("platform", "linux/arm64"),
            recipe_digest=hashlib.sha256(b"fixture-recipe").hexdigest(),
            lock_digests=(),
            service_manifests=(),
            resource_policy_hash=hashlib.sha256(b"default-policy").hexdigest(),
            runtime_fingerprint=str(
                env_raw_data.get("runtime_fingerprint", "cpython-3.12")
            ),
            mirror_uris=(),
        )

        # 3. Snapshot
        snapshot_dir = root_dir / local_manifest.snapshot_file
        snapshot_digest = hashlib.sha256(b"empty_snapshot").hexdigest()
        if snapshot_dir.is_dir():
            # Hash directory content canonically with relative POSIX paths
            hasher = hashlib.sha256()
            for child in sorted(snapshot_dir.rglob("*")):
                if child.is_file() and not child.is_symlink():
                    rel_posix = child.relative_to(snapshot_dir).as_posix()
                    hasher.update((rel_posix + "\0").encode("utf-8"))
                    hasher.update(child.read_bytes())
            snapshot_digest = hasher.hexdigest()

        snapshot = RepositorySnapshot(
            snapshot_digest=snapshot_digest,
            repository_id=local_manifest.task.task_id,
            commit_oid="HEAD",
            archive_uri=str(snapshot_dir),
            tree_digest=snapshot_digest,
            submodule_digests=(),
            lock_digests=(),
            licence=local_manifest.task.licence,
            created_at=datetime.now(UTC),
        )

        # 4. Verifier Manifest & Version
        verifier_path = _resolve_relative_path(root_dir, local_manifest.verifier_file)
        verifier_data = (
            _safe_load_yaml(verifier_path) if verifier_path.is_file() else {}
        )
        v_cmd = tuple(
            str(x) for x in verifier_data.get("command", ["pytest", "tests/"])
        )
        v_bcmd = tuple(str(x) for x in verifier_data.get("build_command", []))
        v_exp = tuple(str(x) for x in verifier_data.get("expected_collection", []))
        v_req = tuple(str(x) for x in verifier_data.get("required_pass_ids", []))
        v_skips = tuple(str(x) for x in verifier_data.get("permitted_skips", []))
        v_edits = tuple(
            str(x) for x in verifier_data.get("allowed_edit_paths", ["src/"])
        )
        v_timeout = int(verifier_data.get("timeout_seconds", 60))
        v_parser = str(verifier_data.get("parser_id", "pytest-report-v1"))
        v_report_path = str(verifier_data.get("report_path", "report.json"))
        v_mode = verifier_data.get("mode", "compatibility")
        if v_mode not in ("compatibility", "blackbox"):
            v_mode = "compatibility"

        payload_digest = hashlib.sha256(b"verifier_payload").hexdigest()
        v_man_obj = VerifierManifest(
            manifest_hash="temp",
            mode=v_mode,
            command=v_cmd,
            build_command=v_bcmd,
            expected_collection=v_exp,
            parser_id=v_parser,
            report_path=v_report_path,
            payload_digest=payload_digest,
            allowed_edit_paths=v_edits,
            required_pass_ids=v_req,
            permitted_skips=v_skips,
            timeout_seconds=v_timeout,
        )
        mhash = manifest_hash(v_man_obj)
        verifier_manifest = VerifierManifest(
            manifest_hash=mhash,
            mode=v_mode,
            command=v_cmd,
            build_command=v_bcmd,
            expected_collection=v_exp,
            parser_id=v_parser,
            report_path=v_report_path,
            payload_digest=payload_digest,
            allowed_edit_paths=v_edits,
            required_pass_ids=v_req,
            permitted_skips=v_skips,
            timeout_seconds=v_timeout,
        )

        verifier_id = str(
            verifier_data.get("verifier_id", f"{local_manifest.task.task_id}-v1")
        )
        verifier_ver = str(verifier_data.get("version", "1.0.0"))
        verifier_key = f"{verifier_id}@{verifier_ver}"
        verifier = VerifierVersion(
            verifier_key=verifier_key,
            verifier_id=verifier_id,
            version=verifier_ver,
            parent_key=None,
            manifest_hash=mhash,
            payload_digest=payload_digest,
            compatible_contract_hashes=(chash,),
            created_at=datetime.now(UTC),
        )

        # 5. Build Final Task Record
        task = Task(
            task_key=local_manifest.task.task_key,
            task_id=local_manifest.task.task_id,
            version=local_manifest.task.version,
            statement=local_manifest.task.statement,
            adapter="local",
            contract_hash=chash,
            snapshot_digest=snapshot_digest,
            environment_id=environment_id,
            licence=local_manifest.task.licence,
            provenance=local_manifest.task.provenance,
            eligibility=local_manifest.task.eligibility,
            notes=local_manifest.task.notes,
            created_at=datetime.now(UTC),
        )
        validate_task(task, contract)

        # 6. Controls
        controls_list: list[PatchCase] = []
        for ctrl_path_str in local_manifest.control_files:
            cp = _resolve_relative_path(root_dir, ctrl_path_str)
            if cp.is_file():
                diff_bytes = cp.read_bytes()
                diff_digest = hashlib.sha256(diff_bytes).hexdigest()
                case_id = f"{task.task_id}-ctrl-{cp.stem}"
                case = PatchCase(
                    case_id=case_id,
                    task_key=task.task_key,
                    diff_digest=diff_digest,
                    base_snapshot_digest=snapshot_digest,
                    source="reference",
                    source_run_id=None,
                    parent_case_ids=(),
                    family_id="reference-family",
                    role="reference",
                    provenance_digest=hashlib.sha256(str(cp).encode()).hexdigest(),
                    licence=task.licence,
                    created_at=datetime.now(UTC),
                )
                controls_list.append(case)

        bundle = ImportBundle(
            task=task,
            contract=contract,
            requirements=requirements,
            snapshot=snapshot,
            environment=environment,
            verifier=verifier,
            verifier_manifest=verifier_manifest,
            controls=tuple(controls_list),
            upstream_artifact=upstream_artifact,
            diagnostics=(),
        )
        self.validate_environment(bundle)
        return bundle
