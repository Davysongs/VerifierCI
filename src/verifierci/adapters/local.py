"""Local task adapter for native VerifierCI tasks (Phase 1).

SDD Section 5: verifierci.adapters.local.
Imports the native manifest used by the retry fixture and hand-authored tasks.
"""

from __future__ import annotations

import hashlib
import os
import struct
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


def _safe_load_yaml_with_bytes(path: Path) -> tuple[bytes, dict[str, Any]]:
    """Read raw YAML bytes once under security bounds and parse mapping root."""
    if path.is_symlink() or os.path.islink(path):
        raise ProtectionError(
            f"Symlink rejected in local manifest loading: {path}",
            code=ErrorCode.PROTECTION_ERROR.value,
        )
    if not path.is_file():
        raise ValidationError(
            f"Manifest file not found: {path}",
            code=ErrorCode.VALIDATION_ERROR.value,
        )
    size = path.stat().st_size
    if size > MAX_MANIFEST_BYTES:
        raise ValidationError(
            f"Manifest size {size} exceeds limit of {MAX_MANIFEST_BYTES} bytes.",
            code=ErrorCode.ARTIFACT_LIMIT.value,
        )

    with path.open("rb") as f:
        raw_bytes = f.read(MAX_MANIFEST_BYTES + 1)
    if len(raw_bytes) > MAX_MANIFEST_BYTES:
        raise ValidationError(
            f"Manifest size exceeds limit of {MAX_MANIFEST_BYTES} bytes.",
            code=ErrorCode.ARTIFACT_LIMIT.value,
        )
    try:
        content = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValidationError(
            f"Failed to decode UTF-8 YAML manifest {path}: {exc}",
            code=ErrorCode.VALIDATION_ERROR.value,
        ) from exc
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
    return raw_bytes, data


def _safe_load_yaml(path: Path) -> dict[str, Any]:
    """Load and validate a YAML file with security constraints."""
    _, data = _safe_load_yaml_with_bytes(path)
    return data


_SNAPSHOT_DIGEST_VERSION = b"verifierci.snapshot.v2\0"


def hash_snapshot_directory(snapshot_dir: Path) -> str:
    """Hash a snapshot directory canonically with length-prefixed paths, exec bits, and content digests."""
    if snapshot_dir.is_symlink() or os.path.islink(snapshot_dir):
        raise ProtectionError(
            f"Symlink rejected for snapshot root directory: {snapshot_dir}",
            code=ErrorCode.PROTECTION_ERROR.value,
        )
    if not snapshot_dir.is_dir():
        raise ValidationError(
            f"Snapshot directory not found or not a directory: {snapshot_dir}",
            code=ErrorCode.VALIDATION_ERROR.value,
        )
    hasher = hashlib.sha256()
    hasher.update(_SNAPSHOT_DIGEST_VERSION)
    for child in sorted(snapshot_dir.rglob("*")):
        if child.is_symlink() or os.path.islink(child):
            raise ProtectionError(
                f"Symlinks are prohibited in snapshot files: {child.relative_to(snapshot_dir)}",
                code=ErrorCode.PROTECTION_ERROR.value,
            )
        if child.is_file():
            rel_bytes = child.relative_to(snapshot_dir).as_posix().encode("utf-8")
            is_exec = 1 if (child.stat().st_mode & 0o111) else 0
            with child.open("rb") as cf:
                file_digest = hashlib.file_digest(cf, "sha256").digest()
            hasher.update(struct.pack(">IB", len(rel_bytes), is_exec))
            hasher.update(rel_bytes)
            hasher.update(file_digest)
    return hasher.hexdigest()


def _safe_load_yaml_any(path: Path) -> Any:
    """Load and validate a YAML file allowing mapping or list roots.

    Like _safe_load_yaml but permits list-rooted files (e.g. requirement files).
    All size, symlink, alias, and depth constraints are still enforced.
    """
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

    if not isinstance(data, (dict, list)):
        raise ValidationError(
            f"Root of requirement file {path} must be a mapping or list, got {type(data).__name__}.",
            code=ErrorCode.VALIDATION_ERROR.value,
        )
    return data


def _resolve_relative_path(root_dir: Path, rel_path_str: str) -> Path:
    """Resolve a relative path, rejecting symlinks and directory traversal."""
    if not rel_path_str:
        raise ProtectionError(
            "Empty relative path is prohibited in task imports.",
            code=ErrorCode.PROTECTION_ERROR.value,
        )
    if Path(rel_path_str).is_absolute() or rel_path_str.startswith(("/", "\\")):
        raise ProtectionError(
            f"Absolute paths are prohibited in task imports: {rel_path_str}",
            code=ErrorCode.PROTECTION_ERROR.value,
        )
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
    cur = p
    resolved_root = root_dir.resolve()
    while cur != root_dir and cur != resolved_root and cur != cur.parent:
        if cur.is_symlink() or os.path.islink(cur):
            raise ProtectionError(
                f"Symlinks are prohibited in task imports: {rel_path_str}",
                code=ErrorCode.PROTECTION_ERROR.value,
            )
        cur = cur.parent
    try:
        resolved = p.resolve()
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
    if path.is_symlink() or os.path.islink(path):
        raise ProtectionError(
            f"Symlink rejected in local manifest loading: {path}",
            code=ErrorCode.PROTECTION_ERROR.value,
        )
    data = manifest_data if manifest_data is not None else _safe_load_yaml(path)
    root_dir = path.parent

    if "task_id" not in data and "task" not in data:
        raise ValidationError(
            "Missing required task definition in manifest.",
            code=ErrorCode.VALIDATION_ERROR.value,
        )

    schema_version = str(data.get("schema_version", data.get("version", "1.0.0")))
    if schema_version not in SUPPORTED_LOCAL_VERSIONS:
        raise ValidationError(
            f"Unsupported local manifest schema version: '{schema_version}'. Supported versions: {sorted(SUPPORTED_LOCAL_VERSIONS)}",
            code=ErrorCode.VALIDATION_ERROR.value,
        )
    resolved_default_prov = str(path.resolve())
    task_data = data.get("task", {})
    if isinstance(task_data, dict) and task_data:
        task_id = str(task_data.get("task_id", data.get("task_id", path.stem)))
        version = str(task_data.get("version", data.get("version", "1.0.0")))
        statement = str(task_data.get("statement", data.get("statement", "")))
        licence = str(task_data.get("licence", data.get("licence", "Apache-2.0")))
        if "provenance" in task_data and task_data["provenance"] is not None:
            provenance = str(task_data["provenance"])
        elif "provenance" in data and data["provenance"] is not None:
            provenance = str(data["provenance"])
        else:
            provenance = resolved_default_prov
        eligibility = task_data.get("eligibility", data.get("eligibility", "eligible"))
        notes = str(task_data.get("notes", data.get("notes", "")))
    else:
        task_id = str(data.get("task_id", path.stem))
        version = str(data.get("version", "1.0.0"))
        statement = str(data.get("statement", ""))
        licence = str(data.get("licence", "Apache-2.0"))
        if "provenance" in data and data["provenance"] is not None:
            provenance = str(data["provenance"])
        else:
            provenance = resolved_default_prov
        eligibility = data.get("eligibility", "eligible")
        notes = str(data.get("notes", ""))

    if eligibility not in ("eligible", "excluded", "pending"):
        eligibility = "eligible"
    adapter = str(data.get("adapter", "local"))

    raw_contract = data.get("contract_file", data.get("contract", "contract.yaml"))
    contract_file = (
        str(raw_contract) if isinstance(raw_contract, str) else "contract.yaml"
    )
    _resolve_relative_path(root_dir, contract_file)

    raw_snapshot = data.get("snapshot_file", data.get("snapshot", "source/"))
    snapshot_file = str(raw_snapshot) if isinstance(raw_snapshot, str) else "source/"
    _resolve_relative_path(root_dir, snapshot_file)

    env_data = data.get("environment_file", data.get("environment", {}))
    environment_file = (
        str(env_data) if isinstance(env_data, str) else "environment.yaml"
    )
    _resolve_relative_path(root_dir, environment_file)

    req_files = data.get("requirement_files", ())
    if not isinstance(req_files, (list, tuple)):
        raise ValidationError(
            "requirement_files must be a list or tuple of file paths",
            code=ErrorCode.VALIDATION_ERROR.value,
        )
    requirement_files = tuple(str(x) for x in req_files)
    for rf in requirement_files:
        _resolve_relative_path(root_dir, rf)

    raw_verifier = data.get("verifier_file", data.get("verifier", "v1.yaml"))
    verifier_file = str(raw_verifier) if isinstance(raw_verifier, str) else "v1.yaml"
    _resolve_relative_path(root_dir, verifier_file)

    ctrl_files = data.get("control_files", ())
    if not isinstance(ctrl_files, (list, tuple)):
        raise ValidationError(
            "control_files must be a list or tuple of file paths",
            code=ErrorCode.VALIDATION_ERROR.value,
        )
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


_MISSING = object()


def _validate_str_list(
    raw_val: Any,
    *,
    field: str,
    verifier_path: Path,
    allow_empty: bool = True,
) -> tuple[str, ...]:
    """Validate that raw_val is a list/tuple of non-empty strings."""
    if not isinstance(raw_val, (list, tuple)):
        raise ValidationError(
            f"Verifier '{verifier_path}' field '{field}' must be a list of strings, "
            f"got {type(raw_val).__name__}.",
            code=ErrorCode.VALIDATION_ERROR.value,
        )
    if not allow_empty and not raw_val:
        raise ValidationError(
            f"Verifier '{verifier_path}' field '{field}' must be a non-empty list.",
            code=ErrorCode.VALIDATION_ERROR.value,
        )
    items: list[str] = []
    for idx, elem in enumerate(raw_val):
        if not isinstance(elem, str) or not elem:
            raise ValidationError(
                f"Verifier '{verifier_path}' field '{field}[{idx}]' must be a non-empty string.",
                code=ErrorCode.VALIDATION_ERROR.value,
            )
        items.append(elem)
    return tuple(items)


def load_local_verifier_with_bytes(
    verifier_path: Path,
    *,
    default_verifier_id: str | None = None,
    compatible_contract_hashes: tuple[str, ...] = (),
) -> tuple[VerifierVersion, VerifierManifest, bytes]:
    """Load and validate a local verifier YAML once, returning exact raw payload bytes."""
    raw_bytes, verifier_data = _safe_load_yaml_with_bytes(verifier_path)
    raw_manifest = verifier_data.get("manifest")
    manifest_src: Mapping[str, Any] = (
        raw_manifest if isinstance(raw_manifest, Mapping) else verifier_data
    )

    v_cmd = _validate_str_list(
        manifest_src.get("command", ["pytest", "tests/"]),
        field="command",
        verifier_path=verifier_path,
        allow_empty=False,
    )
    v_bcmd = _validate_str_list(
        manifest_src.get("build_command", ()),
        field="build_command",
        verifier_path=verifier_path,
        allow_empty=True,
    )
    v_exp = _validate_str_list(
        manifest_src.get("expected_collection", ()),
        field="expected_collection",
        verifier_path=verifier_path,
        allow_empty=True,
    )
    v_req = _validate_str_list(
        manifest_src.get("required_pass_ids", ()),
        field="required_pass_ids",
        verifier_path=verifier_path,
        allow_empty=True,
    )
    v_skips = _validate_str_list(
        manifest_src.get("permitted_skips", ()),
        field="permitted_skips",
        verifier_path=verifier_path,
        allow_empty=True,
    )
    v_edits = _validate_str_list(
        manifest_src.get("allowed_edit_paths", ("src/",)),
        field="allowed_edit_paths",
        verifier_path=verifier_path,
        allow_empty=True,
    )

    raw_timeout = manifest_src.get("timeout_seconds", _MISSING)
    if raw_timeout is _MISSING:
        v_timeout = 60
    else:
        if isinstance(raw_timeout, bool) or not isinstance(raw_timeout, int):
            raise ValidationError(
                f"Verifier '{verifier_path}' timeout_seconds must be an integer, "
                f"got {raw_timeout!r}.",
                code=ErrorCode.VALIDATION_ERROR.value,
            )
        v_timeout = raw_timeout
    if v_timeout <= 0:
        raise ValidationError(
            f"Verifier '{verifier_path}' timeout_seconds must be > 0, got {v_timeout}.",
            code=ErrorCode.VALIDATION_ERROR.value,
        )

    v_parser = str(manifest_src.get("parser_id", "pytest-report-v1"))
    v_report_path = str(manifest_src.get("report_path", "report.json"))
    v_mode = manifest_src.get("mode", "compatibility")
    if v_mode not in ("compatibility", "blackbox"):
        raise ValidationError(
            f"Unsupported verifier mode '{v_mode}' in {verifier_path}.",
            code=ErrorCode.VALIDATION_ERROR.value,
        )

    payload_digest = hashlib.sha256(raw_bytes).hexdigest()
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

    fallback_id = default_verifier_id or verifier_path.stem
    verifier_id = str(verifier_data.get("verifier_id", fallback_id))
    verifier_ver = str(verifier_data.get("version", "1.0.0"))
    verifier_key = f"{verifier_id}@{verifier_ver}"
    verifier = VerifierVersion(
        verifier_key=verifier_key,
        verifier_id=verifier_id,
        version=verifier_ver,
        parent_key=verifier_data.get("parent_verifier"),
        manifest_hash=mhash,
        payload_digest=payload_digest,
        compatible_contract_hashes=compatible_contract_hashes,
        created_at=datetime.now(UTC),
    )
    return verifier, verifier_manifest, raw_bytes


def load_local_verifier(
    verifier_path: Path,
    *,
    default_verifier_id: str | None = None,
    compatible_contract_hashes: tuple[str, ...] = (),
) -> tuple[VerifierVersion, VerifierManifest]:
    """Load and validate a local verifier YAML file into typed VerifierVersion and VerifierManifest."""
    verifier, verifier_manifest, _ = load_local_verifier_with_bytes(
        verifier_path,
        default_verifier_id=default_verifier_id,
        compatible_contract_hashes=compatible_contract_hashes,
    )
    return verifier, verifier_manifest


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

    def import_task_with_bytes(
        self, request: ImportRequest
    ) -> tuple[ImportBundle, bytes]:
        """Import a native task and also return the verified verifier YAML bytes."""
        manifest_path = Path(request.source)
        if manifest_path.is_symlink() or os.path.islink(manifest_path):
            raise ProtectionError(
                f"Symlink rejected in local manifest loading: {manifest_path}",
                code=ErrorCode.PROTECTION_ERROR.value,
            )
        if not manifest_path.is_file():
            raise ValidationError(
                f"Local task manifest not found: {request.source}",
                code=ErrorCode.VALIDATION_ERROR.value,
            )
        if manifest_path.stat().st_size > MAX_MANIFEST_BYTES:
            raise ValidationError(
                f"File exceeds maximum allowed size of {MAX_MANIFEST_BYTES} bytes",
                code=ErrorCode.ARTIFACT_LIMIT.value,
            )

        raw_bytes, manifest_data = _safe_load_yaml_with_bytes(manifest_path)
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

        local_manifest = read_local_manifest(manifest_path, manifest_data=manifest_data)
        if not self.supported_source_version(local_manifest.schema_version):
            raise ValidationError(
                f"Unsupported local manifest schema version: {local_manifest.schema_version}",
                code=ErrorCode.VALIDATION_ERROR.value,
            )
        root_dir = manifest_path.parent
        bundle, verifier_bytes = self._assemble_bundle(
            local_manifest=local_manifest,
            manifest_data=manifest_data,
            root_dir=root_dir,
            upstream_artifact=upstream_artifact,
        )
        return bundle, verifier_bytes

    def import_task(self, request: ImportRequest) -> ImportBundle:
        """Import a native task from its local manifest path."""
        bundle, _ = self.import_task_with_bytes(request)
        return bundle

    def _assemble_bundle(
        self,
        *,
        local_manifest: LocalImportManifest,
        manifest_data: Mapping[str, Any],
        root_dir: Path,
        upstream_artifact: Artifact,
    ) -> tuple[ImportBundle, bytes]:

        # 1. Parse Contract & Requirements
        contract_path = _resolve_relative_path(root_dir, local_manifest.contract_file)
        contract_data = _safe_load_yaml(contract_path)

        raw_reqs = contract_data.get("requirements", [])
        if not isinstance(raw_reqs, list):
            raise ValidationError(
                "contract 'requirements' must be a list",
                code=ErrorCode.VALIDATION_ERROR.value,
            )
        raw_reqs = list(raw_reqs)

        all_rf_candidates: list[str] = list(local_manifest.requirement_files)
        if "requirement_files" in contract_data:
            c_rf = contract_data.get("requirement_files")
            if not isinstance(c_rf, (list, tuple)):
                raise ValidationError(
                    "contract 'requirement_files' must be a list",
                    code=ErrorCode.VALIDATION_ERROR.value,
                )
            for rf in c_rf:
                all_rf_candidates.append(str(rf))

        seen_rf_paths: set[Path] = set()
        deduped_rf: list[tuple[str, Path]] = []
        for rf_str in all_rf_candidates:
            rf_path = _resolve_relative_path(root_dir, rf_str)
            resolved_p = rf_path.resolve()
            if resolved_p not in seen_rf_paths:
                seen_rf_paths.add(resolved_p)
                deduped_rf.append((rf_str, rf_path))

        for rf_str, rf_path in deduped_rf:
            rf_data = _safe_load_yaml_any(rf_path)
            entries: list[Any]
            if isinstance(rf_data, list):
                entries = rf_data
            elif isinstance(rf_data, Mapping):
                entries = [rf_data]
            else:
                raise ValidationError(
                    f"Requirement file {rf_str} must contain a mapping or list of mappings",
                    code=ErrorCode.VALIDATION_ERROR.value,
                )
            for entry in entries:
                if not isinstance(entry, Mapping):
                    raise ValidationError(
                        "Each requirement entry must be a mapping",
                        code=ErrorCode.VALIDATION_ERROR.value,
                    )
                # Preserve explicit source_locator, default to rf_str for external entries
                if not entry.get("source_locator"):
                    entry_dict = dict(entry)
                    entry_dict["source_locator"] = rf_str
                    raw_reqs.append(entry_dict)
                else:
                    raw_reqs.append(entry)
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
            loaded_env = _safe_load_yaml(env_p)
            if not isinstance(loaded_env, Mapping):
                raise ValidationError(
                    "Environment manifest must be a mapping",
                    code=ErrorCode.VALIDATION_ERROR.value,
                )
            env_raw_data = loaded_env

        backend = env_raw_data.get("backend", "fixture")
        if backend not in ("fixture", "docker"):
            raise ValidationError(
                f"Unsupported environment backend: '{backend}'.",
                code=ErrorCode.VALIDATION_ERROR.value,
            )
        raw_env_id = env_raw_data.get("environment_id")
        environment_id = (
            str(raw_env_id).strip()
            if isinstance(raw_env_id, str) and raw_env_id.strip()
            else f"{local_manifest.task.task_id}-env"
        )
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
        snapshot_dir = _resolve_relative_path(root_dir, local_manifest.snapshot_file)
        snapshot_digest = hash_snapshot_directory(snapshot_dir)

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
        verifier, verifier_manifest, verifier_bytes = load_local_verifier_with_bytes(
            verifier_path,
            default_verifier_id=f"{local_manifest.task.task_id}-v1",
            compatible_contract_hashes=(chash,),
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
            if not cp.is_file():
                raise ValidationError(
                    f"Control file not found: {ctrl_path_str}",
                    code=ErrorCode.VALIDATION_ERROR.value,
                )
            if cp.stat().st_size > MAX_MANIFEST_BYTES:
                raise ValidationError(
                    f"Control file exceeds size limit of {MAX_MANIFEST_BYTES} bytes: {ctrl_path_str}",
                    code=ErrorCode.ARTIFACT_LIMIT.value,
                )
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
        return bundle, verifier_bytes
