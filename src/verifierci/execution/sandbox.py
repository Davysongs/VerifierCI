"""Sandbox execution primitives and workspace lifecycle (Phase 1).

SDD Section 5: verifierci.execution.sandbox.
Prepares bounded workspaces, constructs invocation arrays, supervises
subprocesses and cleans up attempt state.
"""

from __future__ import annotations

import fnmatch
import hashlib
import os
import shutil
import signal
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from verifierci.adapters.local import hash_snapshot_directory
from verifierci.errors import (
    ErrorCode,
    ProtectionError,
    ValidationError,
)
from verifierci.models.protocol import ExecutionCapture, Job, ResourceUsage

DEFAULT_MAX_CAPTURE_BYTES = 10 * 1024 * 1024  # 10 MiB stream cap
DEFAULT_MAX_AGGREGATE_OUT_BYTES = 64 * 1024 * 1024  # 64 MiB
DEFAULT_MAX_OUT_FILES = 64


def validate_patch(diff: bytes, allowed_paths: tuple[str, ...]) -> None:
    """Validate patch safety and allowed edit boundaries.

    Rejects directory traversals (..), absolute paths, symlinks, binary diffs,
    and paths not starting with one of allowed_paths.
    """
    if not diff or not diff.strip():
        return  # Valid empty no-op diff

    diff_text = diff.decode("utf-8", errors="replace")

    if "GIT binary patch" in diff_text:
        raise ProtectionError(
            "Binary patches are prohibited.",
            code=ErrorCode.PROTECTION_ERROR.value,
        )

    mode_prefixes = ("new file mode ", "old mode ", "new mode ", "deleted file mode ")
    for line in diff_text.splitlines():
        stripped = line.strip()
        if stripped.startswith(mode_prefixes) and stripped.endswith("120000"):
            raise ProtectionError(
                "Symlink creation or modification in patches is prohibited.",
                code=ErrorCode.PROTECTION_ERROR.value,
            )

        target_files = []
        if line.startswith(("--- a/", "--- b/", "+++ a/", "+++ b/")):
            raw_target = line[6:].split("\t")[0].strip().strip('"')
            target_files.append(raw_target)
        elif line.startswith(("--- ", "+++ ")):
            raw_target = line[4:].split("\t")[0].strip().strip('"')
            if raw_target.startswith(("a/", "b/")):
                raw_target = raw_target[2:]
            target_files.append(raw_target)
        elif line.startswith("rename from "):
            target_files.append(line[len("rename from ") :].split("\t")[0].strip())
        elif line.startswith("rename to "):
            target_files.append(line[len("rename to ") :].split("\t")[0].strip())
        elif line.startswith("copy from "):
            target_files.append(line[len("copy from ") :].split("\t")[0].strip())
        elif line.startswith("copy to "):
            target_files.append(line[len("copy to ") :].split("\t")[0].strip())
        elif line.startswith("diff --git "):
            rest = line[len("diff --git ") :].strip()
            if rest.startswith('"'):
                quoted_parts = [p.strip('"') for p in rest.split('" "')]
                if len(quoted_parts) >= 1:
                    p1 = quoted_parts[0]
                    target_files.append(p1.removeprefix("a/"))
                if len(quoted_parts) >= 2:
                    p2 = quoted_parts[1]
                    target_files.append(p2.removeprefix("b/"))
            else:
                left, sep, right = rest.partition(" b/")
                if sep:
                    p1 = left.removeprefix("a/")
                    p2 = right
                    target_files.append(p1)
                    target_files.append(p2)
                else:
                    target_files.append(rest)

        for target_file in target_files:
            if not target_file or target_file == "/dev/null":
                continue

            if "\0" in target_file:
                raise ProtectionError(
                    f"Null byte in patch path is prohibited: {target_file}",
                    code=ErrorCode.PROTECTION_ERROR.value,
                )

            if target_file.startswith(("/", "\\")):
                raise ProtectionError(
                    f"Absolute path in patch is prohibited: {target_file}",
                    code=ErrorCode.PROTECTION_ERROR.value,
                )
            parts = target_file.replace("\\", "/").split("/")
            if ".." in parts or "." in parts or any(p in ("..", ".") for p in parts):
                raise ProtectionError(
                    f"Path traversal in patch is prohibited: {target_file}",
                    code=ErrorCode.PROTECTION_ERROR.value,
                )

            # Check allowed edit paths
            if "*" not in allowed_paths:
                allowed = False
                for pattern in allowed_paths:
                    norm = pattern.rstrip("/")
                    if (
                        fnmatch.fnmatch(target_file, pattern)
                        or fnmatch.fnmatch(target_file, norm)
                        or target_file == norm
                        or target_file.startswith(norm + "/")
                    ):
                        allowed = True
                        break
                if not allowed:
                    raise ProtectionError(
                        f"Patch touches path outside allowed_edit_paths: {target_file}",
                        code=ErrorCode.PROTECTION_ERROR.value,
                    )


def prepare_workspace(
    job: Job,
    root: Path,
    snapshot_dir: Path,
    diff_bytes: bytes | None,
    allowed_paths: tuple[str, ...] = ("src/", "tests/"),
    *,
    expected_snapshot_digest: str | None = None,
) -> Path:
    """Prepare a fresh attempt workspace directory structure.

    Layout per SDD Section 7.3 & ADR 0007:
      root/attempts/<attempt_id>/
        source/   # Snapshot copy with diff applied (mode 0700)
        meta/     # Trusted metadata and commands (mode 0700)
        out/      # Output directory for test reports (mode 0700)
        capture/  # Captured stdout/stderr streams (mode 0700)
    All attempt directories are scaffolded with 0700 permissions.
    """
    attempt_id = job.attempt_id or str(uuid.uuid4())
    if (
        "/" in attempt_id
        or "\\" in attempt_id
        or ".." in attempt_id
        or not attempt_id
        or attempt_id == "."
    ):
        raise ValidationError(
            f"Invalid attempt_id: {attempt_id}",
            code=ErrorCode.VALIDATION_ERROR.value,
        )

    attempts_dir = root / "attempts"
    attempts_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(attempts_dir, 0o700)
    except OSError:
        pass

    attempt_dir = attempts_dir / attempt_id
    attempt_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(attempt_dir, 0o700)
    except OSError:
        pass

    source_dir = attempt_dir / "source"
    meta_dir = attempt_dir / "meta"
    out_dir = attempt_dir / "out"
    capture_dir = attempt_dir / "capture"

    for d in (source_dir, meta_dir, out_dir, capture_dir):
        d.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass

    # 1. Copy snapshot source (regular files only, skip symlinks)
    if snapshot_dir.is_dir():
        for src_path in snapshot_dir.rglob("*"):
            if src_path.is_file() and not src_path.is_symlink():
                rel = src_path.relative_to(snapshot_dir)
                # Check for intermediate symlink directories
                if any(
                    (snapshot_dir / p).is_symlink()
                    for p in rel.parents
                    if p != Path(".")
                ):
                    continue

                dest = source_dir / rel
                dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                try:
                    os.chmod(dest.parent, 0o700)
                except OSError:
                    pass
                shutil.copy2(src_path, dest, follow_symlinks=False)

    if expected_snapshot_digest is not None:
        actual_snapshot_digest = hash_snapshot_directory(source_dir)
        if actual_snapshot_digest != expected_snapshot_digest:
            raise ProtectionError(
                f"Staged snapshot digest mismatch for '{job.task_key}': "
                f"expected {expected_snapshot_digest}, got {actual_snapshot_digest}.",
                code=ErrorCode.DIGEST_MISMATCH.value,
            )

    # 2. Apply patch if provided
    if diff_bytes and diff_bytes.strip():
        validate_patch(diff_bytes, allowed_paths)
        patch_file = meta_dir / "patch.diff"
        patch_file.write_bytes(diff_bytes)
        try:
            os.chmod(patch_file, 0o600)
        except OSError:
            pass

        # Apply using isolated Git
        empty_home = meta_dir / "git_home"
        empty_home.mkdir(exist_ok=True, mode=0o700)
        try:
            os.chmod(empty_home, 0o700)
        except OSError:
            pass

        git_env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(empty_home),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_CEILING_DIRECTORIES": str(attempt_dir),
            "LC_ALL": "C.UTF-8",
        }
        common_git_args = [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.autocrlf=false",
            "-c",
            "commit.gpgsign=false",
            "-C",
            str(source_dir),
        ]
        check_cmd = common_git_args + [
            "apply",
            "--check",
            "--whitespace=nowarn",
            "--",
            str(patch_file),
        ]
        apply_cmd = common_git_args + [
            "apply",
            "--whitespace=nowarn",
            "--",
            str(patch_file),
        ]

        try:
            check_res = subprocess.run(
                check_cmd,
                env=git_env,
                capture_output=True,
                check=False,
                timeout=30,
            )
            if check_res.returncode != 0:
                raise ValidationError(
                    f"Git patch check failed: {check_res.stderr.decode('utf-8', errors='replace')}",
                    code=ErrorCode.PATCH_ERROR.value,
                )
            apply_res = subprocess.run(
                apply_cmd,
                env=git_env,
                capture_output=True,
                check=False,
                timeout=30,
            )
            if apply_res.returncode != 0:
                raise ValidationError(
                    f"Git patch apply failed: {apply_res.stderr.decode('utf-8', errors='replace')}",
                    code=ErrorCode.PATCH_ERROR.value,
                )
        except subprocess.TimeoutExpired as exc:
            raise ValidationError(
                "Git patch application timed out.",
                code=ErrorCode.TIMEOUT.value,
            ) from exc

    return attempt_dir


def execute(
    job: Job,
    command: tuple[str, ...],
    workspace: Path,
    out_dir: Path,
    *,
    timeout_seconds: int = 60,
    env: dict[str, str] | None = None,
    max_capture_bytes: int = DEFAULT_MAX_CAPTURE_BYTES,
    report_path: str = "report.json",
) -> ExecutionCapture:
    """Supervise subprocess execution within the attempt workspace.

    SDD Section 5, 7.2, and 7.3:
    Executes command with shell=False, start_new_session=True, explicit allowlisted
    environment, hard monotonic wall deadlines, and strict stream draining caps.
    """
    if not command:
        raise ValidationError(
            "Execution command cannot be empty.",
            code=ErrorCode.VALIDATION_ERROR.value,
        )

    if timeout_seconds <= 0:
        raise ValidationError(
            f"timeout_seconds must be positive, got {timeout_seconds}.",
            code=ErrorCode.VALIDATION_ERROR.value,
        )

    if not workspace.is_dir():
        raise ValidationError(
            f"Workspace directory does not exist: {workspace}",
            code=ErrorCode.RUNTIME_UNAVAILABLE.value,
        )

    out_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    expected_out_dir = out_dir.resolve()

    attempt_id = job.attempt_id or "unknown"
    start_time = time.monotonic()

    clean_env: dict[str, str] = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONUNBUFFERED": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "HOME": str(workspace),
        "TMPDIR": str(workspace),
    }
    if "PATH" in os.environ:
        clean_env["PATH"] = os.environ["PATH"]

    if env:
        clean_env.update(env)

    timed_out = False
    truncated = False
    exit_code: int | None = None
    stdout_bytes = b""
    stderr_bytes = b""
    runtime_error: str | None = None

    stdout_buf = bytearray()
    stderr_buf = bytearray()
    trunc_lock = threading.Lock()

    def _reader(stream: Any, buf: bytearray) -> None:
        nonlocal truncated
        try:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                remaining = max_capture_bytes - len(buf)
                if remaining > 0:
                    buf.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        with trunc_lock:
                            truncated = True
                else:
                    with trunc_lock:
                        truncated = True
        except (OSError, ValueError):
            pass
        finally:
            try:
                stream.close()
            except (OSError, ValueError):
                pass

    try:
        proc = subprocess.Popen(
            list(command),
            cwd=workspace,
            env=clean_env,
            shell=False,
            start_new_session=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        t_out = threading.Thread(
            target=_reader, args=(proc.stdout, stdout_buf), daemon=True
        )
        t_err = threading.Thread(
            target=_reader, args=(proc.stderr, stderr_buf), daemon=True
        )
        t_out.start()
        t_err.start()

        try:
            proc.wait(timeout=timeout_seconds)
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            # Terminate process group cleanly
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                try:
                    proc.kill()
                except OSError:
                    pass
            try:
                proc.wait(timeout=5)
            except (subprocess.TimeoutExpired, OSError):
                pass
            exit_code = -1

        t_out.join(timeout=5)
        t_err.join(timeout=5)
        stdout_bytes = bytes(stdout_buf)
        stderr_bytes = bytes(stderr_buf)
    except Exception as exc:  # noqa: BLE001
        runtime_error = f"Subprocess launch failed: {exc}"
        exit_code = -1

    elapsed = time.monotonic() - start_time

    # Cap captured stream sizes (defense-in-depth)
    if len(stdout_bytes) > max_capture_bytes:
        stdout_bytes = stdout_bytes[:max_capture_bytes]
        truncated = True
    if len(stderr_bytes) > max_capture_bytes:
        stderr_bytes = stderr_bytes[:max_capture_bytes]
        truncated = True

    stdout_hash = hashlib.sha256(stdout_bytes).hexdigest() if stdout_bytes else None
    stderr_hash = hashlib.sha256(stderr_bytes).hexdigest() if stderr_bytes else None

    # Write capture streams to attempt capture dir
    capture_dir = workspace.parent / "capture"
    if capture_dir.is_dir():
        if stdout_bytes:
            (capture_dir / "stdout.log").write_bytes(stdout_bytes)
        if stderr_bytes:
            (capture_dir / "stderr.log").write_bytes(stderr_bytes)

    # Validate and inspect report file without following symlinks
    if (
        Path(report_path).is_absolute()
        or report_path.startswith(("/", "\\"))
        or ".." in report_path.replace("\\", "/").split("/")
    ):
        raise ProtectionError(
            f"Path traversal in report_path is prohibited: {report_path}",
            code=ErrorCode.PROTECTION_ERROR.value,
        )

    if out_dir.is_symlink():
        raise ProtectionError(
            f"Symlink in out_dir is prohibited: {out_dir}",
            code=ErrorCode.PROTECTION_ERROR.value,
        )

    rep_file = out_dir / report_path
    report_digest = None
    if rep_file.is_symlink():
        raise ProtectionError(
            f"Symlink in report_path is prohibited: {report_path}",
            code=ErrorCode.PROTECTION_ERROR.value,
        )

    # Check that no intermediate parent directory component is a symlink
    rep_parts = Path(report_path.replace("\\", "/")).parts
    for i in range(1, len(rep_parts)):
        intermediate = out_dir.joinpath(*rep_parts[:i])
        if intermediate.is_symlink():
            raise ProtectionError(
                f"Symlink in report_path parent directory is prohibited: {report_path}",
                code=ErrorCode.PROTECTION_ERROR.value,
            )
    # Confirm resolved path is confined to out_dir
    try:
        resolved_rep = rep_file.resolve()
        if not resolved_rep.is_relative_to(expected_out_dir):
            raise ProtectionError(
                f"report_path escapes output directory: {report_path}",
                code=ErrorCode.PROTECTION_ERROR.value,
            )
    except (ValueError, OSError) as exc:
        raise ProtectionError(
            f"report_path escapes output directory: {report_path}",
            code=ErrorCode.PROTECTION_ERROR.value,
        ) from exc

    if rep_file.is_file():
        if rep_file.stat().st_size > max_capture_bytes:
            truncated = True
        sha = hashlib.sha256()
        bytes_read = 0
        with rep_file.open("rb") as f:
            while chunk := f.read(min(8192, max_capture_bytes - bytes_read)):
                sha.update(chunk)
                bytes_read += len(chunk)
                if bytes_read >= max_capture_bytes:
                    break
        report_digest = sha.hexdigest()

    resources = ResourceUsage(
        duration=elapsed,
        allocated_cpu=1.0,
        cpu_seconds=elapsed,
        peak_memory=None,
        model_usage=None,
        estimated_cost=None,
        pricing_version=None,
        bytes_written=len(stdout_bytes) + len(stderr_bytes),
    )

    return ExecutionCapture(
        attempt_id=attempt_id,
        exit_code=exit_code,
        timed_out=timed_out,
        oom_killed=False,
        cancelled=False,
        build_exit_code=None,
        stdout_hash=stdout_hash,
        stderr_hash=stderr_hash,
        report_digest=report_digest,
        truncated=truncated,
        resources=resources,
        runtime_error=runtime_error,
    )


def collect_output_files(
    out_dir: Path,
    *,
    allowed_filenames: tuple[str, ...] = ("report.json",),
    max_bytes_per_file: int = 16 * 1024 * 1024,
    max_aggregate_bytes: int = DEFAULT_MAX_AGGREGATE_OUT_BYTES,
    max_files: int = DEFAULT_MAX_OUT_FILES,
) -> dict[str, Path]:
    """Collect allowlisted output files from out_dir without following symlinks.

    SDD Section 5 & 7.3:
    Rejects/skips symlinks, directory traversal, hidden files, and files exceeding limits.
    Returns mapping from relative filename to Path.
    """
    if not out_dir.is_dir() or out_dir.is_symlink():
        return {}

    collected: dict[str, Path] = {}
    total_bytes = 0

    normalized_allowed: set[str] = set()
    for name in allowed_filenames:
        if not name or name.startswith(("/", "\\")):
            continue
        parts = name.replace("\\", "/").split("/")
        if ".." in parts or "." in parts:
            continue
        normalized_allowed.add(str(Path(name)))

    for path in sorted(out_dir.rglob("*")):
        if len(collected) >= max_files:
            break
        # Reject and skip any symlinks - never follow symlinks!
        if path.is_symlink():
            continue
        if not path.is_file():
            continue

        try:
            rel = str(path.relative_to(out_dir))
        except ValueError:
            continue

        # Reject hidden files and directories (dot-prefixed path components)
        rel_path_obj = path.relative_to(out_dir)
        if any(part.startswith(".") for part in rel_path_obj.parts):
            continue

        matched = False
        if (
            "*" in allowed_filenames
            or not allowed_filenames
            or rel in normalized_allowed
        ):
            matched = True
        else:
            for pattern in allowed_filenames:
                if fnmatch.fnmatch(rel, pattern):
                    matched = True
                    break

        if not matched:
            continue

        size = path.stat().st_size
        if size > max_bytes_per_file:
            continue
        if total_bytes + size > max_aggregate_bytes:
            break

        total_bytes += size
        collected[rel] = path

    return collected


def cleanup_attempt(attempt_id: str, root: Path) -> None:
    """Remove all attempt directory state."""
    if (
        "/" in attempt_id
        or "\\" in attempt_id
        or ".." in attempt_id
        or not attempt_id
        or attempt_id == "."
    ):
        raise ValidationError(
            f"Invalid attempt_id: {attempt_id}",
            code=ErrorCode.VALIDATION_ERROR.value,
        )
    attempt_dir = root / "attempts" / attempt_id
    if attempt_dir.exists():
        shutil.rmtree(attempt_dir, ignore_errors=True)


__all__ = [
    "cleanup_attempt",
    "collect_output_files",
    "execute",
    "prepare_workspace",
    "validate_patch",
]
