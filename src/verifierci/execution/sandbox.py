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
from pathlib import Path
from typing import Any

from verifierci.errors import (
    ErrorCode,
    ProtectionError,
    ValidationError,
)
from verifierci.models.protocol import ExecutionCapture, Job, ResourceUsage

DEFAULT_MAX_CAPTURE_BYTES = 10 * 1024 * 1024  # 10 MiB stream cap


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
            target_files.append(line[6:].strip())
        elif line.startswith(("rename from ", "rename to ")):
            target_files.append(line[12:].strip())
        elif line.startswith("diff --git a/"):
            parts = line.split(" ")
            if len(parts) >= 3 and parts[2].startswith("a/"):
                target_files.append(parts[2][2:].strip())
            if len(parts) >= 4 and parts[3].startswith("b/"):
                target_files.append(parts[3][2:].strip())

        for target_file in target_files:
            if not target_file or target_file == "/dev/null":
                continue

            if target_file.startswith(("/", "\\")):
                raise ProtectionError(
                    f"Absolute path in patch is prohibited: {target_file}",
                    code=ErrorCode.PROTECTION_ERROR.value,
                )
            parts = target_file.replace("\\", "/").split("/")
            if ".." in parts or "." in parts:
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
) -> Path:
    """Prepare a fresh attempt workspace directory structure.

    Layout:
      root/attempts/<attempt_id>/
        source/   # Snapshot copy with diff applied
        meta/     # Trusted metadata and commands
        out/      # Output directory for test reports
        capture/  # Captured stdout/stderr streams
    """
    attempt_id = job.attempt_id or "default"
    attempt_dir = root / "attempts" / attempt_id
    attempt_dir.mkdir(parents=True, exist_ok=True)

    source_dir = attempt_dir / "source"
    meta_dir = attempt_dir / "meta"
    out_dir = attempt_dir / "out"
    capture_dir = attempt_dir / "capture"

    for d in (source_dir, meta_dir, out_dir, capture_dir):
        d.mkdir(parents=True, exist_ok=True)

    # 1. Copy snapshot source (regular files only, skip symlinks)
    if snapshot_dir.is_dir():
        for src_path in snapshot_dir.rglob("*"):
            if src_path.is_file() and not src_path.is_symlink():
                rel = src_path.relative_to(snapshot_dir)
                dest = source_dir / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src_path, dest)

    # 2. Apply patch if provided
    if diff_bytes and diff_bytes.strip():
        validate_patch(diff_bytes, allowed_paths)
        patch_file = meta_dir / "patch.diff"
        patch_file.write_bytes(diff_bytes)

        # Apply using isolated Git
        empty_home = meta_dir / "git_home"
        empty_home.mkdir(exist_ok=True)

        git_env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(empty_home),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CEILING_DIRECTORIES": str(source_dir),
            "LC_ALL": "C.UTF-8",
        }
        check_cmd = [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.autocrlf=false",
            "-C",
            str(source_dir),
            "apply",
            "--check",
            "--whitespace=nowarn",
            "--",
            str(patch_file),
        ]
        apply_cmd = [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.autocrlf=false",
            "-C",
            str(source_dir),
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
    """Supervise subprocess execution within the attempt workspace."""
    attempt_id = job.attempt_id or "unknown"
    start_time = time.monotonic()

    clean_env: dict[str, str] = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONUNBUFFERED": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "HOME": str(workspace),
        "TMPDIR": str(workspace),
    }

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
                proc.kill()
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

    # Check report file
    rep_file = out_dir / report_path
    report_digest = None
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


def cleanup_attempt(attempt_id: str, root: Path) -> None:
    """Remove all attempt directory state."""
    attempt_dir = root / "attempts" / attempt_id
    if attempt_dir.exists():
        shutil.rmtree(attempt_dir, ignore_errors=True)
