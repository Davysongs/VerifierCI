"""Unit tests for execution sandbox and process supervision.

SDD Section 5, 7.2, and 7.3.
Tests patch validation, safe workspace preparation, subprocess supervision,
timeout enforcement, output capture truncation, and attempt cleanup.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import pytest

from verifierci.errors import ErrorCode, ProtectionError, ValidationError
from verifierci.execution.sandbox import (
    cleanup_attempt,
    collect_output_files,
    execute,
    prepare_workspace,
    validate_patch,
)
from verifierci.models.protocol import Job


def _make_dummy_job(attempt_id: str = "att-1") -> Job:
    return Job(
        job_id="job-1",
        run_id="run-1",
        task_key="task-1",
        case_id="case-1",
        verifier_key="v-1",
        repetition=0,
        state="RUNNING",
        fence=1,
        attempt_id=attempt_id,
        lease_token="token",
        worker_id="worker-1",
        lease_expires_ms=9999999999,
        attempts_started=1,
        selected_attempt_id=None,
        terminal_reason=None,
    )


def test_validate_patch_allowed() -> None:
    diff = b"""--- a/src/main.py
+++ b/src/main.py
@@ -1 +1 @@
-old
+new
"""
    # Should not raise
    validate_patch(diff, allowed_paths=("src/*",))


def test_validate_patch_disallowed_path() -> None:
    diff = b"""--- a/secrets/key.pem
+++ b/secrets/key.pem
@@ -1 +1 @@
-old
+new
"""
    with pytest.raises(ProtectionError) as exc:
        validate_patch(diff, allowed_paths=("src/*",))
    assert exc.value.code == ErrorCode.PROTECTION_ERROR.value
    assert "allowed" in str(exc.value)


def test_validate_patch_path_traversal() -> None:
    diff = b"""--- a/../etc/passwd
+++ b/../etc/passwd
@@ -1 +1 @@
-root
+hacked
"""
    with pytest.raises(ProtectionError) as exc:
        validate_patch(diff, allowed_paths=("*",))
    assert exc.value.code == ErrorCode.PROTECTION_ERROR.value


def test_validate_patch_symlink_creation() -> None:
    diff = b"""--- /dev/null
+++ b/link
@@ -0,0 +1 @@
+new_link
new file mode 120000
"""
    with pytest.raises(ProtectionError) as exc:
        validate_patch(diff, allowed_paths=("*",))
    assert exc.value.code == ErrorCode.PROTECTION_ERROR.value
    assert "Symlink" in str(exc.value)


def test_prepare_workspace_and_cleanup() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        snap_dir = root / "snap"
        snap_dir.mkdir()
        (snap_dir / "app.py").write_text("print('original')\n")

        diff = b"""--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-print('original')
+print('patched')
"""
        job = _make_dummy_job("att-workspace-test")
        attempt_dir = prepare_workspace(
            job=job,
            snapshot_dir=snap_dir,
            diff_bytes=diff,
            allowed_paths=("*",),
            root=root,
        )

        assert attempt_dir.is_dir()
        patched_file = attempt_dir / "source" / "app.py"
        assert patched_file.read_text().strip() == "print('patched')"

        # Cleanup
        cleanup_attempt("att-workspace-test", root=root)
        assert not attempt_dir.exists()


def test_prepare_workspace_invalid_patch() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        snap_dir = root / "snap"
        snap_dir.mkdir()
        (snap_dir / "app.py").write_text("content\n")

        # Diff for non-existent file or corrupted hunk
        diff = b"""--- a/nonexistent.py
+++ b/nonexistent.py
@@ -1 +1 @@
-foo
+bar
"""
        job = _make_dummy_job("att-fail-test")
        with pytest.raises(ValidationError) as exc:
            prepare_workspace(
                job=job,
                snapshot_dir=snap_dir,
                diff_bytes=diff,
                allowed_paths=("*",),
                root=root,
            )
        assert exc.value.code == ErrorCode.PATCH_ERROR.value


def test_execute_success() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        source = root / "source"
        source.mkdir()
        out = root / "out"
        out.mkdir()
        job = _make_dummy_job("att-exec-1")

        capture = execute(
            job=job,
            command=(
                sys.executable,
                "-c",
                "import sys; sys.stdout.write('out'); sys.stderr.write('err')",
            ),
            workspace=source,
            out_dir=out,
            timeout_seconds=10,
        )

        assert capture.exit_code == 0
        assert not capture.timed_out
        assert capture.stdout_hash is not None
        assert capture.stderr_hash is not None


def test_execute_timeout() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        source = root / "source"
        source.mkdir()
        out = root / "out"
        out.mkdir()
        job = _make_dummy_job("att-exec-timeout")

        capture = execute(
            job=job,
            command=(sys.executable, "-c", "import time; time.sleep(10)"),
            workspace=source,
            out_dir=out,
            timeout_seconds=1,
        )

        assert capture.timed_out
        assert capture.exit_code is not None


def test_execute_output_truncation() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        source = root / "source"
        source.mkdir()
        out = root / "out"
        out.mkdir()
        job = _make_dummy_job("att-exec-trunc")

        capture = execute(
            job=job,
            command=(sys.executable, "-c", "print('X' * 5000)"),
            workspace=source,
            out_dir=out,
            timeout_seconds=10,
            max_capture_bytes=100,
        )

        assert capture.truncated


def test_validate_patch_binary_patch_rejected() -> None:
    diff = b"GIT binary patch\nliteral 0\nHc$@<O00001\n"
    with pytest.raises(ProtectionError) as exc:
        validate_patch(diff, allowed_paths=("*",))
    assert exc.value.code == ErrorCode.PROTECTION_ERROR.value


def test_validate_patch_absolute_path_rejected() -> None:
    diff = b"--- a//etc/passwd\n+++ b//etc/passwd\n@@ -1 +1 @@\n-a\n+b\n"
    with pytest.raises(ProtectionError) as exc:
        validate_patch(diff, allowed_paths=("*",))
    assert exc.value.code == ErrorCode.PROTECTION_ERROR.value


def test_prepare_workspace_empty_diff() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        snap_dir = root / "snap"
        snap_dir.mkdir()
        (snap_dir / "app.py").write_text("print('original')\n")

        job = _make_dummy_job("att-empty-diff")
        attempt_dir = prepare_workspace(
            job=job,
            snapshot_dir=snap_dir,
            diff_bytes=b"",
            allowed_paths=("*",),
            root=root,
        )
        assert (
            attempt_dir / "source" / "app.py"
        ).read_text().strip() == "print('original')"


def test_validate_patch_git_header_format() -> None:
    diff = b"""diff --git a/src/app.py b/src/app.py
index 0000000..1111111 100644
--- a/src/app.py
+++ b/src/app.py
@@ -1 +1 @@
-old
+new
"""
    # Should pass allowed edit path check
    validate_patch(diff, allowed_paths=("src/*",))


def test_validate_patch_code_with_120000_allowed() -> None:
    diff = b"""--- a/src/app.py
+++ b/src/app.py
@@ -1 +1 @@
-PORT = 8080
+PORT = 120000
"""
    # 120000 in code should NOT be rejected as a symlink
    validate_patch(diff, allowed_paths=("src/*",))


def test_validate_patch_other_symlink_mode_prefixes() -> None:
    diff1 = b"""--- a/src/link
+++ /dev/null
deleted file mode 120000
@@ -1 +0,0 @@
-target
"""
    with pytest.raises(ProtectionError):
        validate_patch(diff1, allowed_paths=("src/*",))

    diff2 = b"""diff --git a/src/link b/src/link
old mode 120000
new mode 100644
"""
    with pytest.raises(ProtectionError):
        validate_patch(diff2, allowed_paths=("src/*",))


def test_execute_environment_isolation() -> None:
    import os

    os.environ["SECRET_VERIFIERCI_KEY"] = "super-secret"
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            source = root / "source"
            source.mkdir()
            out = root / "out"
            out.mkdir()
            capture_dir = root / "capture"
            capture_dir.mkdir()
            job = _make_dummy_job("att-env-iso")

            capture = execute(
                job=job,
                command=(
                    sys.executable,
                    "-c",
                    "import os, sys; sys.stdout.write(str('SECRET_VERIFIERCI_KEY' in os.environ))",
                ),
                workspace=source,
                out_dir=out,
                timeout_seconds=10,
            )
            # The secret environment variable must not leak into child process
            assert capture.exit_code == 0
            stdout_content = (capture_dir / "stdout.log").read_text()
            assert stdout_content == "False"
    finally:
        os.environ.pop("SECRET_VERIFIERCI_KEY", None)


def test_execute_with_custom_env_and_report_and_stderr() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        source = root / "source"
        source.mkdir()
        out = root / "out"
        out.mkdir()
        capture_dir = root / "capture"
        capture_dir.mkdir()
        job = _make_dummy_job("att-custom-env")

        # Create report.json
        (out / "report.json").write_text('{"summary": "ok"}')

        capture = execute(
            job=job,
            command=(
                sys.executable,
                "-c",
                "import os, sys; sys.stdout.write(os.environ.get('MY_CUSTOM_VAR', '')); sys.stderr.write('err_msg')",
            ),
            workspace=source,
            out_dir=out,
            env={"MY_CUSTOM_VAR": "hello_from_env"},
            timeout_seconds=10,
        )
        assert capture.exit_code == 0
        assert capture.report_digest is not None
        assert (capture_dir / "stdout.log").read_text() == "hello_from_env"
        assert (capture_dir / "stderr.log").read_text() == "err_msg"


def test_execute_launch_failure() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        source = root / "source"
        source.mkdir()
        out = root / "out"
        out.mkdir()
        job = _make_dummy_job("att-launch-fail")

        capture = execute(
            job=job,
            command=("/nonexistent_executable_path_12345",),
            workspace=source,
            out_dir=out,
            timeout_seconds=5,
        )
        assert capture.exit_code == -1
        assert capture.runtime_error is not None
        assert "launch failed" in capture.runtime_error


def test_validate_patch_empty_or_none() -> None:
    # Empty diff or None does nothing
    validate_patch(b"", allowed_paths=("*",))
    validate_patch(b"   ", allowed_paths=("*",))


def test_workspace_permissions_0700() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        snap_dir = root / "snap"
        snap_dir.mkdir()
        (snap_dir / "app.py").write_text("print('hello')\n")

        job = _make_dummy_job("att-perms-test")
        attempt_dir = prepare_workspace(
            job=job,
            snapshot_dir=snap_dir,
            diff_bytes=None,
            allowed_paths=("*",),
            root=root,
        )

        assert attempt_dir.is_dir()
        # Verify 0700 permissions
        assert (attempt_dir.stat().st_mode & 0o777) == 0o700
        for sub in ("source", "meta", "out", "capture"):
            sub_dir = attempt_dir / sub
            assert sub_dir.is_dir()
            assert (sub_dir.stat().st_mode & 0o777) == 0o700


def test_snapshot_symlink_ignored() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        snap_dir = root / "snap"
        snap_dir.mkdir()
        (snap_dir / "regular.txt").write_text("regular file\n")
        # File symlink pointing to an outside file
        outside_file = root / "outside.txt"
        outside_file.write_text("secret\n")
        (snap_dir / "symlink.txt").symlink_to(outside_file)

        # Directory symlink
        outside_dir = root / "outside_dir"
        outside_dir.mkdir()
        (outside_dir / "evil.txt").write_text("evil\n")
        (snap_dir / "sym_dir").symlink_to(outside_dir)

        job = _make_dummy_job("att-symlink-snap")
        attempt_dir = prepare_workspace(
            job=job,
            snapshot_dir=snap_dir,
            diff_bytes=None,
            allowed_paths=("*",),
            root=root,
        )

        source_dir = attempt_dir / "source"
        assert (source_dir / "regular.txt").is_file()
        assert not (source_dir / "symlink.txt").exists()
        assert not (source_dir / "sym_dir").exists()


def test_attempt_id_validation_and_cleanup_traversal() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        snap_dir = root / "snap"
        snap_dir.mkdir()

        job_bad = _make_dummy_job("../escape")
        with pytest.raises(ValidationError, match="Invalid attempt_id") as exc:
            prepare_workspace(
                job=job_bad,
                snapshot_dir=snap_dir,
                diff_bytes=None,
                allowed_paths=("*",),
                root=root,
            )
        assert exc.value.code == ErrorCode.VALIDATION_ERROR.value

        with pytest.raises(ValidationError, match="Invalid attempt_id") as exc:
            cleanup_attempt("../escape", root=root)
        assert exc.value.code == ErrorCode.VALIDATION_ERROR.value

        with pytest.raises(ValidationError, match="Invalid attempt_id") as exc:
            cleanup_attempt("", root=root)
        assert exc.value.code == ErrorCode.VALIDATION_ERROR.value


def test_execute_command_validation() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        source = root / "source"
        source.mkdir()
        out = root / "out"
        out.mkdir()
        job = _make_dummy_job("att-val-test")

        # Empty command
        with pytest.raises(ValidationError, match="cannot be empty") as exc:
            execute(job=job, command=(), workspace=source, out_dir=out)
        assert exc.value.code == ErrorCode.VALIDATION_ERROR.value

        # Non-positive timeout
        with pytest.raises(ValidationError, match="must be positive") as exc:
            execute(
                job=job,
                command=("echo", "hi"),
                workspace=source,
                out_dir=out,
                timeout_seconds=0,
            )
        assert exc.value.code == ErrorCode.VALIDATION_ERROR.value

        with pytest.raises(ValidationError, match="must be positive") as exc:
            execute(
                job=job,
                command=("echo", "hi"),
                workspace=source,
                out_dir=out,
                timeout_seconds=-5,
            )
        assert exc.value.code == ErrorCode.VALIDATION_ERROR.value

        # Nonexistent workspace
        with pytest.raises(ValidationError, match="does not exist") as exc:
            execute(
                job=job,
                command=("echo", "hi"),
                workspace=root / "nonexistent",
                out_dir=out,
            )
        assert exc.value.code == ErrorCode.RUNTIME_UNAVAILABLE.value


def test_execute_report_symlink_prohibited() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        source = root / "source"
        source.mkdir()
        out = root / "out"
        out.mkdir()
        capture_dir = root / "capture"
        capture_dir.mkdir()
        job = _make_dummy_job("att-report-symlink")

        # Create target file outside and symlink report.json to it
        target_file = root / "secret_report.json"
        target_file.write_text('{"summary": "pwned"}')
        (out / "report.json").symlink_to(target_file)

        with pytest.raises(
            ProtectionError, match="Symlink in report_path is prohibited"
        ) as exc:
            execute(
                job=job,
                command=(sys.executable, "-c", "print('done')"),
                workspace=source,
                out_dir=out,
                report_path="report.json",
            )
        assert exc.value.code == ErrorCode.PROTECTION_ERROR.value


def test_execute_report_path_traversal_prohibited() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        source = root / "source"
        source.mkdir()
        out = root / "out"
        out.mkdir()
        capture_dir = root / "capture"
        capture_dir.mkdir()
        job = _make_dummy_job("att-report-traversal")

        with pytest.raises(
            ProtectionError, match="Path traversal in report_path is prohibited"
        ) as exc:
            execute(
                job=job,
                command=(sys.executable, "-c", "print('done')"),
                workspace=source,
                out_dir=out,
                report_path="../escape_report.json",
            )
        assert exc.value.code == ErrorCode.PROTECTION_ERROR.value


def test_collect_output_files_no_symlinks() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "out"
        out.mkdir()

        (out / "report.json").write_text('{"summary": "pass"}')
        (out / "output.txt").write_text("output content")

        outside = Path(tmpdir) / "outside.txt"
        outside.write_text("secret")
        (out / "symlink.txt").symlink_to(outside)

        # Collect files matching *.json and *.txt
        collected = collect_output_files(out, allowed_filenames=("*.json", "*.txt"))

        assert "report.json" in collected
        assert "output.txt" in collected
        assert "symlink.txt" not in collected  # Symlink skipped!
        assert collected["report.json"] == out / "report.json"

        # Max file limits
        collected_one = collect_output_files(out, allowed_filenames=("*",), max_files=1)
        assert len(collected_one) == 1

        # Max byte limit
        collected_capped = collect_output_files(
            out, allowed_filenames=("*",), max_bytes_per_file=5
        )
        assert "output.txt" not in collected_capped  # Exceeds 5 bytes


def test_execute_out_dir_symlink_prohibited() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        source = root / "source"
        source.mkdir()
        out = root / "out"
        out.mkdir()
        capture_dir = root / "capture"
        capture_dir.mkdir()
        job = _make_dummy_job("att-out-symlink")

        # Subprocess replaces out_dir with a symlink to /tmp
        outside = root / "outside"
        outside.mkdir()
        (outside / "report.json").write_text('{"summary": "pass"}')

        script = (
            "import os, shutil, sys\n"
            f"shutil.rmtree(r'{out}')\n"
            f"os.symlink(r'{outside}', r'{out}')\n"
        )

        with pytest.raises(
            ProtectionError, match="Symlink in out_dir is prohibited"
        ) as exc:
            execute(
                job=job,
                command=(sys.executable, "-c", script),
                workspace=source,
                out_dir=out,
                report_path="report.json",
            )
        assert exc.value.code == ErrorCode.PROTECTION_ERROR.value


def test_collect_output_files_symlinked_out_dir() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        real_dir = root / "real"
        real_dir.mkdir()
        (real_dir / "report.json").write_text('{"summary": "pass"}')

        symlink_out = root / "out_symlink"
        symlink_out.symlink_to(real_dir)

        collected = collect_output_files(symlink_out, allowed_filenames=("*",))
        assert collected == {}
