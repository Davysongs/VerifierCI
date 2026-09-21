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
