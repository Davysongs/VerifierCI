"""Top-level Click CLI for VerifierCI (Phase 1).

SDD Section 5, Section 6.1, 6.2, 6.5, 6.9, and ADR 0009.
Parses commands with Click, validates options, delegates orchestration to
registries/execution services (zero raw SQL or subprocess logic here), emits
schema-versioned JSON to stdout when --json is set, routes diagnostics to
stderr, and enforces canonical exit categories 0, 1, 2, and 3.
"""

from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import click

from verifierci._version import __version__
from verifierci.adapters.local import _safe_load_yaml
from verifierci.errors import (
    ErrorCode,
    ProtectionError,
    ValidationError,
    VerifierCIError,
    exit_category,
)
from verifierci.execution.service import execute_audit_pipeline, import_task_command
from verifierci.models.protocol import AuditOptions, AuditResult, ImportRequest
from verifierci.panels.registry import load_and_validate_panel
from verifierci.reports.render import render_summary, serialize_audit_result

CLI_SCHEMA_VERSION = "1.0.0"
DEFAULT_DB_PATH = Path(".verifierci/state.sqlite")
DEFAULT_ARTIFACT_DIR = Path(".verifierci/artifacts")
DEFAULT_CONFIG_PATH = Path("configs/local.yaml")


@dataclass(frozen=True, slots=True)
class CliContext:
    """Shared global CLI options carried via Click context."""

    db_path: Path
    artifact_dir: Path
    config_path: Path
    config_explicit: bool
    json_output: bool


def render_diagnostic(code: str, message: str, *, json_output: bool) -> str:
    """Format a structured diagnostic message for stderr output."""
    if json_output:
        return json.dumps(
            {
                "schema_version": CLI_SCHEMA_VERSION,
                "kind": "Diagnostic",
                "data": {"code": code, "message": message},
            },
            sort_keys=True,
        )
    return f"[{code}] {message}"


def _emit_json(payload: dict[str, Any]) -> None:
    click.echo(json.dumps(payload, sort_keys=True, indent=2), err=False)


def _load_optional_config(ctx_obj: CliContext) -> dict[str, Any]:
    cfg_path = ctx_obj.config_path
    if cfg_path.is_symlink() or os.path.islink(cfg_path):
        raise ProtectionError(
            f"Symlink rejected in config loading: {cfg_path}",
            code=ErrorCode.PROTECTION_ERROR.value,
        )
    if not cfg_path.exists():
        if ctx_obj.config_explicit:
            raise ValidationError(
                f"Config file not found: {cfg_path}",
                code=ErrorCode.VALIDATION_ERROR.value,
            )
        return {}
    return _safe_load_yaml(cfg_path)


def _handle_exception(exc: Exception, *, json_output: bool) -> int:
    if isinstance(exc, VerifierCIError):
        code = exc.code or ErrorCode.UNSUPPORTED_DIAGNOSTIC.value
        msg = exc.message
        exit_code = exit_category(exc)
    elif isinstance(exc, sqlite3.Error):
        code = ErrorCode.DATABASE_ERROR.value
        msg = str(exc)
        exit_code = 3
    elif isinstance(exc, OSError):
        code = ErrorCode.INFRASTRUCTURE_ERROR.value
        msg = str(exc)
        exit_code = 3
    else:
        code = ErrorCode.INFRASTRUCTURE_ERROR.value
        msg = str(exc)
        exit_code = 3

    click.echo(render_diagnostic(code, msg, json_output=json_output), err=True)
    return exit_code


def audit_command(
    options: AuditOptions,
    *,
    db_path: Path = DEFAULT_DB_PATH,
    artifact_dir: Path = DEFAULT_ARTIFACT_DIR,
    json_output: bool = False,
) -> int:
    """Execute the audit command pipeline and map domain exceptions to 0/1/2/3."""
    try:
        result = execute_audit_pipeline(
            options, db_path=db_path, artifact_dir=artifact_dir
        )
        _emit_audit_output(result, options=options, json_output=json_output)
        return 0
    except Exception as exc:  # noqa: BLE001
        return _handle_exception(exc, json_output=json_output)


def _emit_audit_output(
    result: AuditResult,
    *,
    options: AuditOptions,
    json_output: bool,
) -> None:
    manifest = result.manifest
    if json_output:
        if options.dry_run:
            _emit_json(
                {
                    "schema_version": CLI_SCHEMA_VERSION,
                    "kind": "AuditDryRun",
                    "data": {
                        "run_id": manifest.run_id,
                        "manifest_hash": manifest.manifest_hash,
                        "expansion_digest": manifest.expansion_digest,
                        "max_repetitions": manifest.max_repetitions,
                        "timeout_seconds": manifest.timeout_seconds,
                        "collect_only": options.collect_only,
                        "diagnostic": options.diagnostic,
                        "gate_state": None,
                        "diagnostics": list(result.diagnostics),
                    },
                }
            )
        else:
            _emit_json(serialize_audit_result(result))
    else:
        if options.dry_run:
            click.echo(
                f"Dry run validated: run_id={manifest.run_id} "
                f"manifest_hash={manifest.manifest_hash} "
                f"expansion_digest={manifest.expansion_digest}"
            )
            for diag in result.diagnostics:
                click.echo(diag, err=True)
        else:
            click.echo(render_summary(result))


@click.group(
    name="verifierci",
    invoke_without_command=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.option(
    "--db",
    "db_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=DEFAULT_DB_PATH,
    show_default=True,
    help="Path to SQLite state database.",
)
@click.option(
    "--artifact-dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=DEFAULT_ARTIFACT_DIR,
    show_default=True,
    help="Directory for content-addressed artifacts.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help=f"Optional configuration YAML file (defaults to {DEFAULT_CONFIG_PATH} if present).",
)
@click.option(
    "--json",
    "json_output",
    is_flag=True,
    default=False,
    help="Emit schema-versioned JSON results on stdout.",
)
@click.version_option(
    version=__version__,
    prog_name="verifierci",
    message="%(prog)s %(version)s",
)
@click.pass_context
def cli(
    ctx: click.Context,
    db_path: Path,
    artifact_dir: Path,
    config_path: Path | None,
    json_output: bool,
) -> None:
    """VerifierCI command line interface."""
    ctx.obj = CliContext(
        db_path=db_path,
        artifact_dir=artifact_dir,
        config_path=config_path if config_path is not None else DEFAULT_CONFIG_PATH,
        config_explicit=config_path is not None,
        json_output=json_output,
    )
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@cli.group(name="task")
def task_group() -> None:
    """Task import and inspection commands."""


@task_group.command(name="import")
@click.option(
    "--adapter",
    type=click.Choice(["local", "swebench", "harbor"], case_sensitive=False),
    required=True,
    help="Task import adapter.",
)
@click.option(
    "--instance",
    type=str,
    required=True,
    help="Exact source instance ID.",
)
@click.option(
    "--source",
    type=click.Path(path_type=Path),
    required=True,
    help="Path to local task manifest or source input.",
)
@click.option(
    "--source-revision",
    type=str,
    required=True,
    help="Immutable source revision identity.",
)
@click.option(
    "--environment-manifest",
    type=click.Path(path_type=Path),
    default=None,
    help="Resolved pinned harness metadata path (required for SWE-bench).",
)
@click.option(
    "--output-dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path("tasks"),
    show_default=True,
    help="Destination directory for normalized manifests.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Validate and compute hashes without writing outputs or DB rows.",
)
@click.pass_context
def task_import_command(
    ctx: click.Context,
    adapter: str,
    instance: str,
    source: Path,
    source_revision: str,
    environment_manifest: Path | None,
    output_dir: Path,
    dry_run: bool,
) -> None:
    """Normalise and register a task manifest."""
    cli_ctx: CliContext = ctx.obj
    try:
        _load_optional_config(cli_ctx)
        req = ImportRequest(
            adapter=adapter.lower(),
            instance=instance,
            source=str(source),
            source_revision=source_revision,
            environment_manifest=str(environment_manifest)
            if environment_manifest
            else None,
            output_dir=str(output_dir),
            dry_run=dry_run,
        )
        bundle = import_task_command(
            req,
            db_path=cli_ctx.db_path,
            artifact_dir=cli_ctx.artifact_dir,
        )
        if cli_ctx.json_output:
            _emit_json(
                {
                    "schema_version": CLI_SCHEMA_VERSION,
                    "kind": "TaskImportResult",
                    "data": {
                        "task_key": bundle.task.task_key,
                        "task_id": bundle.task.task_id,
                        "version": bundle.task.version,
                        "contract_hash": bundle.contract.contract_hash,
                        "snapshot_digest": bundle.snapshot.snapshot_digest,
                        "environment_id": bundle.environment.environment_id,
                        "verifier_key": bundle.verifier.verifier_key,
                        "requirements_count": len(bundle.requirements),
                        "controls_count": len(bundle.controls),
                        "dry_run": dry_run,
                        "output_dir": str(output_dir),
                        "diagnostics": list(bundle.diagnostics),
                    },
                }
            )
        else:
            mode_label = "dry-run" if dry_run else "imported"
            click.echo(
                f"Task {mode_label}: {bundle.task.task_key} "
                f"(contract={bundle.contract.contract_hash[:12]}, "
                f"snapshot={bundle.snapshot.snapshot_digest[:12]})"
            )
    except Exception as exc:  # noqa: BLE001
        code = _handle_exception(exc, json_output=cli_ctx.json_output)
        ctx.exit(code)


@cli.group(name="panel")
def panel_group() -> None:
    """Patch panel validation and management commands."""


@panel_group.command(name="validate")
@click.argument("panel_file", type=click.Path(path_type=Path))
@click.option(
    "--verify-artifacts",
    is_flag=True,
    default=False,
    help="Verify and hash referenced local patch/witness files.",
)
@click.option(
    "--require-independent",
    is_flag=True,
    default=False,
    help="Require resolved independent adjudications on all cases.",
)
@click.option(
    "--expected-split",
    type=click.Choice(["development", "assessment", "train"]),
    default=None,
    help="Assert panel split matches expected split.",
)
@click.pass_context
def panel_validate_command(
    ctx: click.Context,
    panel_file: Path,
    verify_artifacts: bool,
    require_independent: bool,
    expected_split: Literal["development", "assessment", "train"] | None,
) -> None:
    """Validate a patch panel file without database writes."""
    cli_ctx: CliContext = ctx.obj
    try:
        _load_optional_config(cli_ctx)
        result = load_and_validate_panel(
            panel_file,
            verify_artifacts=verify_artifacts,
            require_independent=require_independent,
            expected_split=expected_split,
        )
        review_counts: dict[str, int] = {}
        for adj in result.adjudications:
            review_counts[adj.review_status] = (
                review_counts.get(adj.review_status, 0) + 1
            )

        if cli_ctx.json_output:
            _emit_json(
                {
                    "schema_version": CLI_SCHEMA_VERSION,
                    "kind": "PanelValidationResult",
                    "data": {
                        "panel_key": result.panel.panel_key,
                        "split": result.panel.split,
                        "membership_digest": result.panel.membership_digest,
                        "case_count": len(result.cases),
                        "review_statuses": review_counts,
                        "valid": result.valid,
                        "findings": list(result.findings),
                    },
                }
            )
        else:
            click.echo(
                f"Panel valid: {result.panel.panel_key} "
                f"(split={result.panel.split}, cases={len(result.cases)}, "
                f"digest={result.panel.membership_digest[:12]})"
            )
            for finding in result.findings:
                click.echo(f"Note: {finding}", err=True)
    except Exception as exc:  # noqa: BLE001
        code = _handle_exception(exc, json_output=cli_ctx.json_output)
        ctx.exit(code)


@cli.group(name="audit", invoke_without_command=True)
@click.option(
    "--task",
    "task_files",
    multiple=True,
    type=click.Path(path_type=Path),
    help="Task manifest YAML path (repeatable).",
)
@click.option(
    "--benchmark",
    "benchmark_file",
    type=click.Path(path_type=Path),
    default=None,
    help="Frozen benchmark manifest path (exclusive with --task).",
)
@click.option(
    "--panel",
    "panel_file",
    type=click.Path(path_type=Path),
    default=None,
    help="Versioned patch panel file.",
)
@click.option(
    "--baseline",
    "baseline_file",
    type=click.Path(path_type=Path),
    default=None,
    help="Baseline verifier manifest YAML.",
)
@click.option(
    "--candidate",
    "candidate_file",
    type=click.Path(path_type=Path),
    default=None,
    help="Candidate verifier manifest YAML.",
)
@click.option(
    "--policy",
    "policy_file",
    type=click.Path(path_type=Path),
    default=None,
    help="Release gate policy YAML path.",
)
@click.option(
    "--sandbox-policy",
    "sandbox_policy_file",
    type=click.Path(path_type=Path),
    default=None,
    help="Sandbox policy YAML path.",
)
@click.option(
    "--analysis-plan",
    "analysis_plan_file",
    type=click.Path(path_type=Path),
    default=None,
    help="Pre-registered analysis plan path.",
)
@click.option(
    "--repetitions",
    type=int,
    default=3,
    show_default=True,
    help="Planned repetitions per (task, case, verifier) cell.",
)
@click.option(
    "--max-jobs",
    type=int,
    default=1000,
    show_default=True,
    help="Maximum planned scheduled evaluations.",
)
@click.option(
    "--concurrency",
    type=int,
    default=1,
    show_default=True,
    help="Worker execution concurrency.",
)
@click.option(
    "--timeout-seconds",
    type=int,
    default=120,
    show_default=True,
    help="Per-attempt execution timeout in seconds.",
)
@click.option(
    "--max-attempts",
    type=int,
    default=3,
    show_default=True,
    help="Maximum infrastructure retries per job.",
)
@click.option(
    "--backend",
    type=click.Choice(["fixture", "docker"]),
    default="docker",
    show_default=True,
    help="Execution backend.",
)
@click.option(
    "--trusted-fixture",
    is_flag=True,
    default=False,
    help="Explicit opt-in required for fixture backend.",
)
@click.option(
    "--seed",
    type=int,
    default=None,
    help="Controlled randomness seed.",
)
@click.option(
    "--offline/--allow-fetch",
    default=True,
    show_default=True,
    help="Disable or permit controller input retrieval.",
)
@click.option(
    "--diagnostic",
    is_flag=True,
    default=False,
    help="Allow provisional labels or fewer than 3 repetitions (diagnostic scope).",
)
@click.option(
    "--collect-only",
    is_flag=True,
    default=False,
    help="Build matrix and report without evaluating release gate.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Validate plan and emit job count without execution or DB writes.",
)
@click.option(
    "--output-dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Output directory for manifest, matrix report, and summary.",
)
@click.option(
    "--resume",
    "resume_run_id",
    type=str,
    default=None,
    help="Resume an existing run ID.",
)
@click.option(
    "--parent-run",
    "parent_run_id",
    type=str,
    default=None,
    help="Parent run ID for linked diagnostic reruns.",
)
@click.pass_context
def audit_group(
    ctx: click.Context,
    task_files: tuple[Path, ...],
    benchmark_file: Path | None,
    panel_file: Path | None,
    baseline_file: Path | None,
    candidate_file: Path | None,
    policy_file: Path | None,
    sandbox_policy_file: Path | None,
    analysis_plan_file: Path | None,
    repetitions: int,
    max_jobs: int,
    concurrency: int,
    timeout_seconds: int,
    max_attempts: int,
    backend: Literal["fixture", "docker"],
    trusted_fixture: bool,
    seed: int | None,
    offline: bool,
    diagnostic: bool,
    collect_only: bool,
    dry_run: bool,
    output_dir: Path | None,
    resume_run_id: str | None,
    parent_run_id: str | None,
) -> None:
    """Plan and execute paired verifier audits."""
    if ctx.invoked_subcommand is not None:
        return

    cli_ctx: CliContext = ctx.obj
    try:
        _load_optional_config(cli_ctx)

        if policy_file is not None and not policy_file.is_file():
            raise ValidationError(
                f"Policy file not found: {policy_file}",
                code=ErrorCode.VALIDATION_ERROR.value,
            )
        if sandbox_policy_file is not None and not sandbox_policy_file.is_file():
            raise ValidationError(
                f"Sandbox policy file not found: {sandbox_policy_file}",
                code=ErrorCode.VALIDATION_ERROR.value,
            )

        default_policy = Path("configs/release-policy.yaml")
        default_sandbox = Path("configs/sandbox-policy.yaml")
        eff_policy_str = (
            str(policy_file)
            if policy_file is not None
            else (str(default_policy) if default_policy.is_file() else "default_policy")
        )
        eff_sandbox_str = (
            str(sandbox_policy_file)
            if sandbox_policy_file is not None
            else (
                str(default_sandbox) if default_sandbox.is_file() else "sandbox_policy"
            )
        )

        options = AuditOptions(
            task_files=tuple(str(p) for p in task_files),
            benchmark_file=str(benchmark_file) if benchmark_file else None,
            panel_file=str(panel_file) if panel_file else "",
            baseline_file=str(baseline_file) if baseline_file else "",
            candidate_file=str(candidate_file) if candidate_file else "",
            repetitions=repetitions,
            backend=backend,
            trusted_fixture=trusted_fixture,
            sandbox_policy_file=eff_sandbox_str,
            max_attempts=max_attempts,
            offline=offline,
            output_dir=str(output_dir) if output_dir else None,
            dry_run=dry_run,
            resume_run_id=resume_run_id,
            parent_run_id=parent_run_id,
            policy_file=eff_policy_str,
            analysis_plan_file=str(analysis_plan_file) if analysis_plan_file else None,
            max_jobs=max_jobs,
            concurrency=concurrency,
            timeout_seconds=timeout_seconds,
            seed=seed,
            collect_only=collect_only,
            diagnostic=diagnostic,
        )

        result = execute_audit_pipeline(
            options,
            db_path=cli_ctx.db_path,
            artifact_dir=cli_ctx.artifact_dir,
        )
        _emit_audit_output(result, options=options, json_output=cli_ctx.json_output)
    except Exception as exc:  # noqa: BLE001
        code = _handle_exception(exc, json_output=cli_ctx.json_output)
        ctx.exit(code)


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for verifierci console script and programmatic invocation."""
    args = list(argv) if argv is not None else None
    json_output = bool(args and "--json" in args)
    try:
        cli.main(args=args, prog_name="verifierci", standalone_mode=False)
        return 0
    except click.exceptions.Exit as exc:
        return int(exc.exit_code)
    except click.UsageError as exc:
        click.echo(
            render_diagnostic(
                ErrorCode.VALIDATION_ERROR.value,
                exc.format_message(),
                json_output=json_output,
            ),
            err=True,
        )
        return 2
    except click.ClickException as exc:
        click.echo(
            render_diagnostic(
                ErrorCode.VALIDATION_ERROR.value,
                exc.format_message(),
                json_output=json_output,
            ),
            err=True,
        )
        return int(exc.exit_code)
    except Exception as exc:  # noqa: BLE001
        return _handle_exception(exc, json_output=json_output)


def main_entry() -> int:
    return main()


__all__ = [
    "CLI_SCHEMA_VERSION",
    "CliContext",
    "audit_command",
    "audit_group",
    "cli",
    "main",
    "main_entry",
    "panel_group",
    "panel_validate_command",
    "render_diagnostic",
    "task_group",
    "task_import_command",
]

if __name__ == "__main__":
    raise SystemExit(main())
