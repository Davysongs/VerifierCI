"""Unit tests for execution planner.

SDD Section 2.2, Section 4.1, Section 4.4, Section 5, and Section 7.1.
Tests deterministic job ID derivation, expansion digest, cross-product job expansion,
manifest construction, policy job capping, immutability, and end-to-end plan_audit.
"""

from __future__ import annotations

import dataclasses
import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime

import pytest

from verifierci.errors import ErrorCode, ValidationError
from verifierci.execution.planner import (
    build_manifest,
    compute_expansion_digest,
    expand,
    job_id,
    plan_audit,
    plan_jobs,
)
from verifierci.models.panel import PatchPanel, PatchPanelMembership
from verifierci.models.protocol import AuditOptions, Job, SandboxPolicy, TaskPin
from verifierci.models.result import AuditManifest
from verifierci.models.task import canonical_bytes


def _make_pin(
    task_key: str = "task1@1.0",
    case_ids: tuple[str, ...] = ("case-1", "case-2"),
    baseline: str = "base@1.0",
    candidate: str = "cand@1.0",
) -> TaskPin:
    return TaskPin(
        task_key=task_key,
        task_version="1.0",
        contract_hash="con1" + "0" * 60,
        repository_snapshot_digest="snap1" + "0" * 59,
        environment_id="env1" + "0" * 60,
        environment_image_digest=None,
        verifier_baseline_version=baseline,
        verifier_candidate_version=candidate,
        baseline_manifest_hash="bman1" + "0" * 59,
        candidate_manifest_hash="cman1" + "0" * 59,
        case_ids=case_ids,
    )


def test_job_id_deterministic() -> None:
    id1 = job_id("run-1", "task@1.0", "case-1", "verifier@1.0", 0)
    id2 = job_id("run-1", "task@1.0", "case-1", "verifier@1.0", 0)
    assert id1 == id2
    assert len(id1) == 64
    assert all(c in "0123456789abcdef" for c in id1)

    # Any change yields different id
    assert id1 != job_id("run-1", "task@1.0", "case-1", "verifier@1.0", 1)
    assert id1 != job_id("run-2", "task@1.0", "case-1", "verifier@1.0", 0)
    assert id1 != job_id("run-1", "task@2.0", "case-1", "verifier@1.0", 0)
    assert id1 != job_id("run-1", "task@1.0", "case-2", "verifier@1.0", 0)
    assert id1 != job_id("run-1", "task@1.0", "case-1", "verifier@2.0", 0)

    # Verify canonical tuple bytes
    expected_bytes = canonical_bytes(("run-1", "task@1.0", "case-1", "verifier@1.0", 0))
    assert id1 == hashlib.sha256(expected_bytes).hexdigest()


def test_job_id_validation() -> None:
    with pytest.raises(ValidationError, match="run_id cannot be empty"):
        job_id("", "task", "case", "ver", 0)

    with pytest.raises(ValidationError, match="task_key cannot be empty"):
        job_id("run", "", "case", "ver", 0)

    with pytest.raises(ValidationError, match="case_id cannot be empty"):
        job_id("run", "task", "", "ver", 0)

    with pytest.raises(ValidationError, match="verifier_key cannot be empty"):
        job_id("run", "task", "case", "", 0)

    with pytest.raises(ValidationError, match="repetition index must be non-negative"):
        job_id("run", "task", "case", "ver", -1)


def test_compute_expansion_digest() -> None:
    digest1 = compute_expansion_digest(["job-b", "job-a"])
    digest2 = compute_expansion_digest(["job-a", "job-b"])
    # Order-independent because it sorts job_ids
    assert digest1 == digest2
    assert len(digest1) == 64

    # Works with Job objects
    j1 = Job(
        job_id="id-a",
        run_id="r",
        task_key="t",
        case_id="c",
        verifier_key="v",
        repetition=0,
        state="PENDING",
        fence=0,
        attempt_id=None,
        lease_token=None,
        worker_id=None,
        lease_expires_ms=None,
        attempts_started=0,
        selected_attempt_id=None,
        terminal_reason=None,
    )
    j2 = Job(
        job_id="id-b",
        run_id="r",
        task_key="t",
        case_id="c",
        verifier_key="v",
        repetition=1,
        state="PENDING",
        fence=0,
        attempt_id=None,
        lease_token=None,
        worker_id=None,
        lease_expires_ms=None,
        attempts_started=0,
        selected_attempt_id=None,
        terminal_reason=None,
    )

    digest_jobs = compute_expansion_digest([j2, j1])
    assert digest_jobs == compute_expansion_digest(["id-a", "id-b"])

    # Empty collection
    empty_digest = compute_expansion_digest([])
    assert len(empty_digest) == 64
    assert empty_digest == hashlib.sha256(canonical_bytes([])).hexdigest()


def test_expand_cross_product() -> None:
    pin = _make_pin(case_ids=("case-1", "case-2"))
    manifest = AuditManifest(
        manifest_hash="mhash" + "0" * 59,
        run_id="run-1",
        benchmark_version="v1",
        task_pins=(pin,),
        panel_key="panel@1.0",
        adjudication_version="adj-v1",
        evaluation_harness_version="harn-v1",
        config_hash="conf1" + "0" * 59,
        policy_hash="pol1" + "0" * 60,
        analysis_plan_hash=None,
        timestamp=datetime.now(UTC),
        host_fingerprint="arm64",
        seed=42,
        agent_version=None,
        model_identifier=None,
        max_repetitions=3,
        max_attempts_per_job=3,
        timeout_seconds=120,
        resource_policy="res1" + "0" * 60,
        expansion_digest="exp1" + "0" * 60,
        parent_run_id=None,
    )

    planned = expand(manifest)
    # 1 task * 2 cases * 2 verifiers * 3 repetitions = 12 jobs
    assert len(planned) == 12

    # Verify repetitions for case-1 and baseline
    case1_base = [
        j for j in planned if j.case_id == "case-1" and j.verifier_key == "base@1.0"
    ]
    assert len(case1_base) == 3
    assert [j.repetition for j in case1_base] == [0, 1, 2]
    assert all(j.state == "PENDING" for j in planned)
    assert all(j.fence == 0 for j in planned)
    assert all(j.attempts_started == 0 for j in planned)
    assert all(j.attempt_id is None for j in planned)
    assert all(j.lease_token is None for j in planned)
    assert all(j.run_id == "run-1" for j in planned)

    # Invariant: sorted deterministically by (task_key, case_id, verifier_key, repetition)
    keys = [(j.task_key, j.case_id, j.verifier_key, j.repetition) for j in planned]
    assert keys == sorted(keys)


def test_expand_deduplication() -> None:
    # Same baseline and candidate verifier should deduplicate so duplicate jobs are not created
    pin_same_verifiers = _make_pin(
        case_ids=("case-1", "case-1"),  # duplicate case id
        baseline="same@1.0",
        candidate="same@1.0",
    )
    manifest = AuditManifest(
        manifest_hash="mhash" + "0" * 59,
        run_id="run-dedup",
        benchmark_version="v1",
        task_pins=(pin_same_verifiers,),
        panel_key="panel@1.0",
        adjudication_version="adj-v1",
        evaluation_harness_version="harn-v1",
        config_hash="conf1" + "0" * 59,
        policy_hash="pol1" + "0" * 60,
        analysis_plan_hash=None,
        timestamp=datetime.now(UTC),
        host_fingerprint="arm64",
        seed=None,
        agent_version=None,
        model_identifier=None,
        max_repetitions=2,
        max_attempts_per_job=3,
        timeout_seconds=120,
        resource_policy="res1" + "0" * 60,
        expansion_digest="exp1" + "0" * 60,
        parent_run_id=None,
    )

    planned = expand(manifest)
    # 1 task * 1 unique case * 1 unique verifier * 2 repetitions = 2 jobs
    assert len(planned) == 2
    assert planned[0].repetition == 0
    assert planned[1].repetition == 1
    assert planned[0].job_id != planned[1].job_id


def test_expand_panel_fallback() -> None:
    # Pin with empty case_ids falls back to panel memberships
    pin_empty_cases = _make_pin(case_ids=())

    @dataclass(frozen=True, slots=True)
    class ExtendedPanel(PatchPanel):
        memberships: tuple[PatchPanelMembership, ...] = ()

    m1 = PatchPanelMembership(
        panel_key="panel@1.0",
        case_id="case-p1",
        adjudication_id="adj-1",
        ordinal=1,
        expected_control_outcomes={},
    )
    m2 = PatchPanelMembership(
        panel_key="panel@1.0",
        case_id="case-p2",
        adjudication_id="adj-2",
        ordinal=2,
        expected_control_outcomes={},
    )
    panel = ExtendedPanel(
        panel_key="panel@1.0",
        panel_id="panel-1",
        version="1.0",
        split="development",
        membership_digest="m" + "0" * 63,
        sampling_policy="default",
        exposed_at=None,
        development_used_at=None,
        sealed_at=None,
        retired_at=None,
        parent_panel_key=None,
        memberships=(m1, m2),
    )

    manifest = AuditManifest(
        manifest_hash="mhash" + "0" * 59,
        run_id="run-panel-fallback",
        benchmark_version="v1",
        task_pins=(pin_empty_cases,),
        panel_key="panel@1.0",
        adjudication_version="adj-v1",
        evaluation_harness_version="harn-v1",
        config_hash="conf1" + "0" * 59,
        policy_hash="pol1" + "0" * 60,
        analysis_plan_hash=None,
        timestamp=datetime.now(UTC),
        host_fingerprint="arm64",
        seed=None,
        agent_version=None,
        model_identifier=None,
        max_repetitions=1,
        max_attempts_per_job=3,
        timeout_seconds=120,
        resource_policy="res1" + "0" * 60,
        expansion_digest="exp1" + "0" * 60,
        parent_run_id=None,
    )

    planned = expand(manifest, panel=panel)
    # 1 task * 2 panel cases * 2 verifiers * 1 repetition = 4 jobs
    assert len(planned) == 4
    case_ids = {j.case_id for j in planned}
    assert case_ids == {"case-p1", "case-p2"}


def test_build_manifest() -> None:
    pin = _make_pin(case_ids=("case-1",))
    fixed_time = datetime(2026, 11, 24, 12, 0, 0, tzinfo=UTC)
    manifest = build_manifest(
        run_id="run-test",
        task_pins=(pin,),
        panel_key="panel-1",
        adjudication_version="adj-1",
        policy_hash="pol-1",
        repetitions=2,
        timestamp=fixed_time,
    )
    assert manifest.run_id == "run-test"
    assert manifest.max_repetitions == 2
    assert len(manifest.manifest_hash) == 64
    assert len(manifest.expansion_digest) == 64
    assert manifest.timestamp == fixed_time

    # Same inputs yield identical manifest_hash
    manifest2 = build_manifest(
        run_id="run-test",
        task_pins=(pin,),
        panel_key="panel-1",
        adjudication_version="adj-1",
        policy_hash="pol-1",
        repetitions=2,
        timestamp=fixed_time,
    )
    assert manifest.manifest_hash == manifest2.manifest_hash
    assert manifest.expansion_digest == manifest2.expansion_digest

    # Immutable
    with pytest.raises(dataclasses.FrozenInstanceError):
        manifest.run_id = "mutated"  # type: ignore[misc]


def test_build_manifest_validation_errors() -> None:
    pin = _make_pin()

    # Empty task pins
    with pytest.raises(ValidationError, match="requires at least one TaskPin") as exc:
        build_manifest(task_pins=())
    assert exc.value.code == ErrorCode.VALIDATION_ERROR.value

    # Duplicate task_key
    pin_dup = _make_pin(task_key=pin.task_key)
    with pytest.raises(ValidationError, match="Duplicate task pin") as exc:
        build_manifest(task_pins=(pin, pin_dup))
    assert exc.value.code == ErrorCode.VALIDATION_ERROR.value

    # Invalid repetitions (< 1)
    with pytest.raises(ValidationError, match="max_repetitions must be >= 1") as exc:
        build_manifest(task_pins=(pin,), repetitions=0)
    assert exc.value.code == ErrorCode.VALIDATION_ERROR.value

    # Invalid max_attempts (< 1 or > 3)
    with pytest.raises(
        ValidationError, match="max_attempts_per_job must be between 1 and 3"
    ) as exc:
        build_manifest(task_pins=(pin,), max_attempts=0)
    assert exc.value.code == ErrorCode.VALIDATION_ERROR.value

    with pytest.raises(
        ValidationError, match="max_attempts_per_job must be between 1 and 3"
    ) as exc:
        build_manifest(task_pins=(pin,), max_attempts=4)
    assert exc.value.code == ErrorCode.VALIDATION_ERROR.value

    # Invalid timeout (<= 0)
    with pytest.raises(ValidationError, match="timeout_seconds must be > 0") as exc:
        build_manifest(task_pins=(pin,), timeout_seconds=0)
    assert exc.value.code == ErrorCode.VALIDATION_ERROR.value


def test_build_manifest_max_jobs_capping() -> None:
    # 1 task * 2 cases * 2 verifiers * 3 repetitions = 12 jobs
    pin = _make_pin(case_ids=("case-1", "case-2"))

    # Explicit max_jobs ceiling
    with pytest.raises(ValidationError, match="exceeds max_jobs ceiling") as exc:
        build_manifest(task_pins=(pin,), repetitions=3, max_jobs=10)
    assert exc.value.code == ErrorCode.RESOURCE_EXHAUSTED.value

    # Exactly 12 jobs permitted
    m_ok = build_manifest(task_pins=(pin,), repetitions=3, max_jobs=12)
    assert len(expand(m_ok)) == 12

    # SandboxPolicy max_jobs capping
    policy = SandboxPolicy(
        policy_hash="p" + "0" * 63,
        cpus=2.0,
        memory_bytes=2 * 1024 * 1024 * 1024,
        pids=128,
        wall_seconds=120,
        cleanup_grace_seconds=5,
        workspace_bytes=2 * 1024 * 1024 * 1024,
        workspace_inodes=100000,
        tmp_bytes=128 * 1024 * 1024,
        artifact_bytes=16 * 1024 * 1024,
        stream_bytes=4 * 1024 * 1024,
        artifact_files=64,
        network="none",
        seccomp_digest="s" + "0" * 63,
        max_jobs=5,
        max_concurrency=1,
    )
    with pytest.raises(ValidationError, match="exceeds max_jobs ceiling") as exc:
        build_manifest(task_pins=(pin,), repetitions=3, policy=policy)
    assert exc.value.code == ErrorCode.RESOURCE_EXHAUSTED.value


def test_plan_audit_end_to_end() -> None:
    pin1 = _make_pin(task_key="task-a@1.0", case_ids=("c1", "c2"))
    pin2 = _make_pin(task_key="task-b@1.0", case_ids=("c3",))

    options = AuditOptions(
        task_files=("task1.yaml", "task2.yaml"),
        benchmark_file=None,
        panel_file="panel.yaml",
        baseline_file="base.yaml",
        candidate_file="cand.yaml",
        repetitions=2,
        backend="fixture",
        trusted_fixture=True,
        sandbox_policy_file="sandbox.yaml",
        max_attempts=2,
        offline=True,
        output_dir=None,
        dry_run=False,
        resume_run_id=None,
        parent_run_id="parent-run-123",
        policy_file="policy.yaml",
        analysis_plan_file=None,
        max_jobs=50,
        concurrency=1,
        timeout_seconds=60,
        seed=12345,
        collect_only=False,
        diagnostic=False,
    )

    manifest, jobs = plan_audit(options=options, task_pins=(pin1, pin2))

    assert isinstance(manifest, AuditManifest)
    assert isinstance(jobs, tuple)
    # (2 cases + 1 case) * 2 verifiers * 2 repetitions = 12 jobs
    assert len(jobs) == 12
    assert manifest.max_repetitions == 2
    assert manifest.max_attempts_per_job == 2
    assert manifest.timeout_seconds == 60
    assert manifest.seed == 12345
    assert manifest.parent_run_id == "parent-run-123"

    # Invariant: Job identities match expansion_digest
    assert compute_expansion_digest(jobs) == manifest.expansion_digest

    # Invariant: Each job is uniquely keyed and properly initialized
    job_ids = {j.job_id for j in jobs}
    assert len(job_ids) == len(jobs)
    assert all(j.state == "PENDING" for j in jobs)
    assert all(j.run_id == manifest.run_id for j in jobs)


def test_plan_jobs_backward_compat() -> None:
    jobs_list = plan_jobs(["task-1", "task-2"])
    assert isinstance(jobs_list, list)
    assert len(jobs_list) == 2
    assert all(isinstance(j, Job) for j in jobs_list)
    assert [j.task_key for j in jobs_list] == ["task-1", "task-2"]
