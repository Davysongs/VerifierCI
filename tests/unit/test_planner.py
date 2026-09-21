"""Unit tests for execution planner.

SDD Section 7.1 and 7.4.
Tests deterministic job ID derivation, expansion digest, cross-product job expansion,
manifest construction, and job ordering.
"""

from __future__ import annotations

from datetime import UTC, datetime

from verifierci.execution.planner import (
    build_manifest,
    compute_expansion_digest,
    expand,
    job_id,
    plan_jobs,
)
from verifierci.models.protocol import Job, TaskPin
from verifierci.models.result import AuditManifest


def test_job_id_deterministic() -> None:
    id1 = job_id("run-1", "task@1.0", "case-1", "verifier@1.0", 0)
    id2 = job_id("run-1", "task@1.0", "case-1", "verifier@1.0", 0)
    assert id1 == id2
    assert len(id1) == 64
    assert all(c in "0123456789abcdef" for c in id1)

    # Any change yields different id
    id3 = job_id("run-1", "task@1.0", "case-1", "verifier@1.0", 1)
    assert id1 != id3

    id4 = job_id("run-2", "task@1.0", "case-1", "verifier@1.0", 0)
    assert id1 != id4


def test_compute_expansion_digest() -> None:
    digest1 = compute_expansion_digest(["job-b", "job-a"])
    digest2 = compute_expansion_digest(["job-a", "job-b"])
    # Order-independent because it sorts job_ids
    assert digest1 == digest2
    assert len(digest1) == 64


def test_expand_cross_product() -> None:
    pin = TaskPin(
        task_key="task1@1.0",
        task_version="1.0",
        contract_hash="con1" + "0" * 60,
        repository_snapshot_digest="snap1" + "0" * 59,
        environment_id="env1" + "0" * 60,
        environment_image_digest=None,
        verifier_baseline_version="base@1.0",
        verifier_candidate_version="cand@1.0",
        baseline_manifest_hash="bman1" + "0" * 59,
        candidate_manifest_hash="cman1" + "0" * 59,
        case_ids=("case-1", "case-2"),
    )
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
    assert all(j.run_id == "run-1" for j in planned)


def test_build_manifest() -> None:
    pin = TaskPin(
        task_key="task1@1.0",
        task_version="1.0",
        contract_hash="con1" + "0" * 60,
        repository_snapshot_digest="snap1" + "0" * 59,
        environment_id="env1" + "0" * 60,
        environment_image_digest=None,
        verifier_baseline_version="base@1.0",
        verifier_candidate_version="cand@1.0",
        baseline_manifest_hash="bman1" + "0" * 59,
        candidate_manifest_hash="cman1" + "0" * 59,
        case_ids=("case-1",),
    )
    manifest = build_manifest(
        run_id="run-test",
        task_pins=(pin,),
        panel_key="panel-1",
        adjudication_version="adj-1",
        policy_hash="pol-1",
        repetitions=2,
    )
    assert manifest.run_id == "run-test"
    assert manifest.max_repetitions == 2
    assert len(manifest.manifest_hash) == 64
    assert len(manifest.expansion_digest) == 64


def test_plan_jobs_backward_compat() -> None:
    jobs_list = plan_jobs(["task-1", "task-2"])
    assert isinstance(jobs_list, list)
    assert len(jobs_list) == 2
    assert all(isinstance(j, Job) for j in jobs_list)
    assert [j.task_key for j in jobs_list] == ["task-1", "task-2"]
