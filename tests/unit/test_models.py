"""Unit tests for domain dataclasses, canonical hashing, and protocol serialization.

SDD Sections 4.1, 4.4, 5, and Section 9.1 invariants.
"""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta, timezone

import pytest

from verifierci.errors import ValidationError
from verifierci.models import (
    Contract,
    EvaluationAttempt,
    PatchCase,
    Requirement,
    ResourceUsage,
    ReviewVote,
    Task,
    VerifierManifest,
    VerifierVersion,
    canonical_bytes,
    compare_versions,
    contract_hash,
    decode_record,
    encode_record,
    manifest_hash,
    requirement_hash,
    resolve_command,
    validate_attempt,
    validate_lineage,
    validate_task,
    validate_verifier,
    validate_wire_version,
)


def _sample_requirement(
    req_id: str = "REQ-1", text: str = "Must return 0"
) -> Requirement:
    r_hash = requirement_hash(
        {
            "requirement_id": req_id,
            "text": text,
            "source_kind": "explicit",
            "evidence_digests": ("a" * 64,),
            "source_locator": "line 10",
            "allowed_variation": "none",
        }
    )
    return Requirement(
        requirement_hash=r_hash,
        requirement_id=req_id,
        text=text,
        source_kind="explicit",
        evidence_digests=("a" * 64,),
        source_locator="line 10",
        allowed_variation="none",
    )


def _sample_contract(req_hashes: tuple[str, ...] = ()) -> Contract:
    c_hash = contract_hash(
        {
            "task_id": "task-1",
            "version": "1.0.0",
            "requirement_hashes": req_hashes,
            "allowed_variation": "standard",
            "unresolved_questions": (),
            "evidence_digests": ("b" * 64,),
        }
    )
    return Contract(
        contract_hash=c_hash,
        task_id="task-1",
        version="1.0.0",
        requirement_hashes=req_hashes,
        allowed_variation="standard",
        unresolved_questions=(),
        evidence_digests=("b" * 64,),
        created_at=datetime(2026, 9, 18, 12, 0, 0, tzinfo=UTC),
    )


def test_dataclass_immutability():
    req = _sample_requirement()
    with pytest.raises(FrozenInstanceError):
        req.text = "modified"  # type: ignore[misc]

    contract = _sample_contract()
    with pytest.raises(FrozenInstanceError):
        contract.version = "2.0.0"  # type: ignore[misc]

    task = Task(
        task_key="task-1@1.0.0",
        task_id="task-1",
        version="1.0.0",
        statement="Do something",
        adapter="local",
        contract_hash=contract.contract_hash,
        snapshot_digest="c" * 64,
        environment_id="env-1",
        licence="Apache-2.0",
        provenance="source",
        eligibility="eligible",
        notes="",
        created_at=datetime.now(UTC),
    )
    with pytest.raises(FrozenInstanceError):
        task.statement = "New statement"  # type: ignore[misc]


def test_canonical_json_key_order_invariance():
    d1 = {"z": 1, "a": 2, "m": {"y": 10, "b": 20}}
    d2 = {"a": 2, "m": {"b": 20, "y": 10}, "z": 1}
    assert canonical_bytes(d1) == canonical_bytes(d2)


def test_canonical_json_non_finite_float_rejected():
    with pytest.raises(ValidationError, match="Non-finite float"):
        canonical_bytes({"val": float("nan")})

    with pytest.raises(ValidationError, match="Non-finite float"):
        canonical_bytes({"val": float("inf")})


def test_canonical_json_naive_datetime_rejected():
    with pytest.raises(ValidationError, match="Datetime must be timezone-aware"):
        canonical_bytes({"time": datetime(2026, 9, 18, 12, 0, 0)})  # noqa: DTZ001


def test_requirement_hash_alters_on_any_field():
    base = {
        "requirement_id": "REQ-1",
        "text": "Must retry 3 times",
        "source_kind": "explicit",
        "evidence_digests": ("a" * 64,),
        "source_locator": "spec.md",
        "allowed_variation": "none",
    }
    base_hash = requirement_hash(base)
    assert len(base_hash) == 64
    assert base_hash.islower()

    # Changing each field must alter requirement_hash
    for key, new_val in [
        ("requirement_id", "REQ-2"),
        ("text", "Must retry 4 times"),
        ("source_kind", "repository"),
        ("evidence_digests", ("b" * 64,)),
        ("source_locator", "spec2.md"),
        ("allowed_variation", "recursion allowed"),
    ]:
        modified = dict(base)
        modified[key] = new_val
        assert requirement_hash(modified) != base_hash, (
            f"Hash did not change when altering {key}"
        )


def test_contract_hash_changes_on_requirement_change():
    """SDD Section 9.1 required test:

    Same statement, changed legitimate requirement/evidence.
    Different contract hash and required new task version.
    """
    req1 = _sample_requirement("REQ-1", "Must return immediately on permanent error")
    req2 = _sample_requirement("REQ-1", "Must retry permanent error up to 3 times")

    c1 = _sample_contract(req_hashes=(req1.requirement_hash,))
    c2 = _sample_contract(req_hashes=(req2.requirement_hash,))

    assert req1.requirement_hash != req2.requirement_hash
    assert c1.contract_hash != c2.contract_hash


def test_compare_versions():
    assert compare_versions("1.0.0", "1.0.1") == -1
    assert compare_versions("1.0.0", "1.0.0") == 0
    assert compare_versions("2.1.0", "2.0.9") == 1
    with pytest.raises(ValidationError):
        compare_versions("invalid.version!", "1.0.0")


def test_validate_task():
    req = _sample_requirement()
    contract = _sample_contract((req.requirement_hash,))

    valid_task = Task(
        task_key="task-1@1.0.0",
        task_id="task-1",
        version="1.0.0",
        statement="Implement retry",
        adapter="local",
        contract_hash=contract.contract_hash,
        snapshot_digest="0" * 64,
        environment_id="env-fixture-1",
        licence="Apache-2.0",
        provenance="repo",
        eligibility="eligible",
        notes="",
        created_at=datetime.now(UTC),
    )
    # Should not raise
    validate_task(valid_task, contract)

    # Key mismatch
    bad_key_task = Task(
        task_key="task-wrong@1.0.0",
        task_id="task-1",
        version="1.0.0",
        statement="Implement retry",
        adapter="local",
        contract_hash=contract.contract_hash,
        snapshot_digest="0" * 64,
        environment_id="env-fixture-1",
        licence="Apache-2.0",
        provenance="repo",
        eligibility="eligible",
        notes="",
        created_at=datetime.now(UTC),
    )
    with pytest.raises(ValidationError, match="task_key"):
        validate_task(bad_key_task, contract)

    # Naive created_at
    naive_dt_task = Task(
        task_key="task-1@1.0.0",
        task_id="task-1",
        version="1.0.0",
        statement="Implement retry",
        adapter="local",
        contract_hash=contract.contract_hash,
        snapshot_digest="0" * 64,
        environment_id="env-fixture-1",
        licence="Apache-2.0",
        provenance="repo",
        eligibility="eligible",
        notes="",
        created_at=datetime(2026, 9, 18, 16, 0, 0),
    )
    with pytest.raises(ValidationError, match="timezone-aware UTC"):
        validate_task(naive_dt_task, contract)

    # Non-UTC timezone
    est_task = Task(
        task_key="task-1@1.0.0",
        task_id="task-1",
        version="1.0.0",
        statement="Implement retry",
        adapter="local",
        contract_hash=contract.contract_hash,
        snapshot_digest="0" * 64,
        environment_id="env-fixture-1",
        licence="Apache-2.0",
        provenance="repo",
        eligibility="eligible",
        notes="",
        created_at=datetime(2026, 9, 18, 16, 0, 0, tzinfo=timezone(timedelta(hours=5))),
    )
    with pytest.raises(ValidationError, match="timezone-aware UTC"):
        validate_task(est_task, contract)


def test_resolve_command_placeholders():
    template = ("pytest", "{workspace}", "--output", "{out}", "--seed", "{seed}")
    paths = {
        "workspace": "/tmp/work",
        "out": "/tmp/work/out.json",
        "seed": "42",
    }
    cmd = resolve_command(template, paths)
    assert cmd.argv == (
        "pytest",
        "/tmp/work",
        "--output",
        "/tmp/work/out.json",
        "--seed",
        "42",
    )

    # Partial substitution is strictly prohibited
    bad_template = ("pytest", "--workspace={workspace}")
    with pytest.raises(ValidationError, match="Only whole-token placeholders"):
        resolve_command(bad_template, paths)

    # Unknown placeholder
    unknown_template = ("pytest", "{unknown}")
    with pytest.raises(ValidationError, match="Only whole-token placeholders"):
        resolve_command(unknown_template, paths)


def test_validate_attempt():
    resources = ResourceUsage(
        duration=1.2,
        allocated_cpu=2.0,
        cpu_seconds=0.8,
        peak_memory=1024 * 1024,
        model_usage=None,
        estimated_cost=None,
        pricing_version=None,
        bytes_written=500,
    )

    # Valid completed attempt
    valid_attempt = EvaluationAttempt(
        attempt_id="att-1",
        job_id="job-1",
        fence=1,
        outcome="accept",
        evaluation_validity="valid",
        error_code=None,
        disposition="authoritative",
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        exit_code=0,
        stdout_hash="0" * 64,
        stderr_hash="0" * 64,
        report_digest="0" * 64,
        test_collection=("test_1",),
        tests_passed=1,
        tests_failed=0,
        resources=resources,
        artifact_digests=(),
        capture_truncated=False,
    )
    validate_attempt(valid_attempt)

    # flaky is prohibited on an individual attempt
    flaky_attempt = EvaluationAttempt(
        attempt_id="att-2",
        job_id="job-1",
        fence=1,
        outcome="flaky",  # type: ignore[arg-type]
        evaluation_validity="valid",
        error_code=None,
        disposition="authoritative",
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        exit_code=0,
        stdout_hash=None,
        stderr_hash=None,
        report_digest=None,
        test_collection=(),
        tests_passed=None,
        tests_failed=None,
        resources=resources,
        artifact_digests=(),
        capture_truncated=False,
    )
    with pytest.raises(ValidationError, match="flaky"):
        validate_attempt(flaky_attempt)


def test_validate_lineage_cycle_detection():
    now = datetime.now(UTC)
    c1 = PatchCase(
        case_id="case-1",
        task_key="t@1",
        diff_digest="0" * 64,
        base_snapshot_digest="0" * 64,
        source="human",
        source_run_id=None,
        parent_case_ids=("case-2",),
        family_id="f1",
        role="challenge",
        provenance_digest="0" * 64,
        licence="Apache-2.0",
        created_at=now,
    )
    c2 = PatchCase(
        case_id="case-2",
        task_key="t@1",
        diff_digest="1" * 64,
        base_snapshot_digest="0" * 64,
        source="human",
        source_run_id=None,
        parent_case_ids=("case-1",),
        family_id="f1",
        role="challenge",
        provenance_digest="0" * 64,
        licence="Apache-2.0",
        created_at=now,
    )
    with pytest.raises(ValidationError, match="Lineage cycle detected"):
        validate_lineage((c1, c2))


def test_protocol_encode_decode_roundtrip():
    vote = ReviewVote(
        reviewer_id="rev-1",
        label="valid",
        rationale="All requirements verified",
        minutes=15.5,
        blinded_to_verifier=True,
        independent_of_author=True,
        recorded_at=datetime(2026, 9, 18, 14, 30, 0, tzinfo=UTC),
    )
    encoded = encode_record(vote)
    decoded = decode_record("ReviewVote", encoded)
    assert decoded == vote

    req = _sample_requirement()
    enc_req = encode_record(req)
    dec_req = decode_record("Requirement", enc_req)
    assert dec_req == req


def test_protocol_decode_duplicate_key_rejected():
    bad_payload = b'{"reviewer_id":"1","label":"valid","reviewer_id":"2"}'
    with pytest.raises(ValidationError, match="Duplicate JSON key"):
        decode_record("ReviewVote", bad_payload)


def test_protocol_decode_oversize_rejected():
    payload = b'{"text": "abc"}'
    with pytest.raises(ValidationError, match="exceeds maximum"):
        decode_record("Requirement", payload, max_bytes=5)


def test_validate_wire_version():
    validate_wire_version("1.0")
    with pytest.raises(ValidationError, match="Unsupported wire version"):
        validate_wire_version("99.0")


def test_verifier_manifest_and_version():
    m_dict = {
        "mode": "compatibility",
        "command": ("pytest", "-q"),
        "build_command": (),
        "expected_collection": ("test_a",),
        "parser_id": "pytest-report-v1",
        "report_path": "report.json",
        "payload_digest": "d" * 64,
        "allowed_edit_paths": ("src/",),
        "required_pass_ids": ("test_a",),
        "permitted_skips": (),
        "timeout_seconds": 60,
    }
    m_hash = manifest_hash(m_dict)
    assert len(m_hash) == 64

    manifest = VerifierManifest(manifest_hash=m_hash, **m_dict)  # type: ignore[arg-type]
    version = VerifierVersion(
        verifier_key="v-1@1.0.0",
        verifier_id="v-1",
        version="1.0.0",
        parent_key=None,
        manifest_hash=m_hash,
        payload_digest="d" * 64,
        compatible_contract_hashes=("c" * 64,),
        created_at=datetime.now(UTC),
    )
    validate_verifier(version, manifest)

    # Bad verifier key
    bad_version = VerifierVersion(
        verifier_key="wrong-key",
        verifier_id="v-1",
        version="1.0.0",
        parent_key=None,
        manifest_hash=m_hash,
        payload_digest="d" * 64,
        compatible_contract_hashes=("c" * 64,),
        created_at=datetime.now(UTC),
    )
    with pytest.raises(ValidationError, match="verifier_key"):
        validate_verifier(bad_version, manifest)


def test_panel_digest_and_membership():
    from verifierci.models import (
        Adjudication,
        PatchPanelMembership,
        panel_digest,
        validate_membership,
    )

    contract = _sample_contract()
    req = _sample_requirement()
    case = PatchCase(
        case_id="case-1",
        task_key="task-1@1.0.0",
        diff_digest="0" * 64,
        base_snapshot_digest="0" * 64,
        source="human",
        source_run_id=None,
        parent_case_ids=(),
        family_id="f-1",
        role="challenge",
        provenance_digest="0" * 64,
        licence="Apache-2.0",
        created_at=datetime.now(UTC),
    )
    review = Adjudication(
        adjudication_id="adj-1",
        case_id="case-1",
        contract_hash=contract.contract_hash,
        version=1,
        label="valid",
        review_status="independent",
        votes=(),
        rationale="Passes all tests",
        requirement_hashes=(req.requirement_hash,),
        witness_ids=(),
        uncertainty="",
        supersedes_id=None,
        created_at=datetime.now(UTC),
    )
    validate_membership(case, review, contract)

    # Membership digest
    m1 = PatchPanelMembership(
        panel_key="p@1",
        case_id="case-1",
        adjudication_id="adj-1",
        ordinal=0,
        expected_control_outcomes={},
    )
    p_digest = panel_digest((m1,))
    assert len(p_digest) == 64


def test_validate_matrix_and_result_digest():
    from verifierci.models import (
        AcceptanceMatrix,
        AuditManifest,
        AuditResult,
        result_digest,
        validate_matrix,
    )

    manifest = AuditManifest(
        manifest_hash="m" * 64,
        run_id="run-123",
        benchmark_version="b-1",
        task_pins=(),
        panel_key="p@1",
        adjudication_version="adj-v1",
        evaluation_harness_version="h-1",
        config_hash="cfg" * 21 + "c",
        policy_hash="pol" * 21 + "p",
        analysis_plan_hash=None,
        timestamp=datetime.now(UTC),
        host_fingerprint="host",
        seed=None,
        agent_version=None,
        model_identifier=None,
        max_repetitions=3,
        max_attempts_per_job=2,
        timeout_seconds=120,
        resource_policy="res",
        expansion_digest="exp" * 21 + "e",
        parent_run_id=None,
    )
    matrix = AcceptanceMatrix(
        matrix_id="mat-1",
        run_id="run-123",
        reducer_version="1.0",
        cells=(),
        complete=True,
        source_attempts_digest="src" * 21 + "s",
        created_at=datetime.now(UTC),
    )
    validate_matrix(matrix, manifest)

    result = AuditResult(
        manifest=manifest,
        matrix=matrix,
        metrics=(),
        gate=None,
        diagnostics=(),
        artifacts=(),
    )
    r_digest = result_digest(result)
    assert len(r_digest) == 64


def test_decode_record_resolves_type_checking_references():
    from verifierci.models import Adjudication, ReviewVote

    data = {
        "adjudication_id": "adj-1",
        "case_id": "case-1",
        "contract_hash": "c" * 64,
        "version": 1,
        "label": "valid",
        "review_status": "independent",
        "votes": [
            {
                "reviewer_id": "rev-1",
                "label": "valid",
                "rationale": "Verified",
                "minutes": 10.0,
                "blinded_to_verifier": True,
                "independent_of_author": True,
                "recorded_at": "2026-09-18T16:00:00Z",
            }
        ],
        "rationale": "All good",
        "requirement_hashes": ["r" * 64],
        "witness_ids": [],
        "uncertainty": "",
        "supersedes_id": None,
        "created_at": "2026-09-18T16:00:00Z",
    }
    payload = json.dumps(data).encode("utf-8")
    decoded = decode_record("Adjudication", payload)
    assert isinstance(decoded, Adjudication)
    assert len(decoded.votes) == 1
    assert isinstance(decoded.votes[0], ReviewVote)
    assert decoded.votes[0].reviewer_id == "rev-1"


def test_decode_record_unwraps_optional_and_union():
    from verifierci.models import Artifact, ParsedOutcome, TestReport

    # Artifact with retention_until present
    art_data = {
        "digest": "a" * 64,
        "kind": "diff",
        "size_bytes": 100,
        "storage_uri": "/path/to/diff",
        "media_type": "text/x-diff",
        "access_policy": "public",
        "retention_until": "2026-09-18T20:00:00Z",
        "available": True,
        "created_at": "2026-09-18T16:00:00Z",
    }
    art = decode_record("Artifact", json.dumps(art_data).encode("utf-8"))
    assert isinstance(art, Artifact)
    assert isinstance(art.retention_until, datetime)
    assert art.retention_until == datetime(2026, 9, 18, 20, 0, 0, tzinfo=UTC)

    # Artifact with retention_until None
    art_data["retention_until"] = None
    art_none = decode_record("Artifact", json.dumps(art_data).encode("utf-8"))
    assert isinstance(art_none, Artifact)
    assert art_none.retention_until is None

    # ParsedOutcome with nested TestReport in report field
    outcome_data = {
        "outcome": "accept",
        "evaluation_validity": "valid",
        "error_code": None,
        "report": {
            "schema_version": "1.0",
            "collected_ids": ["test_1"],
            "results": [
                {
                    "test_id": "test_1",
                    "status": "passed",
                    "duration": 0.5,
                    "failure_digest": None,
                }
            ],
            "completed": True,
            "runner_error": None,
        },
        "evidence_digests": [],
    }
    outcome = decode_record("ParsedOutcome", json.dumps(outcome_data).encode("utf-8"))
    assert isinstance(outcome, ParsedOutcome)
    assert isinstance(outcome.report, TestReport)
    assert outcome.report.collected_ids == ("test_1",)
    assert outcome.report.results[0].status == "passed"


def test_decode_record_rejects_unknown_fields():
    data = {
        "requirement_id": "req-1",
        "description": "Test requirement",
        "rationale": "Rationale",
        "verification_hint": "",
        "tags": ["unit"],
        "version": 1,
        "unexpected_extra_field": "disallowed",
    }
    payload = json.dumps(data).encode("utf-8")
    with pytest.raises(ValidationError, match="Unexpected field"):
        decode_record("Requirement", payload)


def test_register_verifier_stub_raises_not_implemented():
    import sqlite3

    from verifierci.models import register_verifier

    conn = sqlite3.connect(":memory:")
    m_dict = {
        "mode": "compatibility",
        "command": ("pytest", "-q"),
        "build_command": (),
        "expected_collection": ("test_a",),
        "parser_id": "pytest-report-v1",
        "report_path": "report.json",
        "payload_digest": "d" * 64,
        "allowed_edit_paths": ("src/",),
        "required_pass_ids": ("test_a",),
        "permitted_skips": (),
        "timeout_seconds": 60,
    }
    m_hash = manifest_hash(m_dict)
    manifest = VerifierManifest(manifest_hash=m_hash, **m_dict)  # type: ignore[arg-type]
    version = VerifierVersion(
        verifier_key="v-1@1.0.0",
        verifier_id="v-1",
        version="1.0.0",
        parent_key=None,
        manifest_hash=m_hash,
        payload_digest="d" * 64,
        compatible_contract_hashes=("c" * 64,),
        created_at=datetime(2026, 9, 18, 16, 0, 0, tzinfo=UTC),
    )

    with pytest.raises(
        NotImplementedError,
        match="Phase 1 stub: verifier registry persistence is not implemented yet.",
    ):
        register_verifier(conn, version, manifest)

