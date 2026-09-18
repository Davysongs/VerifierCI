"""Unit tests for domain dataclasses, canonical hashing, and protocol serialization.

SDD Sections 4.1, 4.4, 5, and Section 9.1 invariants.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
import math

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
    validate_membership,
    validate_task,
    validate_verifier,
    validate_wire_version,
)


def _sample_requirement(req_id: str = "REQ-1", text: str = "Must return 0") -> Requirement:
    r_hash = requirement_hash({
        "requirement_id": req_id,
        "text": text,
        "source_kind": "explicit",
        "evidence_digests": ("a" * 64,),
        "source_locator": "line 10",
        "allowed_variation": "none",
    })
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
    c_hash = contract_hash({
        "task_id": "task-1",
        "version": "1.0.0",
        "requirement_hashes": req_hashes,
        "allowed_variation": "standard",
        "unresolved_questions": (),
        "evidence_digests": ("b" * 64,),
    })
    return Contract(
        contract_hash=c_hash,
        task_id="task-1",
        version="1.0.0",
        requirement_hashes=req_hashes,
        allowed_variation="standard",
        unresolved_questions=(),
        evidence_digests=("b" * 64,),
        created_at=datetime(2026, 9, 18, 12, 0, 0, tzinfo=timezone.utc),
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
        created_at=datetime.now(timezone.utc),
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
        canonical_bytes({"time": datetime(2026, 9, 18, 12, 0, 0)})


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
        assert requirement_hash(modified) != base_hash, f"Hash did not change when altering {key}"


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
        created_at=datetime.now(timezone.utc),
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
        created_at=datetime.now(timezone.utc),
    )
    with pytest.raises(ValidationError, match="task_key"):
        validate_task(bad_key_task, contract)


def test_resolve_command_placeholders():
    template = ("pytest", "{workspace}", "--output", "{out}", "--seed", "{seed}")
    paths = {
        "workspace": "/tmp/work",
        "out": "/tmp/work/out.json",
        "seed": "42",
    }
    cmd = resolve_command(template, paths)
    assert cmd.argv == ("pytest", "/tmp/work", "--output", "/tmp/work/out.json", "--seed", "42")

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
        started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
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
        started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
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
    now = datetime.now(timezone.utc)
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
        recorded_at=datetime(2026, 9, 18, 14, 30, 0, tzinfo=timezone.utc),
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
