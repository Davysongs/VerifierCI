"""Unit tests for VerifierCI typed error hierarchy.

SDD Section 5 & Section 6.1 exit categories.
"""

from __future__ import annotations

from verifierci.errors import (
    ErrorCode,
    IdentityConflict,
    InfrastructureError,
    LeaseLost,
    ProtectionError,
    ValidationError,
    VerifierCIError,
    exit_category,
)


def test_error_inheritance():
    assert issubclass(ProtectionError, VerifierCIError)
    assert issubclass(ValidationError, VerifierCIError)
    assert issubclass(IdentityConflict, ValidationError)
    assert issubclass(InfrastructureError, VerifierCIError)
    assert issubclass(LeaseLost, InfrastructureError)


def test_error_attributes_and_defaults():
    err = ValidationError("Bad input parameter", details={"param": "version"})
    assert err.message == "Bad input parameter"
    assert err.code == ErrorCode.VALIDATION_ERROR.value
    assert err.details == {"param": "version"}
    assert "[VALIDATION_ERROR] Bad input parameter" in str(err)


def test_error_custom_code():
    err = VerifierCIError(
        "Custom diagnostic", code="PATCH_ERROR", details={"diff": "invalid"}
    )
    assert err.code == "PATCH_ERROR"
    assert err.details == {"diff": "invalid"}


def test_exit_categories():
    # Exit 0: Success (None exception)
    assert exit_category(None) == 0

    # Exit 1: ProtectionError
    assert exit_category(ProtectionError("Split reservation violation")) == 1

    # Exit 2: ValidationError & IdentityConflict
    assert exit_category(ValidationError("Schema failure")) == 2
    assert exit_category(IdentityConflict("Immutable ID clash")) == 2

    # Exit 3: InfrastructureError, LeaseLost, or generic failures
    assert exit_category(InfrastructureError("DB connection lost")) == 3
    assert exit_category(LeaseLost("Lease expired")) == 3
    assert exit_category(VerifierCIError("Generic failure")) == 3
    assert exit_category(RuntimeError("Unexpected Python error")) == 3


def test_error_code_wire_normalization():
    # Known wire codes preserve exact enum value
    assert ErrorCode.from_wire("PATCH_ERROR") == ErrorCode.PATCH_ERROR
    assert ErrorCode.normalize_wire("PATCH_ERROR") == "PATCH_ERROR"

    # Unknown wire codes map to UNSUPPORTED_DIAGNOSTIC per SDD Section 5
    assert (
        ErrorCode.from_wire("TOTALLY_UNKNOWN_CODE") == ErrorCode.UNSUPPORTED_DIAGNOSTIC
    )
    assert ErrorCode.normalize_wire("TOTALLY_UNKNOWN_CODE") == "UNSUPPORTED_DIAGNOSTIC"

    # None input produces None
    assert ErrorCode.from_wire(None) is None
    assert ErrorCode.normalize_wire(None) is None


def test_all_sdd_error_codes_defined():
    sdd_codes = [
        "PATCH_ERROR",
        "BUILD_ERROR",
        "COLLECTION_MISMATCH",
        "EMPTY_COLLECTION",
        "TIMEOUT",
        "RESOURCE_EXHAUSTED",
        "ARTIFACT_LIMIT",
        "DIGEST_MISMATCH",
        "IMAGE_UNAVAILABLE",
        "RUNTIME_UNAVAILABLE",
        "LEASE_LOST",
        "CANCELLED",
        "PARSER_ERROR",
        "DATABASE_ERROR",
        "UNSUPPORTED_DIAGNOSTIC",
        "IDENTITY_CONFLICT",
        "VALIDATION_ERROR",
        "PROTECTION_ERROR",
        "INFRASTRUCTURE_ERROR",
        "WORKSPACE_ERROR",
        "SNAPSHOT_UNAVAILABLE",
        "PATH_TRAVERSAL_ERROR",
        "ENVIRONMENT_INCOMPLETE",
        "ARTIFACT_IO_ERROR",
        "MALFORMED_REPORT",
        "CLEANUP_PENDING",
        "UNCLASSIFIED_EXECUTION",
        "EXIT_REPORT_MISMATCH",
        "RESULT_CONFLICT",
        "SOURCE_UNAVAILABLE",
        "INSTANCE_NOT_FOUND",
        "UNSUPPORTED_SOURCE_VERSION",
        "UNRESOLVED_CONTRACT",
    ]
    for code in sdd_codes:
        assert code in ErrorCode.__members__, f"ErrorCode missing {code}"
        assert ErrorCode[code].value == code
