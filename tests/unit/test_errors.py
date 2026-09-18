"""Unit tests for VerifierCI typed error hierarchy.

SDD Section 5 & Section 6.1 exit categories.
"""

from __future__ import annotations

import pytest

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
    err = VerifierCIError("Custom diagnostic", code="PATCH_ERROR", details={"diff": "invalid"})
    assert err.code == "PATCH_ERROR"
    assert err.details == {"diff": "invalid"}


def test_exit_categories():
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
