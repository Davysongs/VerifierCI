"""Typed error hierarchy for VerifierCI.

SDD Section 5 & 6.1:
Supplies typed, serialisable diagnostics independent of human prose.
Maps exceptions to canonical command exit categories:
  - Exit 1: ProtectionError (policy blocked / BLOCKED)
  - Exit 2: ValidationError / IdentityConflict (invalid input, unresolved comparison, inconclusive)
  - Exit 3: InfrastructureError / LeaseLost (operational/runtime/infrastructure failures)
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any


class ErrorCode(StrEnum):
    """Stable machine-readable error codes defined in SDD Sections 4.2, 5, 7.2, and 7.5."""

    PATCH_ERROR = "PATCH_ERROR"
    BUILD_ERROR = "BUILD_ERROR"
    COLLECTION_MISMATCH = "COLLECTION_MISMATCH"
    EMPTY_COLLECTION = "EMPTY_COLLECTION"
    TIMEOUT = "TIMEOUT"
    RESOURCE_EXHAUSTED = "RESOURCE_EXHAUSTED"
    ARTIFACT_LIMIT = "ARTIFACT_LIMIT"
    DIGEST_MISMATCH = "DIGEST_MISMATCH"
    IMAGE_UNAVAILABLE = "IMAGE_UNAVAILABLE"
    RUNTIME_UNAVAILABLE = "RUNTIME_UNAVAILABLE"
    LEASE_LOST = "LEASE_LOST"
    CANCELLED = "CANCELLED"
    PARSER_ERROR = "PARSER_ERROR"
    DATABASE_ERROR = "DATABASE_ERROR"
    UNSUPPORTED_DIAGNOSTIC = "UNSUPPORTED_DIAGNOSTIC"
    IDENTITY_CONFLICT = "IDENTITY_CONFLICT"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    PROTECTION_ERROR = "PROTECTION_ERROR"
    INFRASTRUCTURE_ERROR = "INFRASTRUCTURE_ERROR"
    WORKSPACE_ERROR = "WORKSPACE_ERROR"
    SNAPSHOT_UNAVAILABLE = "SNAPSHOT_UNAVAILABLE"
    PATH_TRAVERSAL_ERROR = "PATH_TRAVERSAL_ERROR"
    ENVIRONMENT_INCOMPLETE = "ENVIRONMENT_INCOMPLETE"
    ARTIFACT_IO_ERROR = "ARTIFACT_IO_ERROR"
    MALFORMED_REPORT = "MALFORMED_REPORT"
    CLEANUP_PENDING = "CLEANUP_PENDING"
    UNCLASSIFIED_EXECUTION = "UNCLASSIFIED_EXECUTION"
    EXIT_REPORT_MISMATCH = "EXIT_REPORT_MISMATCH"
    RESULT_CONFLICT = "RESULT_CONFLICT"
    SOURCE_UNAVAILABLE = "SOURCE_UNAVAILABLE"
    INSTANCE_NOT_FOUND = "INSTANCE_NOT_FOUND"
    UNSUPPORTED_SOURCE_VERSION = "UNSUPPORTED_SOURCE_VERSION"
    UNRESOLVED_CONTRACT = "UNRESOLVED_CONTRACT"

    @classmethod
    def from_wire(cls, code: str | None) -> ErrorCode | None:
        """Parse or normalize a wire error code string into an ErrorCode.

        SDD Section 5:
        Error codes in 4.2 and 7.2 are an enum with stable wire strings;
        an unknown wire code becomes UNSUPPORTED_DIAGNOSTIC, never pass.
        """
        if code is None:
            return None
        try:
            return cls(code)
        except ValueError:
            return cls.UNSUPPORTED_DIAGNOSTIC

    @classmethod
    def normalize_wire(cls, code: str | None) -> str | None:
        """Normalize a wire error code string, converting unknown codes to UNSUPPORTED_DIAGNOSTIC."""
        parsed = cls.from_wire(code)
        return parsed.value if parsed is not None else None


class VerifierCIError(Exception):
    """Base exception for all VerifierCI errors.

    Exposes code, message, and details for structured serialization.
    """

    default_code: str = ErrorCode.UNSUPPORTED_DIAGNOSTIC.value

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code if code is not None else self.default_code
        self.details = dict(details) if details is not None else {}

    def __str__(self) -> str:
        return f"[{self.code}] {self.message}"


class ProtectionError(VerifierCIError):
    """Raised when a split reservation or protection rule disallows an action (Exit 1)."""

    default_code = ErrorCode.PROTECTION_ERROR.value


class ValidationError(VerifierCIError):
    """Raised on invalid input, schema violation, or comparability conflict (Exit 2)."""

    default_code = ErrorCode.VALIDATION_ERROR.value


class IdentityConflict(ValidationError):
    """Raised when an immutable identifier is reused with conflicting content (Exit 2)."""

    default_code = ErrorCode.IDENTITY_CONFLICT.value


class InfrastructureError(VerifierCIError):
    """Raised on database, filesystem, runtime, or operational failure (Exit 3)."""

    default_code = ErrorCode.INFRASTRUCTURE_ERROR.value


class LeaseLost(InfrastructureError):
    """Raised when a worker loses its fencing lease during execution (Exit 3)."""

    default_code = ErrorCode.LEASE_LOST.value


def exit_category(exc: VerifierCIError | Exception | None) -> int:
    """Map an exception to its canonical CLI exit category (SDD Section 6.1).

    0: Success / PASSED
    1: Policy blocked / BLOCKED (ProtectionError)
    2: Input/evidence insufficient / INCONCLUSIVE (ValidationError, IdentityConflict)
    3: Infrastructure error (InfrastructureError, LeaseLost, or unexpected exception)
    """
    if exc is None:
        return 0
    if isinstance(exc, ProtectionError):
        return 1
    if isinstance(exc, (ValidationError, IdentityConflict)):
        return 2
    if isinstance(exc, (InfrastructureError, LeaseLost)):
        return 3
    if isinstance(exc, VerifierCIError):
        return 3
    return 3
