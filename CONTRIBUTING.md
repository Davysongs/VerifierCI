# Contributing to VerifierCI

Thanks for your interest in VerifierCI. Contributions should follow the phased architecture and module contracts defined in `build/VerifierCI-Software-Design-Document.md` and `docs/`.

## Development flow

- Keep changes small, narrowly scoped, and aligned with the current implementation phase (currently Phase 1: Minimal Vertical Slice).
- Preserve domain model immutability (`@dataclass(frozen=True, slots=True)`), canonical serialization invariants, and lease-fencing guarantees.
- Include or update unit and integration tests for all behavioral changes.
- Update documentation when project state or module contracts change.

## Validation expectations

Before submitting changes, verify that all checks pass:

- `make lint`
- `ruff check .` and `ruff format --check .`
- `PYTHONPATH=src mypy src tests`
- `make test-unit` and `make test-integration`
