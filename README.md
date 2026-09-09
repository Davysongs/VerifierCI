# VerifierCI

VerifierCI is a production-oriented foundation for auditing coding-agent verifiers.

At this stage, the repository is a clean, minimal MVP skeleton focused on:
- versioned verifier workflows and artifact evidence paths
- explicit task/contracts and adjudication structures
- reproducible local tooling to support incremental engineering

## Technology direction

Current implementation is intentionally narrow and intentionally Python-first:
- `src/verifierci/`: core package and a small CLI surface
- `src/verifierci/models/`: core domain models
- `src/verifierci/adapters/`: execution/verifier integration abstraction points
- `src/verifierci/execution/`: job planning and result primitives
- `src/verifierci/evaluators/`: compatibility and blackbox evaluators
- `schemas/`: versioned JSON schema definitions
- `workers/go/`: stubbed Go worker layout reserved for later scaling phases

No evaluator logic has been implemented yet; this repo is intentionally structured for incremental feature work.

## Local setup

1. Set up Python 3.11+.
2. Install development dependencies:
   - `make install`
3. Run tests:
   - `make test-unit`

## Development commands

- `make install` installs editable package + test dependencies.
- `make lint` runs static compile checks.
- `make test-unit` runs package-level unit tests.
- `make test-integration`, `make test-property`, and `make test-security` are prepared for future layers.
- `make test` currently runs unit tests and can be expanded as test suites grow.

## Implementation status

- ✅ Repository skeleton and package layout in place
- ✅ Core developer tooling and test command structure in place
- ✅ Unit test scaffold and package entrypoint established
- 🟡 No runtime verifier-adaptation logic implemented yet
- 🟡 No worker/runtime supervision stack implemented yet
- 🟡 No benchmark integration or adjudication logic implemented yet
