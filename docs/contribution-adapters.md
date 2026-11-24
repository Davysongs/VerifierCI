# Contribution Adapters

Task adapters implement the `TaskAdapter` protocol defined in `src/verifierci/adapters/base.py`, converting pinned task sources into validated `ImportBundle` records.

- **Phase 1 (implemented):** `LocalAdapter` (`src/verifierci/adapters/local.py`) for native local manifests.
- **Phase 5 & Phase 9 (planned):** SWE-bench and Harbor adapters (`build/VerifierCI-Software-Design-Document.md` §5, §13).
