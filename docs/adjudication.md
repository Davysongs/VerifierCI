# Adjudication

Immutable adjudication and panel domain models (`PatchCase`, `Witness`, `Adjudication`, `PatchPanel`, `PatchPanelMembership`, `AgentRun`) are defined in `models/panel.py` and backed by the Phase 1 SQLite schema and immutability triggers (`001_initial_schema.sql`, `002_immutability_triggers.sql`).

During Phase 1 matrix reduction (`execution/matrix.py`), frozen adjudication decisions are attached by case identity without consulting verifier outcomes (`unresolved` if unadjudicated; `disputed` must remain `unresolved`). Full multi-reviewer ingestion, witness validation, and irreversible cohort sealing workflows arrive in Phase 6.
