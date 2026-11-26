# Reproducibility

VerifierCI enforces immutable, content-addressed identities across inputs, execution plans, artifacts, and matrices:

- **Canonical serialization (`models/task.py`):** `canonical_bytes` produces deterministic UTF-8 JSON (sorted keys, compact separators, finite numbers, UTC RFC 3339 timestamps) for SHA-256 content hashing.
- **Audit manifests (`execution/planner.py`):** `AuditManifest` fixes task pins, policy hashes, seed, repetitions, timeout ceilings, and `expansion_digest` over sorted deterministic `job_id`s.
- **Content-addressed artifacts (`storage/artifacts.py`):** `ArtifactStore` writes payloads atomically, verifies SHA-256 digests, and guards aggregate byte limits; SQLite immutability triggers (`002_immutability_triggers.sql`) prevent mutation or deletion of protected records.
- **Matrix identity (`execution/matrix.py`):** `AcceptanceMatrix` computes deterministic `source_attempts_digest` and `matrix_id` independent of input ordering, and refuses finalization while any planned job remains pending.
