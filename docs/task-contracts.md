# Task Contracts

Task contracts (`models/task.py`: `Task`, `Contract`, `Requirement`, `RepositorySnapshot`, `Environment`) bind normalized requirement specifications to immutable SHA-256 content hashes (`contract_hash`, `requirement_hash`).

In Phase 1, `LocalAdapter` (`adapters/local.py`) parses `task.yaml`, `contract.yaml`, and external `requirement_files`, deduplicates requirement files by resolved identity, preserves explicit `source_locator` values (defaulting external entries to their source filename), and persists normalized entities into the SQLite schema (`contracts`, `requirements`, `contract_requirements`, `tasks`). See `examples/retry-contract/` for the reference Phase 1 contract fixture.
