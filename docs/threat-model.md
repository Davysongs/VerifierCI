# Threat Model

Phase 1 implements local execution and parser-hardening controls for reviewed synthetic fixtures (`adapters/local.py`, `execution/sandbox.py`, `execution/worker.py`, `storage/`):

- **Untrusted manifest & YAML bounds:** 2 MiB size limit, max nesting depth of 32 (`RestrictedSafeLoader`), anchor/alias rejection, and symlink/traversal rejection on referenced files.
- **Isolated patch application & workspaces:** Per-attempt `0700` directories (`source/`, `meta/`, `out/`, `capture/`), `validate_patch` traversal/symlink/allowlist enforcement, and isolated Git invocation (`core.hooksPath=/dev/null`, empty home, `GIT_CEILING_DIRECTORIES`).
- **Subprocess supervision & boundary pinning:** `shell=False`, `start_new_session=True`, minimal allowlisted environment, monotonic wall deadlines with process-group termination, stream byte caps, and non-redirectable `out_dir` boundary checks preventing symlinked report collection into `ArtifactStore`.
- **Storage & queue integrity:** SQLite immutability triggers and lease-fenced `claim`/`heartbeat`/`complete` transactions prevent stale workers from overwriting authoritative results.

**Phase 4 scope:** Rootless Docker/VM container isolation, cgroup limits, and hostile candidate execution are not implemented in Phase 1 and arrive in Phase 4.
