"""verifierci.storage.db — SQLite database layer (Phase 1).

SQLite settings per SDD Section 4.1:
  - Foreign keys enabled
  - WAL on local filesystem
  - synchronous=FULL
  - busy_timeout=5000
  - Schema-versioned migrations executed in a transaction

Immutable content rows reject UPDATE/DELETE through generated triggers.
Operational tables (audit_runs, jobs, active attempts, artifact
locations/availability) have narrow, documented mutations.
"""

from __future__ import annotations

import hashlib
import random
import sqlite3
import time
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import Self

from verifierci.errors import (
    ErrorCode,
    IdentityConflict,
    InfrastructureError,
    ValidationError,
)

DEFAULT_MIGRATIONS_DIR = Path(__file__).parent / "migrations"


def connect(path: Path | str = ":memory:") -> sqlite3.Connection:
    """Create and configure a SQLite connection according to SDD Section 4.1.

    Enforces foreign keys, busy timeout, full synchronisation, WAL mode for disk databases,
    and disables dynamic extension loading.
    """
    path_str = str(path)
    conn = sqlite3.connect(
        path_str,
        isolation_level=None,  # Explicit transaction control
        check_same_thread=False,
    )
    conn.row_factory = sqlite3.Row

    # Pragmas
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA busy_timeout = 5000;")
    conn.execute("PRAGMA synchronous = FULL;")

    is_memory = path_str == ":memory:" or path_str.startswith("file::memory:")
    if not is_memory:
        conn.execute("PRAGMA journal_mode = WAL;")

    if hasattr(conn, "enable_load_extension"):
        try:
            conn.enable_load_extension(False)
        except (AttributeError, sqlite3.OperationalError):
            pass

    return conn


@contextmanager
def transaction(
    conn: sqlite3.Connection,
    *,
    immediate: bool = False,
    timeout: float = 5.0,
) -> Iterator[sqlite3.Connection]:
    """Context manager for SQLite transactions with bounded busy retry.

    Executes BEGIN IMMEDIATE (for write transactions) or standard BEGIN.
    Commits on clean block exit, and rolls back if an exception occurs.
    """
    cmd = "BEGIN IMMEDIATE" if immediate else "BEGIN"
    start_time = time.monotonic()
    delay = 0.01

    timeout_ms = max(1, int(timeout * 1000))
    conn.execute(f"PRAGMA busy_timeout = {timeout_ms};")
    try:
        while True:
            try:
                conn.execute(cmd)
                break
            except sqlite3.OperationalError as exc:
                msg = str(exc).lower()
                if ("locked" in msg or "busy" in msg) and (
                    time.monotonic() - start_time < timeout
                ):
                    sleep_time = delay + random.uniform(0, 0.02)
                    time.sleep(sleep_time)
                    delay = min(0.25, delay * 2)
                else:
                    raise InfrastructureError(
                        f"Failed to acquire transaction lock ({cmd}): {exc}",
                        code=ErrorCode.DATABASE_ERROR.value,
                    ) from exc

        try:
            yield conn
            conn.execute("COMMIT")
        except BaseException:
            if conn.in_transaction:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.OperationalError:
                    pass
            raise
    finally:
        try:
            conn.execute("PRAGMA busy_timeout = 5000;")
        except (sqlite3.OperationalError, sqlite3.ProgrammingError):
            pass


def migrate(
    conn: sqlite3.Connection,
    *,
    target_version: int | None = None,
    migrations_dir: Path | None = None,
) -> int:
    """Discover and apply numbered schema migrations in sorted order.

    Each migration is executed within an atomic transaction alongside its tracking record.
    Verifies checksums of already-applied migrations and runs PRAGMA foreign_key_check.

    Returns the latest applied schema version.
    """
    if migrations_dir is None:
        migrations_dir = DEFAULT_MIGRATIONS_DIR

    # Ensure schema_migrations table exists
    conn.execute("""
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL,
            checksum TEXT NOT NULL
        );
    """)

    # Query already applied migrations
    applied = {
        row["version"]: row["checksum"]
        for row in conn.execute(
            "SELECT version, checksum FROM schema_migrations ORDER BY version ASC"
        ).fetchall()
    }

    if not migrations_dir.exists():
        return max(applied.keys()) if applied else 0

    migration_files = sorted(migrations_dir.glob("*.sql"))
    latest_version = max(applied.keys()) if applied else 0

    for file_path in migration_files:
        prefix = file_path.stem.split("_")[0]
        try:
            version = int(prefix)
        except ValueError:
            continue

        content = file_path.read_text(encoding="utf-8")
        checksum = hashlib.sha256(content.encode("utf-8")).hexdigest()

        if version in applied:
            expected_checksum = applied[version]
            if checksum != expected_checksum:
                raise IdentityConflict(
                    f"Migration {version} ({file_path.name}) checksum mismatch: "
                    f"recorded {expected_checksum}, current {checksum}",
                    code=ErrorCode.IDENTITY_CONFLICT.value,
                )
            continue

        if target_version is not None and version > target_version:
            break

        now_iso = datetime.now(UTC).isoformat()
        script = f"""BEGIN IMMEDIATE;
{content}
"""
        try:
            conn.executescript(script)
            # Pre-commit foreign key integrity check
            fk_violations = conn.execute("PRAGMA foreign_key_check;").fetchall()
            if fk_violations:
                raise ValidationError(
                    f"Foreign key violations detected in migration {version}: {fk_violations}",
                    code=ErrorCode.DATABASE_ERROR.value,
                )
            conn.execute(
                "INSERT INTO schema_migrations (version, applied_at, checksum) VALUES (?, ?, ?);",
                (version, now_iso, checksum),
            )
            conn.execute("COMMIT;")
        except Exception:
            if conn.in_transaction:
                try:
                    conn.execute("ROLLBACK;")
                except sqlite3.OperationalError:
                    pass
            raise

        applied[version] = checksum
        latest_version = version

    # Final post-migration foreign key integrity check
    fk_violations = conn.execute("PRAGMA foreign_key_check;").fetchall()
    if fk_violations:
        raise ValidationError(
            f"Foreign key violations detected after migrations: {fk_violations}",
            code=ErrorCode.DATABASE_ERROR.value,
        )

    return latest_version


class Database:
    """Local-disk SQLite database owning short, fenced claim and completion
    transactions.

    SQLITE_BUSY gets bounded retry; a lost connection aborts a mutation.
    Claim expiry records an abandoned attempt and requeues only eligible jobs.
    The controller is the sole database writer service.
    """

    def __init__(self, path: Path | str = ":memory:") -> None:
        self.path = Path(path) if str(path) != ":memory:" else ":memory:"
        self._conn: sqlite3.Connection | None = None

    @property
    def connection(self) -> sqlite3.Connection:
        """Return the active connection, establishing it if needed."""
        if self._conn is None:
            self._conn = connect(self.path)
        return self._conn

    def connect(self) -> sqlite3.Connection:
        """Create a new independent connection (or return the shared memory connection)."""
        if self.path == ":memory:":
            return self.connection
        return connect(self.path)

    def transaction(
        self,
        *,
        immediate: bool = False,
        timeout: float = 5.0,
    ) -> AbstractContextManager[sqlite3.Connection]:
        """Execute a block within an atomic transaction."""
        return transaction(self.connection, immediate=immediate, timeout=timeout)

    def migrate(
        self,
        *,
        target_version: int | None = None,
        migrations_dir: Path | None = None,
    ) -> int:
        """Apply migrations to the active connection."""
        return migrate(
            self.connection,
            target_version=target_version,
            migrations_dir=migrations_dir,
        )

    def close(self) -> None:
        """Close the underlying connection if open."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()
