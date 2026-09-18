"""verifierci.telemetry.events — bounded structured event writer (Phase 1).

Emits internal structured events for observability.  Events are bounded in
size; no model keys, raw trajectories or complete container stdout are emitted.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass(frozen=True, slots=True)
class TelemetryEvent:
    """An immutable structured telemetry event."""

    name: str
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(UTC)
    )
    payload: dict[str, Any] = field(default_factory=dict)


class EventWriter:
    """Bounded structured event writer.

    Emits TelemetryEvents to a configured sink.  Sensitive fields are
    excluded before emission.
    """

