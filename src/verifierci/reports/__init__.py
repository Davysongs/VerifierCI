"""verifierci.reports — static report renderers (Phase 1 JSON / Phase 3 HTML)."""

from .render import (
    REPORT_SCHEMA_VERSION,
    ReportRenderer,
    format_json_bytes,
    render_html,
    render_json,
    render_summary,
    serialize_audit_result,
)

__all__ = [
    "REPORT_SCHEMA_VERSION",
    "ReportRenderer",
    "format_json_bytes",
    "render_html",
    "render_json",
    "render_summary",
    "serialize_audit_result",
]
