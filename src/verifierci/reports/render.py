"""verifierci.reports.render — atomic, static report renderer (Phase 1 JSON / Phase 3 HTML).

An in-process renderer produces atomic, static outputs with escaped content
and no external scripts.  A failed render leaves the previous file intact
and returns an infrastructure diagnostic.  Rendering success is distinct
from the audit's gate status.

HTML templates with escaped content arrive in Phase 3.
"""

from __future__ import annotations


class ReportRenderer:
    """Renders audit results to JSON (Phase 1) and escaped HTML (Phase 3).

    Outputs are written atomically: the previous file is preserved on failure.
    """
