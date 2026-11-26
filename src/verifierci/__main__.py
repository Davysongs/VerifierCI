"""Package module entry point allowing `python -m verifierci`."""

from __future__ import annotations

from verifierci.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
