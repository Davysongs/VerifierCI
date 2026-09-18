"""Top-level CLI for VerifierCI.

This command surface is intentionally minimal in the MVP skeleton.
"""

from __future__ import annotations

import argparse
import sys

from ._version import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="verifierci",
        description="VerifierCI command line scaffold",
    )
    parser.add_argument(
        "--version", action="version", version=f"verifierci {__version__}"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    parser.parse_args(argv)
    return 0


def main_entry() -> int:
    return main(sys.argv[1:])
