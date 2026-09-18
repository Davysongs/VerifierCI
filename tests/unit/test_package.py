from __future__ import annotations

from verifierci import __version__
from verifierci.cli import build_parser, main


def test_version_is_set():
    assert __version__ == "0.0.0"
    assert __version__ == "0.1.0"


def test_parser_has_version_flag():
    parser = build_parser()
    assert "--version" in parser._option_string_actions


def test_main_defaults_to_success():
    assert main([]) == 0
