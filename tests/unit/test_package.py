from __future__ import annotations

from click.testing import CliRunner

from verifierci import __version__
from verifierci.cli import cli, main


def test_version_is_set():
    assert __version__ == "0.1.0"


def test_cli_has_version_and_help_flags():
    runner = CliRunner()
    ver_res = runner.invoke(cli, ["--version"])
    assert ver_res.exit_code == 0
    assert f"verifierci {__version__}" in ver_res.output

    help_res = runner.invoke(cli, ["--help"])
    assert help_res.exit_code == 0
    assert "task" in help_res.output
    assert "panel" in help_res.output
    assert "audit" in help_res.output


def test_main_defaults_to_success():
    assert main([]) == 0
