import argparse
import subprocess
import sys

from droidforensix import __version__
from droidforensix.cli import build_parser, main


def test_version_command_prints(capsys):
    rc = main(["version"])
    captured = capsys.readouterr()
    assert rc == 0
    assert f"droidforensix {__version__}" in captured.out


def test_parser_exposes_expected_subcommands():
    parser = build_parser()
    commands = set()
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            commands.update(action.choices)
    assert {"analyze", "classify", "serve", "unpack", "version"} <= commands


def test_module_runs_as_main():
    proc = subprocess.run(
        [sys.executable, "-m", "droidforensix", "version"],
        capture_output=True,
        text=True,
        cwd=".",
        timeout=60,
    )
    assert proc.returncode == 0
    assert f"droidforensix {__version__}" in proc.stdout


def test_bad_subcommand_fails():
    try:
        main(["analyze"])  # missing required <apk>
    except SystemExit as e:
        assert e.code == 2
    else:
        raise AssertionError("expected SystemExit for missing required argument")