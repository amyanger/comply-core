"""Tests for the Click CLI."""

from __future__ import annotations

from click.testing import CliRunner

from comply_core.cli import cli


def test_version_flag() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "comply-core" in result.output
    assert "0.1.0" in result.output


def test_help() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "ComplyCore" in result.output


def test_init_help() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["init", "--help"])
    assert result.exit_code == 0
    assert "Set up ComplyCore" in result.output


def test_collect_help() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["collect", "--help"])
    assert result.exit_code == 0
    assert "--controls" in result.output
    assert "--dry-run" in result.output


def test_gaps_help() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["gaps", "--help"])
    assert result.exit_code == 0
    assert "--format" in result.output


def test_verify_help() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["verify", "--help"])
    assert result.exit_code == 0


def test_report_help() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["report", "--help"])
    assert result.exit_code == 0
    assert "--template" in result.output
    assert "--output" in result.output
