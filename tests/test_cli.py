import json
from pathlib import Path

from click.testing import CliRunner

from pqc_readiness.cli import main


def test_inventory_with_fixture(rsa2048_cert: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["inventory", "--cert", str(rsa2048_cert)])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["specVersion"] == "1.7"


def test_inventory_directory(cert_dir: Path, tmp_path: Path) -> None:
    out = tmp_path / "cbom.json"
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["--quiet", "inventory", "--directory", str(cert_dir), "--output", str(out)],
    )
    assert result.exit_code == 0, result.output
    data = json.loads(out.read_text())
    assert data["specVersion"] == "1.7"
    assert len(data["components"]) >= 5


def test_version_command() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["version"])
    assert result.exit_code == 0
    assert result.output.strip()


def test_algorithms_command(rsa2048_cert: Path) -> None:
    """algorithms subcommand emits tab-separated rows: algo bits oid assessment path."""
    runner = CliRunner()
    result = runner.invoke(main, ["algorithms", "--cert", str(rsa2048_cert)])
    assert result.exit_code == 0
    line = result.output.strip().split("\n")[0]
    fields = line.split("\t")
    assert fields[0] == "RSA"
    assert fields[1] == "2048"
