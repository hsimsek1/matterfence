from importlib.metadata import PackageNotFoundError

import pytest
from typer.testing import CliRunner

from matterfence import cli


@pytest.mark.parametrize("installed_version", ["9.8.7", "10.0.0rc1"])
def test_version_command_uses_installed_metadata(monkeypatch, installed_version):
    requested_packages = []

    def recorded_version(package_name):
        requested_packages.append(package_name)
        return installed_version

    monkeypatch.setattr(cli, "package_version", recorded_version)

    result = CliRunner().invoke(cli.app, ["version"])

    assert result.exit_code == 0
    assert requested_packages == ["matterfence"]
    assert result.stdout == f"MatterFence version: {installed_version}\n"
    assert result.stderr == ""


def test_version_command_does_not_invent_missing_metadata(monkeypatch):
    def missing_version(package_name):
        raise PackageNotFoundError(package_name)

    monkeypatch.setattr(cli, "package_version", missing_version)

    result = CliRunner().invoke(cli.app, ["version"])

    assert result.exit_code != 0
    assert isinstance(result.exception, PackageNotFoundError)
    assert result.stdout == ""
