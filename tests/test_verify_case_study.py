import json
import subprocess
import sys
from hashlib import sha256
from pathlib import Path

import pytest

from examples import verify_case_study as verifier
from examples.run_case_study import CASES, run_comparison


@pytest.fixture
def evidence(tmp_path):
    directory = tmp_path / "saved evidence"
    directory.mkdir()
    for name, body in {"findings.json": b"[]\r\n", "comparison.html": b"<p>demo</p>\n"}.items():
        (directory / name).write_bytes(body)
    fixture = tmp_path / "fixture.json"
    fixture.write_bytes(b"synthetic fixture bytes")
    manifest = {
        "schema_version": "1.0",
        "fixture_sha256": sha256(fixture.read_bytes()).hexdigest(),
        "artifacts_sha256": {
            name: sha256((directory / name).read_bytes()).hexdigest()
            for name in verifier.ARTIFACTS
        },
    }
    (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return directory, fixture, manifest


def test_matching_bytes_are_checked_without_modification(evidence, capsys):
    directory, fixture, _ = evidence
    original = {path: path.read_bytes() for path in [*directory.iterdir(), fixture]}
    assert verifier.main([str(directory), "--fixture", str(fixture)]) == 0
    assert verifier.verify_evidence(directory, fixture) == {
        "findings.json": True, "comparison.html": True, "fixture": True,
    }
    assert all(path.read_bytes() == body for path, body in original.items())
    output = capsys.readouterr()
    assert "fixture: MATCH" in output.out
    assert "do not mean a security PASS" in output.out
    assert not output.err


@pytest.mark.parametrize("name", ["findings.json", "comparison.html", "fixture"])
def test_changed_bytes_are_mismatch_not_error(evidence, capsys, name):
    directory, fixture, _ = evidence
    path = fixture if name == "fixture" else directory / name
    path.write_bytes(path.read_bytes() + b" ")
    assert verifier.main([str(directory), "--fixture", str(fixture)]) == 1
    output = capsys.readouterr()
    assert f"{name}: MISMATCH" in output.out
    assert not output.err


def test_fixture_is_not_inferred_from_manifest_metadata(evidence, capsys):
    directory, fixture, manifest = evidence
    manifest["fixture_path"] = str(fixture)
    manifest["case"] = "../../outside"
    (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    fixture.write_bytes(b"different")
    assert verifier.main([str(directory)]) == 0
    assert "Fixture: NOT CHECKED" in capsys.readouterr().out
    assert verifier.verify_evidence(directory) == {
        "findings.json": True, "comparison.html": True,
    }


@pytest.mark.parametrize("mutation", [
    "version", "missing_artifact", "extra_path", "absolute_path", "not_a_mapping",
    "bad_digest", "numeric_digest", "missing_fixture_hash", "short_fixture_hash",
])
def test_invalid_checksum_fields_rejected_before_artifact_reads(
    evidence, monkeypatch, capsys, mutation,
):
    directory, _, manifest = evidence
    if mutation == "version":
        manifest["schema_version"] = "2.0"
    elif mutation == "missing_artifact":
        del manifest["artifacts_sha256"]["findings.json"]
    elif mutation in {"extra_path", "absolute_path"}:
        key = "../outside.txt" if mutation == "extra_path" else "C:/outside.txt"
        manifest["artifacts_sha256"][key] = "0" * 64
    elif mutation == "not_a_mapping":
        manifest["artifacts_sha256"] = []
    elif mutation == "bad_digest":
        manifest["artifacts_sha256"]["findings.json"] = "z" * 64
    elif mutation == "numeric_digest":
        manifest["artifacts_sha256"]["findings.json"] = 123
    elif mutation == "missing_fixture_hash":
        del manifest["fixture_sha256"]
    else:
        manifest["fixture_sha256"] = "abc"
    (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    def unexpected_read(path):
        pytest.fail("Invalid manifest must be rejected before hashing artifacts")

    monkeypatch.setattr(verifier, "_file_hash", unexpected_read)
    with pytest.raises(SystemExit) as error:
        verifier.main([str(directory)])
    assert error.value.code == 2
    assert "Unable to verify" in capsys.readouterr().err


@pytest.mark.parametrize("raw", [
    b"{", b"[]", b"null", b"\xff", b" " * (verifier.MAX_MANIFEST_BYTES + 1),
    b'{"schema_version":"1.0","schema_version":"1.0"}',
    b'{"artifacts_sha256":{"findings.json":"a","findings.json":"b"}}',
    b"[" * 2000 + b"0" + b"]" * 2000,
], ids=["truncated", "array", "null", "invalid_utf8", "oversized",
        "duplicate_root", "duplicate_nested", "deeply_nested"])
def test_malformed_or_ambiguous_json_is_rejected(evidence, raw):
    directory, _, _ = evidence
    (directory / "manifest.json").write_bytes(raw)
    with pytest.raises(ValueError):
        verifier.verify_evidence(directory)


@pytest.mark.parametrize("name", ["manifest.json", "findings.json", "comparison.html", "fixture"])
def test_missing_files_are_errors_not_matches(evidence, name):
    directory, fixture, _ = evidence
    path = fixture if name == "fixture" else directory / name
    path.rename(path.with_name(path.name + ".moved"))
    with pytest.raises(SystemExit) as error:
        verifier.main([str(directory), "--fixture", str(fixture)])
    assert error.value.code == 2


@pytest.mark.parametrize("name", ["manifest.json", "findings.json", "comparison.html", "fixture.json"])
def test_symlink_entries_are_rejected(evidence, monkeypatch, name):
    directory, fixture, _ = evidence
    monkeypatch.setattr(Path, "is_symlink", lambda path: path.name == name)
    with pytest.raises(ValueError, match="regular"):
        verifier.verify_evidence(directory, fixture)


def test_filesystem_errors_do_not_expose_details(evidence, monkeypatch, capsys):
    def denied(*args):
        raise PermissionError("private filesystem detail")

    monkeypatch.setattr(verifier, "_file_hash", denied)
    with pytest.raises(SystemExit) as error:
        verifier.main([str(evidence[0])])
    assert error.value.code == 2
    output = capsys.readouterr()
    assert not output.out
    assert "private filesystem detail" not in output.err


def test_matching_rewritten_manifest_is_not_authentication(evidence):
    directory, _, manifest = evidence
    artifact = directory / "comparison.html"
    artifact.write_bytes(b"replaced report")
    manifest["artifacts_sha256"]["comparison.html"] = sha256(artifact.read_bytes()).hexdigest()
    (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert all(verifier.verify_evidence(directory).values())


@pytest.mark.parametrize("case", list(CASES))
def test_documented_module_verifies_actual_demo_with_intentional_fail(tmp_path, case):
    directory = tmp_path / case
    findings = run_comparison(case, directory)
    assert findings[0].status.value == "FAIL"
    result = subprocess.run(
        [sys.executable, "-m", "examples.verify_case_study", str(directory),
         "--fixture", str(CASES[case])],
        cwd=Path(__file__).resolve().parents[1], capture_output=True,
        text=True, timeout=30, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "fixture: MATCH" in result.stdout
    assert "Unsigned hashes do not authenticate" in result.stdout
