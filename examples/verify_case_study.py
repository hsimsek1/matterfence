"""Check saved case-study fingerprints without running a target or changing files."""

import argparse
import json
import re
import sys
from hashlib import file_digest
from pathlib import Path

ARTIFACTS = ("findings.json", "comparison.html")
MAX_MANIFEST_BYTES = 64 * 1024


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject ambiguous JSON objects instead of silently keeping the last value."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate manifest field.")
        result[key] = value
    return result


def _read_hashes(output_dir: Path) -> tuple[dict[str, str], str]:
    """Validate the manifest's checksum fields; metadata is not authenticated."""
    path = output_dir / "manifest.json"
    if path.is_symlink() or not path.is_file():
        raise ValueError("A regular manifest file is required.")
    with path.open("rb") as source:
        raw = source.read(MAX_MANIFEST_BYTES + 1)
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError("Manifest exceeds the size limit.")
    try:
        manifest = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except RecursionError:
        raise ValueError("Manifest nesting exceeds decoder limits.") from None
    if not isinstance(manifest, dict) or manifest.get("schema_version") != "1.0":
        raise ValueError("Unsupported manifest format.")
    artifacts = manifest.get("artifacts_sha256")
    if not isinstance(artifacts, dict) or set(artifacts) != set(ARTIFACTS):
        raise ValueError("Manifest must identify exactly the two known artifacts.")
    fixture_hash = manifest.get("fixture_sha256")
    for digest in (*artifacts.values(), fixture_hash):
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("Invalid SHA-256 fingerprint.")
    return artifacts, fixture_hash


def _file_hash(path: Path) -> str:
    """Stream a regular file into SHA-256 rather than loading it all into memory."""
    if path.is_symlink() or not path.is_file():
        raise ValueError("A regular evidence or fixture file is required.")
    with path.open("rb") as source:
        return file_digest(source, "sha256").hexdigest()


def verify_evidence(output_dir: Path, fixture: Path | None = None) -> dict[str, bool]:
    """Return byte-match results for fixed artifact names and an optional fixture."""
    artifacts, fixture_hash = _read_hashes(output_dir)
    # Never turn arbitrary manifest keys or metadata into filesystem paths.
    checks = {
        name: _file_hash(output_dir / name) == artifacts[name]
        for name in ARTIFACTS
    }
    if fixture is not None:
        checks["fixture"] = _file_hash(fixture) == fixture_hash
    return checks


def main(argv: list[str] | None = None) -> int:
    """Print checksum matches; return 0 for matches, 1 for mismatch, 2 for errors."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--fixture", type=Path, help="Also check this explicit fixture.")
    args = parser.parse_args(argv)
    try:
        checks = verify_evidence(args.output_dir, args.fixture)
    except (OSError, ValueError):
        parser.exit(
            2, "Unable to verify: use a readable, complete evidence folder with a "
            "supported manifest and regular, non-symlink files.\n",
        )
    print("Checksum comparison only; matching hashes do not mean a security PASS.")
    for name, matched in checks.items():
        print(f"{name}: {'MATCH' if matched else 'MISMATCH'}")
    if args.fixture is None:
        print("Fixture: NOT CHECKED (use --fixture to select it explicitly).")
    print("Unsigned hashes do not authenticate evidence or its author.")
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
