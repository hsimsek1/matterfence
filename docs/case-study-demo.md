# One command: demonstrate the failure and the repair

This helper removes setup friction from the SQLite case studies. It does
not change verdicts or add model integration. All cases run
through the real HTTP adapter and the existing evaluator and HTML renderer.

## Run it

Install from a repository checkout as described in the
[quickstart](../README.md#install-and-run), activate its virtual environment, and
run from the repository root:

```sh
python -m examples.run_case_study --output-dir case-study-output/auth-demo
```

For the poisoned-exhibit follow-up instead:

```sh
python -m examples.run_case_study --case exhibit --output-dir case-study-output/exhibit-demo
```

For an ethical screen overriding team membership and privileged access:

```sh
python -m examples.run_case_study --case wall --output-dir case-study-output/wall-demo
```

See the [ethical-wall case study](ethical-wall-case-study.md) for the permission
setup and the separately tested authorized-colleague control.

In PowerShell, if the environment is not activated, replace `python` with
`.\.venv\Scripts\python.exe`. No second terminal, port substitution, model key,
or separate server shutdown is needed. Python's SQLite must support FTS5.

Open `comparison.html` inside your selected folder in a browser. The wide-screen
report places `SQLite vulnerable (HTTP)` and `SQLite secure (HTTP)` side by side.
`findings.json` contains the same two findings, vulnerable first. The printed
paths tell you where they were saved. `manifest.json` records the case, scenario,
creation time, and fingerprints described below. Files under `case-study-output/`
are ignored by Git; review any report before sharing it.

All cases should show FAIL then PASS. The permitted timeline (authorization/wall)
or exhibit (exhibit case) should remain present in both results; the forbidden
strategy and its canary should appear only in the vulnerable result. The normal
security exit codes still apply: 0 for all PASS, 1 for a violation, 2 for any
ERROR or a setup/output problem. The intentional FAIL therefore exits **1**,
not 0. The command reports actual verdicts; it does not force the expected pair
or certify that the demonstration matched expectations.

Every invocation needs a **new output directory**, even if the previous folder
is empty. Parent folders are created as needed. Existing destinations are
rejected before a server starts, and each artifact also uses exclusive file
creation. If a run is interrupted or a write fails, a new empty folder or partial
output may remain for inspection. No previous evidence is deleted or replaced;
choose a new folder for the next attempt. Ctrl+C exits 130 after cleanup.

## Identify and check saved evidence

The manifest uses schema version `1.0`. It records `case`, `scenario_id`,
`scenario_version`, and `created_at_utc` (the local machine's clock expressed in
UTC). `fixture_sha256` identifies the exact bytes read and validated at startup.
`artifacts_sha256` maps `findings.json` and `comparison.html` to the SHA-256 of
their saved bytes, including line endings. A whitespace-only fixture edit can
therefore change its hash without changing the scenario's meaning.

The fixture is read once. Both targets use that validated snapshot, and the
manifest fingerprints the same bytes even if the file changes during the run.
This avoids identifying a later fixture revision as the one that was tested.
There are no document bodies, raw responses, or absolute filesystem paths in
the manifest. The findings and HTML retain their existing evidence formats.

For the authorization command above, these PowerShell checks should each print
`True` immediately after a successful export:

```powershell
$evidenceManifest = Get-Content -Raw case-study-output/auth-demo/manifest.json | ConvertFrom-Json
(Get-FileHash -Algorithm SHA256 case-study-output/auth-demo/findings.json).Hash -eq $evidenceManifest.artifacts_sha256.'findings.json'
(Get-FileHash -Algorithm SHA256 case-study-output/auth-demo/comparison.html).Hash -eq $evidenceManifest.artifacts_sha256.'comparison.html'
(Get-FileHash -Algorithm SHA256 matterfence/core/mf_auth_001.json).Hash -eq $evidenceManifest.fixture_sha256
```

Use the corresponding output folder and `examples/poisoned_exhibit.json` or
`examples/ethical_wall.json` for the other cases. A mismatch means the bytes do
not match the saved fingerprint; it does not diagnose why they changed. A later
fixture edit does not invalidate the original run, but requires the original
fixture to reproduce it.

The manifest is written last, after both artifact files and server cleanup.
An export failure exits 2 and may leave partial files for inspection, including
an incomplete manifest if the write itself fails. Existing manifests are never
overwritten. A complete manifest can describe ERROR findings: successful export
is separate from the security verdict. Older outputs have no manifest and are
not retroactively changed.

**These are unsigned checksums, not tamper-proof evidence.** Someone able to edit
both artifacts and manifest can replace the hashes too. The timestamp is not a
trusted timestamp. This slice does not capture the code revision, dependencies,
or runtime environment and does not by itself make a run fully reproducible.
Keep the relevant source revision and environment details alongside important
runs. It does not authenticate the target's observations or prove security.

## Functions to understand

The implementation is [examples/run_case_study.py](../examples/run_case_study.py).

- `_run_mode(scenario, mode, review=...)` receives a validated scenario, a server
  mode, and whether to simulate exhibit review. It loads a fresh SQLite store,
  binds a loopback server to an automatically chosen port, starts its thread,
  and sends the evaluation request using `HttpLegalTarget`. It returns one
  `Finding` after shutting down the thread and closing the socket and database.
  The `finally` block also runs when evaluation raises. Only the target's display
  name changes to include the known startup mode; evidence and verdict are intact.
- `run_comparison(case, output_dir)` selects and validates the matching bundled
  fixture from one byte snapshot, reserves a new output folder, and calls
  `_run_mode` once per mode. It writes `findings.json`, `comparison.html`, and
  `manifest.json`, then returns the two findings.
  Both servers are closed before any report writing begins. Exceptions propagate
  to the caller; it never fabricates successful findings when setup fails.
- `_write_manifest(case, fixture_bytes, scenario, output_dir)` receives the case
  name, original fixture bytes, validated scenario, and artifact folder. It
  fingerprints the fixture bytes in memory and the two files on disk, then
  writes a new UTF-8 `manifest.json`. It returns `None`; read/write errors
  propagate to `main`'s existing safe exit-2 path. `sha256(...).hexdigest()`
  turns bytes into a 64-character hexadecimal fingerprint, not an encrypted copy.
- `main(argv=None)` accepts command arguments (or reads the terminal arguments),
  calls `run_comparison`, prints paths and actual verdicts, and returns their
  exit code. Argument, setup, and write failures exit with a generic message
  instead of exposing raw exception details. The module entry point passes the
  returned code to `sys.exit`.

The [pytest suite](../tests/test_case_study_demo.py) verifies exact permitted and
forbidden IDs, canary evidence, fixture selection, mode labels, and JSON/HTML
agreement through real HTTP for all cases. It observes real threads, sockets,
and stores to prove they close on success and injected startup/evaluation/write
failures. Further tests check preserved output, safe error reporting, ERROR
results on transport failure, and exit-code precedence. Subprocess tests run the
documented module commands and repeat them to verify overwrite protection.
Manifest checks compare all recorded fingerprints with the saved bytes for all
three cases and check the UTC timestamp and absence of document bodies/paths.
A regression changes the fixture during execution: both verdicts and its
recorded hash must still use the original snapshot. Additional tests preserve
an existing manifest, simulate a denied manifest write, and confirm that errors
leave evidence intact, close resources, and exit 2 without raw error details.

## What this does not prove

These are controlled synthetic demonstrations, not third-party product audits.
Servers run sequentially on threads **inside the runner process**, not isolated
processes. The target's existing search and permission code remains independent
of MatterFence's evaluator. For separate processes, follow the manual
[authorization](retrieval-case-study.md) or
[exhibit](poisoned-exhibit-case-study.md) walkthrough.

There is no authentication or real LLM. Exhibit review follows one scripted
instruction; it does not measure how often a model obeys a payload. PASS covers
only observed forbidden retrieval and exact canary disclosure, not answer quality
or general security. Reports omit document bodies and raw responses but include
synthetic identifiers and canaries. This helper lives in the source checkout,
not the installed wheel, and accepts only the three bundled case choices.
