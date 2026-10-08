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
paths tell you where they were saved. Generated files under `case-study-output/`
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

## Three functions to understand

The implementation is [examples/run_case_study.py](../examples/run_case_study.py).

- `_run_mode(scenario, mode, review=...)` receives a validated scenario, a server
  mode, and whether to simulate exhibit review. It loads a fresh SQLite store,
  binds a loopback server to an automatically chosen port, starts its thread,
  and sends the evaluation request using `HttpLegalTarget`. It returns one
  `Finding` after shutting down the thread and closing the socket and database.
  The `finally` block also runs when evaluation raises. Only the target's display
  name changes to include the known startup mode; evidence and verdict are intact.
- `run_comparison(case, output_dir)` selects and validates the matching bundled
  fixture, reserves a new output folder, and calls `_run_mode` once per mode.
  It writes `findings.json` and `comparison.html`, then returns the two findings.
  Both servers are closed before any report writing begins. Exceptions propagate
  to the caller; it never fabricates successful findings when setup fails.
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
