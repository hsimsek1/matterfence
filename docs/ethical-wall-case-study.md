# Issue #26: an explicit screen overrides access grants

Bob is a Partner listed on both M101 and M105, with privileged access to M105.
He is also explicitly screened from M105. Alice, an Associate, has the same
membership and privilege grants without that screen. Both may read M101.

This deliberately overlapping configuration tests **deny precedence**: an
explicit screen must win over an otherwise valid grant. A senior role label or
a request to ignore the screen does not change the requesting identity or policy.
The fixture represents a synthetic software access policy, not a determination
of whether any particular legal screen is sufficient.

## Run the comparison

From the repository root, after the [quickstart](../README.md#install-and-run):

```sh
python -m examples.run_case_study --case wall --output-dir case-study-output/wall-demo
```

In PowerShell without activation, replace `python` with
`.\.venv\Scripts\python.exe`. Open the output folder's `comparison.html`;
`findings.json` contains the same evidence. Use a new output folder every time.
Ports and server shutdown are automatic. Expected: vulnerable FAIL, secure PASS,
and command exit code **1** because the vulnerable violation is intentional.

The scenario is `MF-WALL-001-RETRIEVAL`, version 1.0, a retrieval-evidence
companion to the existing `MF-WALL-001` canary-only mock benchmark. It uses the
existing `cross_matter_retrieval` contract and `authorization_canary_v1` detector.

| Observation | Bob, vulnerable | Bob, secure | Alice, secure control |
| --- | --- | --- | --- |
| M101 timeline returned | Yes | Yes | Yes |
| M105 strategy returned | Yes | No | Yes |
| M105 canary disclosed | Yes | No | Yes, permitted |
| Containment finding | FAIL | PASS | Not evaluated as Bob's scenario |

The two report cards compare **Bob's** modes only. Alice's result is verified by
the real-HTTP pytest control, not included as a third report card. The evaluator
requires a scenario-specific forbidden resource; M105 is permitted for Alice,
so applying Bob's prohibited-document list to her would be misleading.

## What enters and leaves the existing functions

No permission algorithm, model, evaluator, or report schema was changed.
The [fixture](../examples/ethical_wall.json) declares the users, grants, screen,
documents, prompt, and expected result. A new entry in the demo's `CASES` mapping
connects `--case wall` to that file. It uses ordinary retrieval, not exhibit review.

- `load_auth_scenario(path)` takes the fixture path and returns a validated
  scenario. For Bob, M105 is denied despite his presence in its team list.
- `build_store(fixture)` takes the scenario dictionary and returns an in-memory
  SQLite connection. It snapshots grants as team members minus screened users,
  further restricted to privileged users for privileged documents. Bob therefore
  gets no M105 document grant; Alice does.
- `retrieve(store, user_id, prompt, mode)` takes the store and request and returns
  selected document bodies, complete selected IDs, and an error field. Secure
  search requires a stored grant before ranking and limiting results. Vulnerable
  search bypasses that filter, including the screen. It is a deliberately broad
  permission bypass, not an implementation that ignores only screens.
- `run_auth_scenario(target, scenario)` takes observed HTTP retrieval and the
  scenario policy and returns a `Finding`. Forbidden IDs or a forbidden matter
  canary produce FAIL. The demo writes these findings to JSON and HTML after
  closing its servers; raw document bodies are not copied into reports.

## How the tests establish the cause

The [wall tests](../tests/test_wall_case_study.py) first assert that Bob really
has both grants and the explicit screen. Through one secure HTTP server they
request the same prompt as Bob, Alice, then Bob again. Alice receives the exact
strategy body; Bob receives only his timeline both times. This guards against
blanket denial and permissions leaking between requests.

Another control removes **only** Bob's screen before building a fresh store:
the same strategy becomes accessible. If team membership or privileged access
is also removed, it remains blocked. Further controls screen Alice or change
Bob's role label and include an impersonation claim in the prompt. Explicit
permissions still determine access, not names embedded in query text or rank.
These policy variations are target controls, not reused containment verdicts
under a stale prohibited-document list.

The [demo tests](../tests/test_case_study_demo.py) additionally run the wall case
through both modes, verify exact IDs and canary evidence, check JSON/HTML agreement
and resource cleanup, and execute the documented command in a subprocess. A
repeat invocation must refuse to overwrite its saved evidence.

## Limits

All data is synthetic. Caller-supplied user IDs are test identities, not
authentication. There is no LLM or semantic search, and the local servers run on
threads in one process. Screens are snapshots at database creation; this does
not test mid-session revocation or cache invalidation. PASS is limited to the
observed retrieval IDs and exact canary, not legal compliance or general security.
