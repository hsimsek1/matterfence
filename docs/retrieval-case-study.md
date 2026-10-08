# Issue #20: reproduce a retrieval leak, apply the filter, retest

This example makes the confidentiality failure concrete: a search for relevant
documents returns another matter's strategy to Bob. Enabling the application's
permission filter removes that document while preserving his permitted timeline.
MatterFence evaluates both runs through the same HTTP adapter.

The target is [one standalone Python file](../examples/retrieval_case_study.py).
It loads the bundled synthetic fixture into an in-memory SQLite search index and
uses no MatterFence imports. Its permissions, search, and returned document IDs
are computed independently of the evaluator. It is still our own controlled
example, not a third-party legal-AI product or a production security assessment.

## Reproduce the case

For an automatic comparison without manual ports or a second terminal, use the
[one-command demo](case-study-demo.md). The steps below retain the separately
running server workflow for inspecting the HTTP integration yourself.

From a repository checkout, install MatterFence and activate its virtual
environment as described in the [quickstart](../README.md#install-and-run).
Python's SQLite must include FTS5; no extra Python dependency or model key is
needed. The example lives in the repository, not the installed wheel.

Create a folder for this run's artifacts (once):

```sh
mkdir case-study-output
git rev-parse HEAD > case-study-output/revision.txt
git hash-object matterfence/core/mf_auth_001.json > case-study-output/fixture-blob.txt
```

Use a clean checkout so the recorded revision identifies the code being run.
The second identifier is Git's content hash of the actual fixture file. Keep
these alongside the findings: both reports use MF-AUTH-001 version 1.0 and the
same actor, prompt, and corpus. The output folder is ignored by Git.

In terminal 1, start the deliberately vulnerable search service:

```sh
python examples/retrieval_case_study.py --mode vulnerable --port 0
```

It prints an endpoint such as `http://127.0.0.1:54321/retrieve`. In terminal 2,
activate the same environment and run the following command, replacing `PORT`
with the printed number:

```sh
python -m matterfence.cli run --target http --endpoint http://127.0.0.1:PORT/retrieve --json --report case-study-output/before.html > case-study-output/before.json
```

Expected: FAIL and exit code 1. The two files should still be saved. Do not use
`&&` to start the next step after this intentional failure.

Stop terminal 1's server with Ctrl+C, then start it with the filter enabled:

```sh
python examples/retrieval_case_study.py --mode secure --port 0
```

Secure mode is also the default when `--mode` is omitted. Copy the **new** port
into terminal 2's command:

```sh
python -m matterfence.cli run --target http --endpoint http://127.0.0.1:PORT/retrieve --json --report case-study-output/after.html > case-study-output/after.json
```

Expected: PASS and exit code 0. Double-click `before.html` and `after.html` to
inspect the evidence, then stop the server with Ctrl+C. Each report requires a
new filename; use a new output folder for a repeat run. JSON redirection can
overwrite an existing JSON file, unlike the protected HTML writer.

In PowerShell, if activation is unavailable, replace `python` with
`.\.venv\Scripts\python.exe`. The commands use `python -m matterfence.cli` so
they do not depend on the separate Windows `matterfence.exe` launcher.

## What the evidence should show

| Observation for Bob | Before: vulnerable | After: secure |
| --- | --- | --- |
| Permitted `DOC_M101_TIMELINE` returned | Yes | Yes |
| Forbidden `DOC_M105_STRATEGY` returned | Yes | No |
| M105 canary in returned text | Yes | No |
| MatterFence verdict | FAIL | PASS |
| Exit code | 1 | 0 |

Both reports label the target `HttpLegalTarget`. That label identifies the
adapter, not the server's mode. Keep the before/after filenames and launch
commands with the evidence. Do not infer which mode ran from the target label.

## The failure and the repair

The app turns the prompt into literal search terms, searches titles and document
bodies, orders matches by relevance, and returns at most five documents. SQLite
[FTS5](https://www.sqlite.org/fts5.html) provides indexed lexical search and the
rank value. The Porter tokenizer lets `timelines` match `timeline`; this is not
semantic search. Only ASCII letters and digits are used for this English demo.

At ingestion, the app builds a table of per-document grants: matter membership
minus ethical screens, with a further privilege check for privileged documents.
The secure SQL query requires a grant for Bob **before** ordering and limiting
the returned rows. The vulnerable setting makes this one predicate always true:

```sql
AND (? = 'vulnerable' OR document_id IN (
    SELECT document_id FROM grants WHERE user_id = ?
))
```

The first parameter is the startup mode; the second is the requesting user.
Clients cannot submit a mode or permission list. Switching mode demonstrates
the effect of adding this predicate while keeping the corpus, search, and
answer assembly fixed. Raw prompt text is never SQL or FTS query syntax: literal
tokens become a quoted `OR` query passed as a bound parameter.

Returned text is a concatenation of selected document bodies, with an ID for
every selected row. There is no LLM answering stage here. SQLite's trusted index
contains the full synthetic corpus; the tested boundary is which records leave
retrieval for the answering step, not which records the search engine indexes.

## Function walkthrough and tests

- `build_store(fixture)` takes the trusted bundled JSON as a dictionary and
  returns a SQLite connection holding users, search documents, and grants.
  It closes a partially built store if ingestion fails. It is not a validator
  for arbitrary uploaded scenarios. Permissions are a startup snapshot.
- `retrieve(store, user_id, prompt, mode)` takes that connection and query input
  and returns a dictionary with `response_text`, `retrieved_document_ids`, and
  `error: None`. Unknown users raise `PermissionError`, including in vulnerable
  mode. Unsupported modes or more than 64 distinct search terms raise
  `ValueError`. A query with no matches returns an observed empty list.
- `create_server(store, mode, port)` returns a bound, serial HTTP server on
  `127.0.0.1`; it does not start it. POST `/retrieve` accepts only nonempty string
  `user_id` and `prompt` fields. It maps bad input, unknown users, and database
  failures to generic errors. GET returns brief usage information. The caller
  owns startup, shutdown, and closing the database connection.
- `main()` reads the startup arguments and bundled file, creates the store and
  server, prints the actual endpoint, and serves until Ctrl+C. Context managers
  close both resources. The demo does not expose a host or custom-fixture option.

The [pytest suite](../tests/test_retrieval_case_study.py) starts real loopback
servers and evaluates them through `HttpLegalTarget`, the runner, and CLI JSON
and HTML output. It checks exact returned IDs and bodies, useful permitted
retrieval, query-dependent matches, screens, privileged access, rejected
identities, literal query syntax, and malformed request handling.

One regression fills the five highest-ranked matches with forbidden documents
and places an allowed match below them. Secure mode must still return the
allowed match. Filtering only after the result limit would incorrectly return
nothing, and that regression would fail.

```sh
python -m pytest -q tests/test_retrieval_case_study.py
python -m ruff check .
```

## Limits of this result

All records are synthetic, and the caller-supplied user ID is a test identity,
not authentication. This serial, loopback-only example is not a production
server. It demonstrates an implemented retrieval authorization failure and its
repair; it does not test model prompt injection, embeddings, answer quality,
production identity checks, or a vendor's legal AI. PASS remains limited to the
observed run and depends on honest, complete retrieval instrumentation.
