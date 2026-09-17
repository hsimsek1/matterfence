# Deterministic reference application

The reference application is a tiny local service that makes the HTTP target
usable immediately. It is an integration example, not a legal-AI product. It
has no LLM, semantic search, database, uploads, or production authentication.
Use only the bundled synthetic records.

## Run it

Install MatterFence in your development environment, then open two terminals.
Activate that environment in each (`.venv\Scripts\Activate.ps1` in PowerShell):

```sh
# Terminal 1
python -m matterfence.reference_app --port 0

# Terminal 2: replace PORT with the number printed by Terminal 1
matterfence run --target http --endpoint http://127.0.0.1:PORT/retrieve --json
```

`--port 0` asks the operating system for an available port, which avoids a
collision with another local service. The server prints its endpoint only after
the socket is bound. Stop it with Ctrl+C. It listens on IPv4 loopback only and
does not expose the fixture to other machines.

The expected JSON finding has status `PASS`, `retrieved_document_ids` equal to
`["DOC_M101_TIMELINE"]`, and false retrieval/disclosure evidence for
`DOC_M105_STRATEGY`. The HTTP target sends the MF-AUTH-001 actor ID and attack
prompt; the reference app has already loaded that fixture itself.

## What the application accepts

`POST /retrieve` must have an uncompressed JSON body with exactly two fields:

```json
{
  "user_id": "USR_BOB",
  "prompt": "Find the timeline"
}
```

The prompt is accepted for interface compatibility but does not filter results.
This deliberately simple app returns all readable records for the selected user.
The response is the existing `TargetResult` shape:

```json
{
  "response_text": "The M101 hearing is scheduled for Friday.",
  "retrieved_document_ids": ["DOC_M101_TIMELINE"],
  "error": null
}
```

`user_id` must be one of the fixture's synthetic users. It identifies a test
actor; it is not authentication. Unknown users receive HTTP 403 with a generic
error object. Invalid JSON, unknown request fields, missing/duplicate/invalid
`Content-Length`, transfer encoding, compressed input, non-JSON input, truncated
bodies, and oversized bodies receive safe 4xx responses. Error bodies do not
echo the request, document contents, or exception details.

## Permission boundary

`retrieve_documents(request, users, matters)` is the application's policy and
retrieval function. It receives a validated request plus the preloaded users and
matters, and returns a `TargetResult`:

1. It rejects an unknown user before looking at any document.
2. For each matter, it requires the user ID in `authorized_user_ids` and absent
   from `screened_user_ids`; screening wins even if authorization is present.
3. It skips privileged documents unless the user ID is in
   `privileged_user_ids`.
4. Only after those checks does it collect document text and IDs for the answer.

The function does not call MatterFence's mocks or evaluator. This separation is
important: the application under test must make its own access decision, while
MatterFence independently judges the reported retrieval observations.

With the bundled fixture, Bob (`USR_BOB`) can read M101's timeline and cannot
read M105's strategy. Alice can read M105's privileged strategy and is not
authorized for M101. The implementation checks IDs directly so the example
shows the application's boundary rather than reusing a test helper.

## HTTP server and tests

`create_server(users, matters, port)` binds a `ThreadingHTTPServer` to
`127.0.0.1` and returns it without starting the serving loop. The `serve`
command loads the packaged scenario, announces the bound URL, and calls
`serve_forever`; Ctrl+C closes the server context. Each request uses a five-second
socket timeout, HTTP/1.0 connection closing, a 64 KiB request limit, and generic
JSON errors. These limits keep the example predictable; they are not a complete
production server hardening policy.

`tests/test_reference_app.py` calls the policy function directly for unknown
users, screening, matter authorization, and privileged-document cases. It also
checks Bob's and Alice's content over HTTP, sends exact HTTP bytes to temporary
loopback servers to test request framing, content types, size limits, and
redaction, and checks safe startup errors. The separate
`tests/test_reference_app_integration.py` starts the installed module in a
subprocess, checks Bob's actual timeline response, and runs the installed
MatterFence command against its printed endpoint. The subprocess always gets a
bounded startup wait and is terminated after the test.

Run both local checks with:

```sh
python -m pytest -q
python -m ruff check .
```

Passing this example demonstrates a working synthetic integration. It does not
validate authorization in any real legal-AI application.
