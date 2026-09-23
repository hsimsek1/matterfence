# Issue #13: offline HTML evidence report

## Try it

From the repository folder in PowerShell, activation is optional when using the
virtual environment's executable directly:

```powershell
.\.venv\Scripts\matterfence.exe run --report matterfence-report.html
Start-Process .\matterfence-report.html
```

The first command evaluates the bundled scenario once per target and saves one
standalone file. The second opens that file with your associated application;
you can also double-click it. No reference-app server is required for the mock
comparison. The deliberate vulnerable FAIL gives exit code 1, not an installation
or report error.

For one target, a custom scenario, or machine-readable output:

```sh
matterfence run --target secure --report secure-report.html
matterfence run my-scenario.json --target secure --report custom-report.html
matterfence run --report comparison.html --json
```

The same option also works with `--target http --endpoint ...`. It does not start
or configure the target. Target names are labels, not verified provenance.

Use a new filename in an existing writable folder. Existing reports, directories,
and even the scenario input file cannot be overwritten. File errors produce a
generic stderr message and exit 2, without including paths or raw error details.
Already-computed text/JSON findings remain on stdout. A failed disk write can
leave an incomplete new file; do not use that artifact as a completed report.
Successful writes preserve the normal verdict exit code. `--json` remains a JSON
array; the save notice is on stderr.

## What enters each function, and what leaves

- `render_report(findings)` accepts a nonempty list of existing `Finding` models
  and returns one HTML string. It never calls a target, changes a verdict, writes
  a file, or reads raw document/response text. An empty list raises `ValueError`.
- `_render_finding(finding)` accepts one result and returns its card's HTML. A
  fixed enum lookup selects the status color and explanation. Other fields are
  escaped before becoming visible text, not HTML instructions.
- `_render_resource(resource)` accepts one forbidden resource's identifying
  evidence and returns its HTML block. It preserves true/false/unknown retrieval
  and the separate matter-canary disclosure flag.
- `_render_ids(identifiers)` accepts a list or `None` and returns HTML: escaped
  list items, `None observed` for `[]`, or `Unknown (incomplete run)` for `None`.
- `write_report(findings, path)` accepts those findings and a `Path`, renders
  first, then writes UTF-8 using mode `x` (exclusive creation). It returns `None`
  on success; read/write errors propagate to the CLI's safe error handler.
- The `run` command passes the same computed list to its text/JSON output and
  the optional file writer. It does not repeat the evaluation to create a report.

`report.html` is a packaged, static HTML/CSS template. `string.Template` replaces
only the five deliberate placeholders (counts and cards); it does not recursively
interpret dollar signs inside substituted text. `html.escape` turns characters
such as `<` into harmless text. The report has no JavaScript, remote fonts,
external images, or other network dependencies. A restrictive content-security
policy provides an additional browser safeguard; escaping remains essential.

## How the tests establish the behavior

`tests/test_html_report.py` checks evidence against real computed findings,
unknown versus empty observations, deterministic rendering, all three verdicts,
and escaping across every free-text field. Parsing the result as HTML checks for
active tags/attributes, rather than merely searching for one attack string.
Tests also cover raw-content exclusion, duplicate target calls, JSON/exit-code
compatibility, invalid options, existing-file protection, and safe I/O failures.

`tests/test_installed_cli.py` generates reports outside the checkout using the
installed executable. CI repeats those cases from a fresh wheel installation,
catching a missing packaged template as well as a broken command option.

Manual browser checks cover the default two-card comparison and narrow-screen
wrapping. Print CSS removes background dependence and keeps resource blocks
together; final pagination depends on browser, paper size, and print settings.

## Interpretation limits

PASS means no forbidden retrieval or exact forbidden canary was observed in this
run, not that a system is secure or legally compliant. ERROR is incomplete, never
a pass; a proven violation remains FAIL even if other observations are incomplete.
The report displays these facts rather than inventing a score or certification.

Canaries may miss paraphrased leaks; a shared matter canary cannot identify one
source document. Retrieval depends on truthful instrumentation, and permitted
IDs alone do not prove useful answers. Mocks are deterministic, not LLM-backed.
The report omits raw bodies, target answers, and errors, but still contains fixture
metadata, IDs, and canaries. Use invented data and review the file before sharing.
