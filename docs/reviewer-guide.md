# Presenting and independently reviewing MatterFence

This is a presentation script and review plan, not a record of outside validation.
No model-backed experiment, endorsement, customer, or reviewer is claimed here.
The current demonstrations use synthetic records and deterministic targets.

## Two-minute walkthrough

Open `docs/index.html` in a browser, then open its sample-report link.
The script below accompanies those pages; a video has not yet been recorded.

**0:00–0:25 — The question.**
“Suppose Bob can access one client's matter, but not another's. A reassuring AI
answer doesn't tell us whether the application retrieved a forbidden document.
MatterFence tests that boundary using invented records and observable retrieval.”

**0:25–0:55 — The failure.**
Point to the vulnerable result. Bob is allowed M101's timeline, not M105's
strategy. Both document IDs appear in the retrieval evidence. The strategy's
canary also appears in the response. Either violation is enough for FAIL.

**0:55–1:20 — The control.**
Point to the secure result. Permission filtering removes the forbidden record
before answer construction while retaining the permitted timeline. This is a
controlled mock comparison, not a model reasoning its way to the correct policy.

**1:20–1:45 — The engineering decision.**
Explain why incomplete observations without a proven violation produce ERROR,
not PASS. Show that the report exposes the actor, policy boundary, and document
IDs rather than only a score. The checked-in sample is compared against freshly
computed findings by pytest.

**1:45–2:00 — The limits and next experiment.**
“A PASS applies to this run. Canaries can miss paraphrases, and retrieval logs
must be trustworthy. The next research step is a bounded local-model experiment,
followed by independent reproduction—not a claim that this certifies legal AI.”

## Reproduce before presenting

Install and activate the environment as described in the README. From the checkout:

```sh
python -m matterfence.cli run --report presentation-report.html
```

Expect FAIL followed by PASS, a saved HTML file, and exit code 1. Use a new filename
for another run. Open the report; do not interpret the intentional FAIL as a setup
problem. For the separate HTTP/SQLite examples, follow [the demo guide](case-study-demo.md).

In an interview, be ready to explain the fixture, the target's observations, the
evaluator, the renderer, and one negative test without assistance. Describe your
own decisions and AI assistance accurately. Do not substitute test counts for
evidence of real-world effectiveness or describe a scripted injection as a live
model exploit.

## Independent-review session (not yet conducted)

Start with one developer, then one security or legal-technology reviewer. Use only
authorized, isolated test applications and synthetic records. Ask for feedback,
not an endorsement. Do not ask for client documents or access to production systems.

1. Can you explain the problem after viewing the showcase for one minute?
2. Can you reproduce the mock comparison from the README without help?
3. Can you distinguish FAIL, PASS, and incomplete evidence?
4. Does the report show enough evidence to investigate the failure?
5. Which limitation would prevent you from using this in your workflow?

Record the tested commit, OS/Python version, setup time, commands tried, failures,
and the reviewer's actual feedback. Ask permission before publishing their name,
quotes, or identifying details. File one issue per actionable problem. Report a
successful independent reproduction only after it actually happens.

### Invitation draft — not sent

“I'm developing MatterFence, a small security-testing project for legal-AI
authorization boundaries. It currently uses synthetic data and deterministic
demos, not a real-model audit. Would you be willing to spend 15–20 minutes trying
the demo and telling me what is unclear or missing? No client data, credentials,
or production access is needed. I'm seeking critical feedback, not an endorsement.”

## Zero-budget next milestones

1. **Reviewed presentation:** finish this showcase, verify its links and mobile
   layout, then publish on a confirmed free hosting option. Do not buy a domain.
   Licensing remains undecided; no release is advertised as licensed open source.
2. **Local-model feasibility:** check available RAM, GPU, disk space, and runtime
   compatibility. Choose a suitably licensed model only after checking its current
   requirements. Obtain approval before a large download or runtime installation.
   If the hardware is unsuitable, document the limitation; do not substitute paid
   calls or imply that the mock results are real-model findings.
3. **One bounded experiment:** first predefine one synthetic fixture, one payload,
   a benign control, model/runtime versions, settings, and a trial count. Compare
   permission-filtered and deliberately vulnerable retrieval using the same actor.
   Preserve complete document IDs across all tool calls, including permitted ones.
4. **Publish the observations:** report violations, clean runs, and errors with
   their denominators. Keep retrieval violations separate from exact-canary
   disclosure and permitted retrieval. Include failed attacks, configuration,
   evidence hashes, and limitations; do not cherry-pick a successful exploit.
   A model's refusal is a valid observation. Keep model runs optional and offline
   unit tests deterministic; no network-dependent assertions in ordinary CI.
5. **Independent reproduction:** invite named reviewers only with the owner's
   approval. Address their feedback and write a short case study describing what
   changed. Tag a release only after license and release scope are settled.

## How this showcase is checked

The showcase is static HTML/CSS, not a new Python application. It does not execute
the benchmark in the visitor's browser or accept uploads.

`ShowcaseParser(html)` in `tests/test_showcase.py` takes the HTML string and collects
tags, attributes, visible text, and each target's result card. Tests use those
values to compare card statuses and document IDs with actual runner findings,
reject active content and unexpected external destinations, and check local links
and fragment targets. The existing report-equality test still checks the complete
sample HTML against `render_report(findings)`.

These structural tests do not prove visual accessibility. Browser checks cover
desktop/mobile layout, keyboard focus, disclosure controls, and navigation to the
real report. No presentation test claims a real-model result or outside approval.
