"""Present existing findings as an offline report; never evaluate a target."""

from html import escape
from importlib.resources import files
from pathlib import Path
from string import Template

from matterfence.core.runner import Finding, ResourceEvidence, TestStatus


def _render_ids(identifiers: list[str] | None) -> str:
    """Keep unobserved retrieval distinct from an observed empty list."""
    if identifiers is None:
        return '<p class="muted">Unknown (incomplete run)</p>'
    if not identifiers:
        return '<p class="muted">None observed</p>'
    items = "".join(f"<li><code>{escape(item)}</code></li>" for item in identifiers)
    return f'<ul class="ids">{items}</ul>'


def _render_resource(resource: ResourceEvidence) -> str:
    """Turn one forbidden resource's identifying evidence into escaped HTML."""
    retrieved = "Unknown"
    if resource.retrieved is not None:
        retrieved = "Yes" if resource.retrieved else "No"
    disclosed = "Yes" if resource.disclosed else "No"
    return f"""
    <div class="resource">
      <h4>{escape(resource.document_title)}</h4>
      <p class="resource-id"><code>{escape(resource.document_id)}</code></p>
      <dl class="evidence">
        <div><dt>Forbidden matter</dt><dd>{escape(resource.matter_id)}</dd></div>
        <div><dt>Document retrieved</dt><dd>{retrieved}</dd></div>
        <div><dt>Matter canary disclosed</dt><dd>{disclosed}</dd></div>
      </dl>
      <p class="label">Exact-match canary</p>
      <code class="canary">{escape(resource.canary_token)}</code>
    </div>"""


def _render_finding(finding: Finding) -> str:
    """Format one verdict without recomputing or strengthening its meaning."""
    # Only these fixed values enter a CSS class, never fixture-supplied text.
    styles = {
        TestStatus.FAIL: ("fail", "A prohibited retrieval or disclosure was observed."),
        TestStatus.PASS: ("pass", "No violation observed in this run."),
        TestStatus.ERROR: ("error", "Incomplete evidence. This is not a pass."),
    }
    style, meaning = styles[finding.status]
    resources = "".join(_render_resource(item) for item in finding.prohibited_resources)
    if not resources:
        resources = '<p class="muted">None recorded</p>'
    return f"""
    <article class="finding {style}">
      <header class="finding-header">
        <span class="badge">{finding.status.value}</span>
        <p class="scenario">{escape(finding.scenario_id)}
          <span> / v{escape(finding.scenario_version)}</span></p>
        <h2>{escape(finding.target_name)}</h2>
        <p class="meaning">{meaning}</p>
      </header>
      <div class="finding-body">
        <section>
          <h3><span>01</span> Request &amp; boundary</h3>
          <dl class="context">
            <div><dt>Acting user</dt><dd>{escape(finding.actor.name)}
              <code>{escape(finding.actor.id)}</code></dd></div>
            <div><dt>Role label</dt><dd>{escape(finding.actor.role)}</dd></div>
          </dl>
          <p class="label">Authorized matters</p>
          {_render_ids(finding.authorized_matter_ids)}
          <p class="label">Expected behavior</p>
          <p>{escape(finding.expected_behavior)}</p>
        </section>
        <section>
          <h3><span>02</span> Retrieval evidence</h3>
          <div class="retrieval-grid">
            <div><p class="label">Permitted retrieval</p>
              {_render_ids(finding.permitted_retrieved_document_ids)}</div>
            <div><p class="label">All reported retrieval</p>
              {_render_ids(finding.retrieved_document_ids)}</div>
          </div>
        </section>
        <section>
          <h3><span>03</span> Forbidden resources</h3>
          {resources}
          <p class="note">A matter canary can be shared by several documents;
            its disclosure does not identify a unique source document.</p>
        </section>
        <section>
          <h3><span>04</span> Interpretation &amp; next step</h3>
          <p class="label">Observed</p><p>{escape(finding.observed)}</p>
          <p class="label">Remediation</p><p>{escape(finding.remediation)}</p>
          <dl class="context metadata">
            <div><dt>Impact if violated</dt><dd>{escape(finding.severity)}</dd></div>
            <div><dt>Detector</dt><dd><code>{escape(finding.detector)}</code></dd></div>
          </dl>
        </section>
      </div>
    </article>"""


def render_report(findings: list[Finding]) -> str:
    """Return a standalone HTML document from one or more computed findings.

    This does not call targets, change findings, or include raw target responses.
    All fixture-supplied text is escaped before insertion into the template.
    """
    if not findings:
        raise ValueError("A report requires at least one finding.")
    template = Template(files("matterfence").joinpath("report.html").read_text("utf-8"))
    return template.substitute(
        finding_count=len(findings),
        fail_count=sum(item.status == TestStatus.FAIL for item in findings),
        pass_count=sum(item.status == TestStatus.PASS for item in findings),
        error_count=sum(item.status == TestStatus.ERROR for item in findings),
        findings="".join(_render_finding(item) for item in findings),
    )


def write_report(findings: list[Finding], path: Path) -> None:
    """Write UTF-8 HTML to a new file; raise on failure or an existing path."""
    document = render_report(findings)
    # Exclusive creation protects existing reports and scenario input files.
    with path.open("x", encoding="utf-8") as output:
        output.write(document)
