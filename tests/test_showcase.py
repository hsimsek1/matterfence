import re
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from matterfence.core.runner import run_auth_scenario
from matterfence.core.scenario import load_auth_scenario
from matterfence.report import render_report
from matterfence.targets.mock import SecureMockTarget, VulnerableMockTarget

DOCS = Path(__file__).resolve().parents[1] / "docs"


class ShowcaseParser(HTMLParser):
    """Collect static markup, readable text, and text belonging to result cards."""

    def __init__(self, html):
        super().__init__()
        self.elements = []
        self.text = []
        self.cards = {}
        self.current_card = None
        self.hidden_depth = 0
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        self.elements.append((tag, attributes))
        if tag in {"head", "style", "script"}:
            self.hidden_depth += 1
        if tag == "article":
            self.current_card = attributes["data-target"]
            assert self.current_card not in self.cards
            self.cards[self.current_card] = []

    def handle_endtag(self, tag):
        if tag in {"head", "style", "script"}:
            self.hidden_depth -= 1
        if tag == "article":
            self.current_card = None

    def handle_data(self, data):
        if self.hidden_depth == 0:
            self.text.append(data)
            if self.current_card is not None:
                self.cards[self.current_card].append(data)


@pytest.fixture
def showcase():
    return ShowcaseParser((DOCS / "index.html").read_text(encoding="utf-8"))


def test_checked_in_example_report_matches_the_deterministic_run():
    """Keep the public report artifact tied to the current benchmark output."""
    report_path = Path(__file__).resolve().parents[1] / "docs" / "example-report.html"
    scenario = load_auth_scenario()
    findings = [
        run_auth_scenario(VulnerableMockTarget(), scenario),
        run_auth_scenario(SecureMockTarget(), scenario),
    ]

    assert [finding.status.value for finding in findings] == ["FAIL", "PASS"]
    assert report_path.read_text(encoding="utf-8") == render_report(findings)


def test_showcase_cards_match_actual_mock_evidence(showcase):
    scenario = load_auth_scenario()
    targets = [VulnerableMockTarget(), SecureMockTarget()]
    assert set(showcase.cards) == {target.__class__.__name__ for target in targets}
    for target in targets:
        finding = run_auth_scenario(target, scenario)
        card = " ".join(showcase.cards[finding.target_name])
        assert card.split()[0] == finding.status.value
        assert set(re.findall(r"\b(?:PASS|FAIL|ERROR)\b", card)) == {finding.status.value}
        assert re.findall(r"DOC_[A-Z0-9_]+", card) == finding.retrieved_document_ids
        forbidden = finding.prohibited_resources[0]
        assert forbidden.retrieved is (finding.status.value == "FAIL")
        assert forbidden.disclosed is (finding.status.value == "FAIL")


def test_showcase_limits_and_setup_are_visible(showcase):
    text = " ".join(" ".join(showcase.text).split())
    scenario = load_auth_scenario()
    assert scenario.scenario_id in text
    assert scenario.actor_id in text
    for matter in scenario.matters:
        for document in matter.documents:
            assert f"{matter.id} / {document.title}" in text
            assert document.content not in text
    for explanation in (
        "deterministic mocks and invented records",
        "not a real-model evaluation",
        "Incomplete evidence without a proven violation produces ERROR, not PASS",
        "can miss paraphrased leaks",
        "Real-model experiments and independent validation remain future work",
        "Exit code 1 is expected",
    ):
        assert explanation in text


def test_showcase_links_resolve_without_installation(showcase):
    identifiers = [attrs["id"] for _, attrs in showcase.elements if "id" in attrs]
    assert len(identifiers) == len(set(identifiers))
    links = [attrs["href"] for tag, attrs in showcase.elements if tag == "a"]
    assert "example-report.html" in links
    for link in links:
        parsed = urlsplit(link)
        if parsed.scheme:
            assert parsed.scheme == "https"
            assert parsed.netloc == "github.com"
            assert parsed.path.startswith("/hsimsek1/matterfence")
        elif parsed.path:
            destination = (DOCS / parsed.path).resolve()
            assert destination.is_relative_to(DOCS.resolve())
            assert destination.is_file()
        else:
            assert parsed.fragment in identifiers


def test_showcase_is_passive_and_uses_only_local_images(showcase):
    assert not {"script", "iframe", "form", "input", "object", "embed", "base", "link"} & {
        tag for tag, _ in showcase.elements
    }
    for tag, attrs in showcase.elements:
        assert not any(name.startswith("on") for name in attrs)
        assert not {"srcdoc", "srcset", "action", "formaction", "ping"} & attrs.keys()
        if "src" in attrs:
            assert tag == "img"
            assert attrs["src"] == "example-report.png"
            assert (DOCS / attrs["src"]).is_file()
            assert attrs.get("alt")
    policies = [
        attrs["content"] for tag, attrs in showcase.elements
        if tag == "meta" and attrs.get("http-equiv") == "Content-Security-Policy"
    ]
    assert policies == [
        (
            "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; "
            "base-uri 'none'; form-action 'none'"
        )
    ]
    html = (DOCS / "index.html").read_text(encoding="utf-8")
    assert "@import" not in html
    assert "url(" not in html


def test_showcase_has_accessible_structure_and_keyboard_navigation(showcase):
    tags = [tag for tag, _ in showcase.elements]
    assert tags.count("h1") == 1
    assert tags.count("main") == 1
    assert ("html", {"lang": "en"}) in showcase.elements
    assert any(
        tag == "a" and attrs.get("class") == "skip" and attrs.get("href") == "#main"
        for tag, attrs in showcase.elements
    )
    for tag, attrs in showcase.elements:
        if tag == "section":
            assert attrs.get("aria-labelledby")
        assert "tabindex" not in attrs  # Keep native link/summary keyboard order.
    html = (DOCS / "index.html").read_text(encoding="utf-8")
    assert ":focus-visible" in html
    assert "@media (max-width: 760px)" in html
