"""
Tests for the terminal report node's output safety.

Regression: the report prints glyphs such as ▶ and → . Writing those to a
stream that cannot encode them (cp1252 when stdout is piped or redirected on
Windows) raised UnicodeEncodeError *inside* the node, so the node failed — and
with it the whole scan — over a cosmetic character. The failure also meant
finding_count never reached the shared state, so the scan summary reported
"Candidates 0 / Confirmed findings 0" while the report itself showed a
browser-confirmed finding.
"""
from __future__ import annotations

import io
import sys
from unittest.mock import MagicMock

from xscan.nodes.reporting.report import ReportNode, _EncodingSafeStream


def _cp1252_stream() -> io.TextIOWrapper:
    """A text stream that cannot encode the report's box/arrow glyphs."""
    return io.TextIOWrapper(io.BytesIO(), encoding="cp1252", newline="")


class TestEncodingSafeStream:
    def test_unencodable_glyph_degrades_instead_of_raising(self):
        raw = _cp1252_stream()

        _EncodingSafeStream(raw).write("  \u25b6  jQuery .attr()  \u2192  href")
        raw.flush()

        assert raw.buffer.getvalue(), "output must still be written"

    def test_ascii_is_written_untouched(self):
        raw = _cp1252_stream()

        _EncodingSafeStream(raw).write("plain ascii")
        raw.flush()

        assert raw.buffer.getvalue() == b"plain ascii"

    def test_stream_attributes_are_delegated(self):
        raw = _cp1252_stream()

        assert _EncodingSafeStream(raw).encoding == "cp1252"
        assert _EncodingSafeStream(raw).isatty() is False


class TestReportNodeOnLegacyConsole:
    """The node must complete, and report its count, on a cp1252 console."""

    @staticmethod
    def _ctx(**inputs) -> MagicMock:
        ctx = MagicMock()
        ctx.scan_id = "TEST"
        ctx.config = {}
        ctx.inputs = {"profile": "balanced", **inputs}
        ctx.get = lambda key, default=None: ctx.inputs.get(key, default)
        return ctx

    def test_dom_and_validated_candidates_render_without_crashing(self, monkeypatch):
        monkeypatch.setattr(sys, "stdout", _cp1252_stream())

        confirmed = {
            "url":       "http://127.0.0.1:8000/feedback",
            "parameter": "returnPath",
            "validated": True,
            "confirmed": True,
            "best_payload":  "javascript:alert(document.cookie)",
            "best_test_url": "http://127.0.0.1:8000/feedback?returnPath=javascript%3Aalert%28document.cookie%29",
            "browser_evidence": {
                "dialog_fired": True,
                "dialogs": [{"type": "alert", "args": ["document.cookie"]}],
                "dom_state": [{"tag": "a", "attribute": "href", "value": "javascript:alert(1)"}],
                "note": "",
            },
        }
        unconfirmed = {
            "url":       "http://127.0.0.1:8000/feedback",
            "parameter": "returnPath",
            "validated": False,
            "confirmed": False,
            "best_payload": "<img src=x onerror=alert(1)>",
            "browser_evidence": {
                "dialog_fired": False,
                "dialogs": [],
                "dom_state": [{"tag": "a", "attribute": "href", "value": "<img src=x>"}],
                "note": "sink holds the payload but no execution observed",
            },
        }
        dom = {
            "source":    "location.search",
            "sink":      "jQuery .attr() [href]",
            "sink_kind": "url_attribute",
            "severity":  "high",
            "snippet":   "$('#backLink').attr('href', returnPath);",
            "payloads":  ["javascript:alert(document.cookie)"],
            "test_urls": ["http://127.0.0.1:8000/feedback?returnPath=javascript:alert(1)"],
        }

        out = ReportNode().execute(self._ctx(
            target_url="http://127.0.0.1:8000/feedback",
            crawl_count=3,
            dom_candidates=[dom],
            validated_candidates=[confirmed, unconfirmed],
            confirmed_count=1,
        ))

        assert out["finding_count"] == 1, "browser-confirmed findings must reach the summary"
        printed = sys.stdout.buffer.getvalue().decode("cp1252")
        assert "DOM XSS candidates" in printed
        assert "CONFIRMED" in printed
        assert "but never executed" in printed
