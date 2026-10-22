"""
Context Analyser
================
Determines exactly where a reflected marker lands in an HTTP response.

Does NOT use the LLM — this is deterministic parsing.
The LLM receives the output of this node as structured evidence,
not raw HTML for it to guess from.

Input:  HTTP response body + marker string
Output: ContextAnalysis dataclass

Possible context values
-----------------------
  html_text            <p>MARKER</p>
  html_attribute       <input value="MARKER">
  html_attribute_unquoted <input value=MARKER>
  html_comment         <!-- MARKER -->
  script_string_double var x = "MARKER";
  script_string_single var x = 'MARKER';
  script_string_template var x = `MARKER`;
  script_expression    var x = MARKER;
  script_block         <script>...MARKER...</script> (no string)
  url_param            href="?q=MARKER"
  json_string          {"key":"MARKER"}
  css_value            color: MARKER;
  unknown
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class ContextAnalysis:
    """Full analysis of a single reflection point."""
    marker: str
    reflected: bool = False

    # Primary context classification
    context: str = "unknown"

    # HTML attribute details (when context is html_attribute*)
    tag_name: str = ""
    attribute_name: str = ""
    quote_type: str = ""          # double | single | unquoted

    # Script details
    script_quote: str = ""        # double | single | template | none

    # Encoding — which characters are HTML-entity encoded before reflection
    encoded_chars: list[str] = field(default_factory=list)
    raw_present: bool = False     # True = unencoded marker appears in body

    # Surrounding context snippets (for LLM evidence)
    before: str = ""              # 80 chars before marker
    after: str  = ""              # 80 chars after marker
    full_snippet: str = ""        # 200 chars centred on marker

    # Breakout characters — what would escape this context
    breakout_chars: list[str] = field(default_factory=list)

    # Confidence: high (deterministic), medium, low
    confidence: str = "high"

    def to_evidence_dict(self) -> dict:
        return {
            "marker":          self.marker,
            "context":         self.context,
            "reflected":       self.reflected,
            "raw_present":     self.raw_present,
            "encoded_chars":   self.encoded_chars,
            "tag":             self.tag_name,
            "attribute":       self.attribute_name,
            "quote_type":      self.quote_type,
            "script_quote":    self.script_quote,
            "breakout_chars":  self.breakout_chars,
            "before":          self.before,
            "after":           self.after,
            "snippet":         self.full_snippet,
        }


class ContextAnalyser:
    """
    Classify the reflection context of a marker in an HTTP response.

    Usage::

        ca = ContextAnalyser()
        analysis = ca.analyse(response_body, marker)
    """

    def analyse(self, body: str, marker: str) -> ContextAnalysis:
        result = ContextAnalysis(marker=marker)

        # Check raw presence
        result.raw_present = marker in body
        result.reflected   = result.raw_present or self._encoded_present(body, marker)

        if not result.reflected:
            return result

        # Detect JSON response BEFORE position-based analysis.
        # The 80-char before-window is too short for JSON bodies — the opening
        # { may be hundreds of chars before the marker.  Check the whole body.
        if self._body_is_json(body):
            # Find the marker position and classify its immediate context
            idx = body.find(marker)
            if idx >= 0:
                r = ContextAnalysis(marker=marker, reflected=True, raw_present=True)
                start = max(0, idx - 80)
                r.before       = body[start:idx]
                r.after        = body[idx + len(marker):idx + len(marker) + 80]
                r.full_snippet = body[max(0, idx - 100): idx + len(marker) + 100]
                r.encoded_chars = self._check_encoding(body, marker)
                # Classify whether marker is in a JSON string value or key
                if re.search(r'[{,]\s*"[\w\-]+"\s*:\s*"?$', r.before, re.DOTALL):
                    r.context = "json_value"
                elif re.search(r'[{,]\s*"$', r.before, re.DOTALL):
                    r.context = "json_key"
                else:
                    r.context = "json_value"  # safe default for JSON bodies
                # JSON string values are always double-quoted — set these so the
                # synthesiser treats them as a JS-string breakout target.
                r.quote_type   = "double"
                r.script_quote = "double"
                r.confidence    = "high"
                r.breakout_chars = ['"']
                return r

        # Find ALL positions — pick the most exploitable one
        all_analyses = self._analyse_all_positions(body, marker)

        if not all_analyses:
            return result

        # Rank by exploitability: attribute > script_string > html_text > unknown
        rank = {
            "html_attribute":           5,
            "html_attribute_unquoted":  5,
            "script_string_double":     4,
            "script_string_single":     4,
            "script_string_template":   4,
            "script_expression":        4,
            "url_param":                3,
            "html_text":                2,
            "html_comment":             1,
            "css_value":                1,
            "unknown":                  0,
        }
        best = max(all_analyses, key=lambda a: rank.get(a.context, 0))
        return best

    def analyse_all(self, body: str, marker: str) -> list[ContextAnalysis]:
        """Return analysis for every position where the marker appears."""
        self._encoded_present(body, marker)  # ensure reflected is checked
        return self._analyse_all_positions(body, marker)

    def _analyse_all_positions(self, body: str, marker: str) -> list[ContextAnalysis]:
        """Analyse every occurrence of marker in body."""
        import re as _re
        positions = [m.start() for m in _re.finditer(_re.escape(marker), body)]
        results = []
        for idx in positions:
            r = ContextAnalysis(marker=marker, reflected=True, raw_present=True)
            start = max(0, idx - 80)
            end   = min(len(body), idx + len(marker) + 80)
            r.before       = body[start:idx]
            r.after        = body[idx + len(marker):end]
            r.full_snippet = body[max(0, idx-100): idx + len(marker) + 100]
            r.encoded_chars = self._check_encoding(body, marker)
            self._classify(r, body, idx)
            r.breakout_chars = self._breakout_chars(r)
            results.append(r)
        return results

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------

    def _classify(self, r: ContextAnalysis, body: str, idx: int) -> None:
        before = r.before
        after  = r.after

        # ── Inside a <script> block ───────────────────────────────────
        script_match = self._enclosing_script(body, idx)
        if script_match:
            self._classify_script(r, before)
            return

        # ── Inside an HTML comment ────────────────────────────────────
        if re.search(r"<!--[^>]*$", before, re.DOTALL):
            r.context = "html_comment"
            return

        # ── Inside a CSS block ────────────────────────────────────────
        if re.search(r"<style[^>]*>[^<]*$", before, re.DOTALL | re.I):
            r.context = "css_value"
            return

        # ── Inside an HTML attribute ──────────────────────────────────
        attr_match = re.search(
            r'<(\w+)[^>]*\s+([\w\-:]+)=["\']?[^"\'<>]*$',
            before, re.I | re.DOTALL,
        )
        if attr_match:
            r.context   = "html_attribute"
            r.tag_name  = attr_match.group(1).lower()
            r.attribute_name = attr_match.group(2).lower()

            # Quote type
            before_stripped = before.rstrip()
            if before_stripped.endswith('"'):
                r.quote_type = "double"
                r.context    = "html_attribute"
            elif before_stripped.endswith("'"):
                r.quote_type = "single"
                r.context    = "html_attribute"
            else:
                # Could be unquoted attr or end of tag name
                dq = before.rfind('"')
                sq = before.rfind("'")
                eq = before.rfind("=")
                if eq > max(dq, sq):
                    r.quote_type = "unquoted"
                    r.context    = "html_attribute_unquoted"
                else:
                    r.quote_type = "double" if dq > sq else "single"

            # Special attribute sinks
            if r.attribute_name in ("href", "src", "action", "formaction", "data"):
                r.context = "url_param"
            elif r.attribute_name.startswith("on"):
                r.context = "script_string_double"  # event handler is JS
            return

        # ── JSON context ──────────────────────────────────────────────
        before_trimmed = before.rstrip()
        if (before_trimmed.endswith('"') or before_trimmed.endswith("'")) and \
           re.search(r'[{,]\s*"[\w\-]+"\s*:\s*["\']?$', before, re.DOTALL):
            r.context = "json_string"
            return

        # ── HTML text node ────────────────────────────────────────────
        # Marker is in text if there's a closing > before it and no < opening a new tag
        if re.search(r">\s*[^<]*$", before) or re.search(r"^\s*[^>]*<", after):
            r.context = "html_text"
            return

        # Final fallback: if marker appears after a tag closure or text punctuation
        if before.rstrip().endswith(("'", '"', ")", ">", ";", ",")):
            r.context = "html_text"
            return

        r.context = "unknown"

    def _classify_script(self, r: ContextAnalysis, before: str) -> None:
        """Determine if marker is inside a JS string or bare expression."""
        # Count unescaped quotes in `before` to find string context
        dq_open = self._unescaped_quote_count(before, '"')
        sq_open = self._unescaped_quote_count(before, "'")
        tq_open = self._unescaped_quote_count(before, "`")

        if dq_open % 2 == 1:
            r.context      = "script_string_double"
            r.script_quote = "double"
        elif sq_open % 2 == 1:
            r.context      = "script_string_single"
            r.script_quote = "single"
        elif tq_open % 2 == 1:
            r.context      = "script_string_template"
            r.script_quote = "template"
        else:
            r.context = "script_expression"

    # ------------------------------------------------------------------
    # Breakout characters
    # ------------------------------------------------------------------

    def _breakout_chars(self, r: ContextAnalysis) -> list[str]:
        ctx = r.context
        if ctx == "html_text":
            return ["<"]
        if ctx == "html_attribute":
            return ['"'] if r.quote_type == "double" else ["'"]
        if ctx == "html_attribute_unquoted":
            return [" ", ">"]
        if ctx == "script_string_double":
            return ['"']
        if ctx == "script_string_single":
            return ["'"]
        if ctx == "script_string_template":
            return ["`"]
        if ctx == "script_expression":
            return [";"]
        if ctx == "html_comment":
            return ["-->"]
        if ctx == "url_param":
            return ["javascript:"] if r.attribute_name in ("href", "src") else ['"', "'"]
        # JSON string values are always double-quoted; breakout requires "
        if ctx in ("json_value", "json_string", "json_key"):
            return ['"']
        return []

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _body_is_json(body: str) -> bool:
        """
        Return True if the response body is JSON rather than HTML.
        Checks the first non-whitespace character and a quick structural test.
        This is more reliable than checking Content-Type from within the
        analyser (which doesn't receive the HTTP response object).
        """
        stripped = body.lstrip()
        if not stripped:
            return False
        # JSON objects/arrays always start with { or [
        if stripped[0] not in ('{', '['):
            return False
        # Sanity check: no HTML tags in the first 200 chars
        return not re.search(r"<(?:html|head|body|div|p|span|script)\b", stripped[:200], re.I)

    @staticmethod
    def _enclosing_script(body: str, idx: int) -> bool:
        """Return True if idx is inside a <script>...</script> block."""
        open_tags  = [m.start() for m in re.finditer(r"<script[^>]*>", body, re.I)]
        close_tags = [m.start() for m in re.finditer(r"</script>", body, re.I)]

        in_script = False
        oi = ci = 0
        while oi < len(open_tags):
            open_pos = open_tags[oi]
            if open_pos > idx:
                break
            in_script = True
            # find matching close
            while ci < len(close_tags) and close_tags[ci] < open_pos:
                ci += 1
            if ci < len(close_tags) and close_tags[ci] < idx:
                in_script = False
            oi += 1
        return in_script

    @staticmethod
    def _unescaped_quote_count(text: str, quote: str) -> int:
        count = 0
        i = 0
        while i < len(text):
            if text[i] == "\\" :
                i += 2
                continue
            if text[i] == quote:
                count += 1
            i += 1
        return count

    @staticmethod
    def _check_encoding(body: str, marker: str) -> list[str]:
        """Return list of characters that were HTML-entity encoded."""
        import html
        encoded: list[str] = []
        for char in ("<", ">", '"', "'", "&"):
            if char in marker and html.escape(char) in body and char not in body:
                encoded.append(char)
        return encoded

    @staticmethod
    def _encoded_present(body: str, marker: str) -> bool:
        import html
        return html.escape(marker) in body
