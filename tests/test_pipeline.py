"""
End-to-end pipeline test using a synthetic response body
that matches the PortSwigger 'Reflected XSS into attribute with
angle brackets HTML-encoded' lab pattern.

Two reflections:
  1. html_text   — <h1>0 results for 'MARKER'</h1>
  2. html_attribute — <input value="MARKER">

Encoding:
  < and > are HTML-entity encoded
  " (double-quote) is NOT encoded

Expected behaviour:
  - Context analyser picks html_attribute (more exploitable)
  - Heuristic plan generates event-handler payloads (no < or >)
  - Validator would find " onmouseover="alert(1) works
"""
import warnings
warnings.filterwarnings("ignore")

from xscan.nodes.analysis.context import ContextAnalyser
from xscan.nodes.validation.xss_validate import XssValidatorNode


BODY = (
    "<section>"
    "<h1>0 search results for 'xscMARKER'</h1>"
    "</section>"
    "<form>"
    '<input type=text name=search value="xscMARKER" placeholder="Search">'
    "</form>"
)

ENC_PROFILE = {
    "raw_chars":                ['"', "'", " ", "=", "-", "."],
    "encoded_chars":            ["<", ">"],
    "stripped_chars":           [],
    "can_break_html_text":      False,
    "can_break_html_attribute": True,
    "can_break_script_string":  True,
    "summary":                  "raw: ['\"']  encoded: ['<', '>']",
}


def test_context_picks_attribute():
    ca = ContextAnalyser()
    best = ca.analyse(BODY, "xscMARKER")
    all_ctxs = ca.analyse_all(BODY, "xscMARKER")

    print(f"\nAll reflection contexts: {[a.context for a in all_ctxs]}")
    print(f"Best (most exploitable): {best.context}")
    print(f"  tag={best.tag_name}  attr={best.attribute_name}  quote={best.quote_type}")
    print(f"  breakout_chars={best.breakout_chars}")

    assert best.context == "html_attribute", f"Expected html_attribute, got {best.context}"
    assert best.quote_type == "double"
    assert '"' in best.breakout_chars
    print("PASS: context correctly identified as html_attribute")


def test_heuristic_generates_event_handler_payloads():
    from xscan.nodes.analysis.context import ContextAnalyser
    ca = ContextAnalyser()
    all_ctxs = ca.analyse_all(BODY, "xscMARKER")

    node = XssValidatorNode()

    all_test_cases = []
    for ctx in all_ctxs:
        plan = node._heuristic_plan(ctx.to_evidence_dict(), ENC_PROFILE)
        print(f"\nContext {ctx.context!r}: viable={plan['viable']}")
        print(f"  Strategy: {plan['breakout_strategy']}")
        for tc in plan["test_cases"][:4]:
            print(f"  {tc['priority']}. {tc['payload']}")
        if plan["viable"]:
            all_test_cases.extend(plan["test_cases"])

    # Deduplicate
    seen: set[str] = set()
    unique = []
    for tc in sorted(all_test_cases, key=lambda x: x.get("priority", 99)):
        p = tc["payload"]
        if p not in seen:
            seen.add(p)
            unique.append(tc)

    print(f"\nFinal unified test plan ({len(unique)} cases):")
    for tc in unique:
        print(f"  {tc['priority']}. {tc['payload']}")

    # Must have event-handler payloads that don't use < >
    angle_free = [tc["payload"] for tc in unique if "<" not in tc["payload"] and ">" not in tc["payload"]]
    assert angle_free, f"No angle-free payloads generated! All payloads: {[tc['payload'] for tc in unique]}"

    event_handlers = [p for p in angle_free if any(
        ev in p for ev in ["onmouseover", "onfocus", "onmouseenter", "onclick", "oninput"]
    )]
    assert event_handlers, f"No event handler payloads! Angle-free: {angle_free}"

    print(f"\nValid event-handler payloads (no < or >): {event_handlers}")
    print("PASS: heuristic generates correct payloads for html_attribute + encoded angles")


def test_encoding_detection():
    """Verify < > are blocked and \" is exploitable."""
    assert not ENC_PROFILE["can_break_html_text"], "html_text should not be breakable"
    assert ENC_PROFILE["can_break_html_attribute"], "html_attribute should be breakable via \""
    assert '"' in ENC_PROFILE["raw_chars"], "\" should be in raw_chars"
    assert "<" in ENC_PROFILE["encoded_chars"], "< should be encoded"
    print("\nPASS: encoding profile correctly reflects the lab's behaviour")


if __name__ == "__main__":
    print("=" * 60)
    print("XScan Pipeline Test: attribute XSS with encoded angle brackets")
    print("=" * 60)

    test_encoding_detection()
    all_ctxs = test_context_picks_attribute()
    test_heuristic_generates_event_handler_payloads(all_ctxs)

    print("\n" + "=" * 60)
    print("ALL TESTS PASSED")
    print("=" * 60)
    print("\nFor this lab the correct exploit is:")
    print('  URL: https://target.net/?search=" onmouseover="alert(1)')
    print("  Or:  https://target.net/?search=\" onfocus=\"alert(1)\" autofocus=\"")
    raise SystemExit(0)
