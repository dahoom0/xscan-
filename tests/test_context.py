"""
Context analyser tests — covers all reflection contexts including the
multi-reflection case (html_text + html_attribute) which must pick html_attribute.
"""
from xscan.nodes.analysis.context import ContextAnalyser


def test_all():
    ca = ContextAnalyser()

    tests = [
        ("html_text inside h1 single-quoted",
         "<h1>0 results for 'xscC01'</h1>",
         "xscC01", "html_text"),

        ("html_text plain",
         "<p>Hello xscC01 world</p>",
         "xscC01", "html_text"),

        ("html_attribute double-quoted",
         '<input value="xscC01" name="q">',
         "xscC01", "html_attribute"),

        ("html_attribute single-quoted",
         "<input value='xscC01' name='q'>",
         "xscC01", "html_attribute"),

        ("script string double",
         '<script>var x = "xscC01"; </script>',
         "xscC01", "script_string_double"),

        ("script string single",
         "<script>var x = 'xscC01'; </script>",
         "xscC01", "script_string_single"),

        ("html comment",
         "<!-- xscC01 -->",
         "xscC01", "html_comment"),

        # The critical case: two reflections — html_text (h1) + html_attribute (input)
        # Analyser must pick html_attribute as more exploitable
        ("multi-reflection: html_text + html_attribute -> picks attribute",
         """<h1>0 results for 'xscC01'</h1>
            <input type=text name=search value="xscC01">""",
         "xscC01", "html_attribute"),
    ]

    all_pass = True
    for desc, body, marker, expected in tests:
        r = ca.analyse(body, marker)
        status = "PASS" if r.context == expected else "FAIL"
        print(f"  {status}  {desc:<55}  got={r.context}")
        if status == "FAIL":
            all_pass = False
            print(f"         expected={expected}")
            print(f"         before={r.before[-40:]!r}")

    print(f"\nAll pass: {all_pass}")
    return all_pass


def test_heuristic_attribute_with_encoded_angles():
    """
    html_attribute + encoded < > but raw " → must generate event-handler payloads.
    This is the PortSwigger 'Reflected XSS into attribute with angle brackets HTML-encoded' lab.
    """
    from xscan.nodes.validation.xss_validate import XssValidatorNode

    node = XssValidatorNode()
    ctx_analysis = {
        "context":      "html_attribute",
        "tag":          "input",
        "attribute":    "value",
        "quote_type":   "double",
        "breakout_chars": ['"'],
    }
    enc_profile = {
        "raw_chars":     ['"', "'", " ", "="],
        "encoded_chars": ["<", ">"],
        "stripped_chars":[],
        "can_break_html_text":      False,
        "can_break_html_attribute": True,
        "can_break_script_string":  True,
    }
    plan = node._heuristic_plan(ctx_analysis, enc_profile)

    assert plan["viable"], "Plan should be viable"
    payloads = [tc["payload"] for tc in plan["test_cases"]]
    print("\n  Heuristic payloads for html_attribute (encoded angles):")
    for p in payloads:
        print(f"    {p}")

    # Must contain event-handler payloads that don't use < >
    angle_free = [p for p in payloads if "<" not in p and ">" not in p]
    assert angle_free, f"No angle-free payloads! Got: {payloads}"
    assert any("onmouseover" in p or "onfocus" in p or "onmouseenter" in p
               for p in angle_free), "Must have event handler payload"
    print("  PASS — event handler payloads present without < >")
    return True


if __name__ == "__main__":
    ok1 = test_all()
    ok2 = test_heuristic_attribute_with_encoded_angles()
    raise SystemExit(0 if (ok1 and ok2) else 1)
