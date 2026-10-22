"""Test that Function() sink detection doesn't false-positive on callbacks."""
from xscan.nodes.dom.sinks import detect_sinks


def test_no_false_positive_on_callbacks():
    safe_cases = [
        ('$(window).on("hashchange", function() {', "hashchange callback"),
        ("var fn = function() { return x; }",        "anonymous function expression"),
        (".on('click', function(e) { e.preventDefault(); })", "event handler callback"),
        ("array.forEach(function(item) { process(item); })", "forEach callback"),
        ("setTimeout(function() { doSomething(); }, 100)",    "setTimeout with function arg"),
    ]
    for code, description in safe_cases:
        sinks = detect_sinks(code, "test.js")
        func_sinks = [s for s in sinks if "Function" in s.sink_label]
        assert not func_sinks, (
            f"FALSE POSITIVE: {description!r} should not produce Function() sink\n"
            f"  Code: {code}\n"
            f"  Got:  {[s.sink_label for s in func_sinks]}"
        )
        print(f"  OK (no FP): {description}")


def test_detects_dynamic_function_constructor():
    dangerous_cases = [
        ('var f = new Function(userInput)',   "new Function(var)"),
        ('new Function("alert(1)")()',         "new Function(string literal)"),
    ]
    for code, description in dangerous_cases:
        sinks = detect_sinks(code, "test.js")
        func_sinks = [s for s in sinks if "Function" in s.sink_label]
        assert func_sinks, (
            f"MISSED: {description!r} should produce Function() sink\n"
            f"  Code: {code}"
        )
        print(f"  DETECTED: {description}")


def test_jquery_hashchange_pattern_no_function_fp():
    """The exact PortSwigger lab pattern should NOT produce Function() sink."""
    lab_code = """
$(window).on('hashchange', function(){
    var post = $('section.blog-list h2:contains(' + decodeURIComponent(window.location.hash.slice(1)) + ')');
    if (post) post.get(0).scrollIntoView();
});
"""
    sinks = detect_sinks(lab_code, "inline")
    sink_labels = [s.sink_label for s in sinks]
    print(f"  Sinks detected: {sink_labels}")

    # Must detect jQuery $() as a sink
    assert any("jQuery" in s for s in sink_labels), \
        f"Should detect jQuery $() sink. Got: {sink_labels}"

    # Must NOT detect Function() as a sink (the 'function()' callback is not a sink)
    func_sinks = [s for s in sink_labels if "Function" in s]
    assert not func_sinks, \
        f"FALSE POSITIVE: Function() sink from callback. Got: {func_sinks}"

    print(f"  OK: jQuery $() detected, no Function() false positive")


if __name__ == "__main__":
    test_no_false_positive_on_callbacks()
    test_detects_dynamic_function_constructor()
    test_jquery_hashchange_pattern_no_function_fp()
    print("\nAll Function() sink tests passed.")
