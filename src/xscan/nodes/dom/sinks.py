"""
DOM Sink registry and detection.
Finds dangerous HTML/JS sinks in JavaScript.
"""
from __future__ import annotations
import re
from xscan.schemas.xss import DOMSinkObservation, DOMSinkCategory

# Extensible registry: (pattern, label, category, severity)
SINK_REGISTRY: list[tuple[str, str, DOMSinkCategory, str]] = [
    # Critical HTML sinks
    (r"\.innerHTML\s*=",          "innerHTML",            DOMSinkCategory.HTML,       "critical"),
    (r"\.outerHTML\s*=",          "outerHTML",            DOMSinkCategory.HTML,       "critical"),
    (r"document\.write\s*\(",     "document.write()",     DOMSinkCategory.DOM,        "critical"),
    (r"document\.writeln\s*\(",   "document.writeln()",   DOMSinkCategory.DOM,        "critical"),
    (r"\.insertAdjacentHTML\s*\(","insertAdjacentHTML()", DOMSinkCategory.HTML,       "critical"),
    # JS execution sinks — ONLY dynamic code execution, NOT regular function syntax
    # \bFunction\( matches Function(str) dynamic constructor but NOT function() {} callbacks
    (r"\beval\s*\(",                              "eval()",               DOMSinkCategory.JAVASCRIPT, "critical"),
    # Function() only as dynamic constructor: new Function( or Function( with string/variable arg
    # NOT: function() {}, .on('event', function() {})
    (r"\bnew\s+Function\s*\(",                    "Function()",           DOMSinkCategory.JAVASCRIPT, "critical"),
    (r"(?<!\bfunction\s)(?<!\w)Function\s*\(\s*['\"`]", "Function(str)",  DOMSinkCategory.JAVASCRIPT, "critical"),
    (r"setTimeout\s*\(\s*['\"`]",                 "setTimeout(str)",      DOMSinkCategory.JAVASCRIPT, "high"),
    (r"setInterval\s*\(\s*['\"`]",                "setInterval(str)",     DOMSinkCategory.JAVASCRIPT, "high"),
    # jQuery sinks
    (r"\$\s*\(",                  "jQuery $()",           DOMSinkCategory.SELECTOR,   "high"),
    (r"\$\w*\.html\s*\(",         "jQuery .html()",       DOMSinkCategory.FRAMEWORK,  "high"),
    (r"\$\w*\.append\s*\(",       "jQuery .append()",     DOMSinkCategory.FRAMEWORK,  "high"),
    (r"\$\w*\.prepend\s*\(",      "jQuery .prepend()",    DOMSinkCategory.FRAMEWORK,  "high"),
    (r"\$\w*\.after\s*\(",        "jQuery .after()",      DOMSinkCategory.FRAMEWORK,  "high"),
    (r"\$\w*\.before\s*\(",       "jQuery .before()",     DOMSinkCategory.FRAMEWORK,  "high"),
    (r"\.parseHTML\s*\(",         "jQuery.parseHTML()",   DOMSinkCategory.FRAMEWORK,  "high"),
    # Attribute / URL sinks
    (r"\.href\s*=",               "element.href",         DOMSinkCategory.URL,        "high"),
    (r"\.src\s*=",                "element.src",          DOMSinkCategory.URL,        "high"),
    (r"location\.assign\s*\(",    "location.assign()",    DOMSinkCategory.URL,        "high"),
    (r"location\.replace\s*\(",   "location.replace()",   DOMSinkCategory.URL,        "high"),
    (r"\.setAttribute\s*\(\s*['\"]on", "setAttribute(on*)","attribute",               "medium"),
]


def detect_sinks(content: str, file_url: str) -> list[DOMSinkObservation]:
    """Find all DOM taint sinks in a JS content string."""
    observations: list[DOMSinkObservation] = []
    lines = content.splitlines()

    for line_no, line in enumerate(lines, 1):
        for pattern, label, category, severity in SINK_REGISTRY:
            m = re.search(pattern, line, re.I)
            if m:
                observations.append(DOMSinkObservation(
                    sink_label=label,
                    sink_category=category,
                    severity=severity,
                    file_url=file_url,
                    line=line_no,
                    column=m.start(),
                    snippet=line.strip()[:200],
                    confidence="high" if severity == "critical" else "medium",
                ))
    return observations
