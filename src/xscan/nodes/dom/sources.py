"""
DOM Source registry and detection.
Finds attacker-controlled data sources in JavaScript.
"""
from __future__ import annotations
import re
from xscan.schemas.xss import DOMSourceObservation, DOMSourceType

# Extensible registry: pattern -> (label, source_type, confidence)
SOURCE_REGISTRY: list[tuple[str, str, DOMSourceType, str]] = [
    (r"location\.hash",                   "location.hash",          DOMSourceType.LOCATION_HASH,     "high"),
    (r"location\.search",                 "location.search",        DOMSourceType.LOCATION_SEARCH,   "high"),
    (r"location\.href",                   "location.href",          DOMSourceType.LOCATION_HREF,     "high"),
    (r"document\.URL\b",                  "document.URL",           DOMSourceType.DOCUMENT_URL,      "high"),
    (r"document\.documentURI\b",          "document.documentURI",   DOMSourceType.DOCUMENT_URL,      "high"),
    (r"document\.referrer\b",             "document.referrer",      DOMSourceType.DOCUMENT_REFERRER, "medium"),
    (r"window\.name\b",                   "window.name",            DOMSourceType.WINDOW_NAME,       "high"),
    (r"URLSearchParams[^;]*?\.get\(",     "URLSearchParams.get()",  DOMSourceType.URL_SEARCH_PARAMS, "high"),
    (r"decodeURIComponent\(",             "decodeURIComponent()",   DOMSourceType.DECODE_URI,        "medium"),
    (r"addEventListener\s*\(\s*['\"]message['\"]", "postMessage",   DOMSourceType.POST_MESSAGE,      "medium"),
    (r"document\.cookie\b",              "document.cookie",         DOMSourceType.COOKIE,            "medium"),
    (r"localStorage\.getItem\(",         "localStorage",            DOMSourceType.LOCAL_STORAGE,     "low"),
    (r"sessionStorage\.getItem\(",       "sessionStorage",          DOMSourceType.SESSION_STORAGE,   "low"),
]


def detect_sources(content: str, file_url: str) -> list[DOMSourceObservation]:
    """Find all DOM taint sources in a JS content string."""
    observations: list[DOMSourceObservation] = []
    lines = content.splitlines()

    for line_no, line in enumerate(lines, 1):
        for pattern, label, source_type, confidence in SOURCE_REGISTRY:
            m = re.search(pattern, line, re.I)
            if m:
                # Try to find assignment target
                assigned = ""
                assign_m = re.search(
                    r"\b(?:var|let|const)?\s*([\w$]+)\s*=\s*(?:.*?)" + re.escape(m.group()[:20]),
                    line,
                )
                if assign_m:
                    assigned = assign_m.group(1)

                observations.append(DOMSourceObservation(
                    source_type=source_type,
                    label=label,
                    file_url=file_url,
                    line=line_no,
                    column=m.start(),
                    snippet=line.strip()[:200],
                    assigned_to=assigned,
                    confidence=confidence,
                ))
    return observations
