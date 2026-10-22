"""
Technology fingerprinting from HTTP responses.
Detects frameworks, servers, and security headers.
"""
from __future__ import annotations
import re
from xscan.core.models import HttpResponse

# ── Signatures ──────────────────────────────────────────────────────────────
# Each entry: (pattern_in_body_or_header, technology_label)
# Checked against response headers + body

_HEADER_SIGS: list[tuple[str, str, str]] = [
    # (header_name, value_pattern, label)
    ("server",           r"nginx",          "Nginx"),
    ("server",           r"apache",         "Apache"),
    ("server",           r"iis",            "IIS"),
    ("server",           r"lighttpd",       "Lighttpd"),
    ("server",           r"caddy",          "Caddy"),
    ("x-powered-by",     r"php",            "PHP"),
    ("x-powered-by",     r"asp\.net",       "ASP.NET"),
    ("x-powered-by",     r"express",        "Express.js"),
    ("x-powered-by",     r"next\.js",       "Next.js"),
    ("x-generator",      r"wordpress",      "WordPress"),
    ("x-generator",      r"drupal",         "Drupal"),
    ("set-cookie",       r"jsessionid",     "Java/Tomcat"),
    ("set-cookie",       r"laravel_session","Laravel"),
    ("set-cookie",       r"csrftoken",      "Django"),
    ("set-cookie",       r"rack\.session",  "Ruby/Rack"),
    ("cf-ray",           r".",              "Cloudflare"),
    ("x-cache",          r".",              "CDN/Cache"),
]

_BODY_SIGS: list[tuple[str, str]] = [
    # (pattern_in_body, label)
    (r"react",                        "React"),
    (r"__NEXT_DATA__",                "Next.js"),
    (r"ng-version|angular",           "Angular"),
    (r"vue\.js|createApp\(",          "Vue.js"),
    (r"jquery",                       "jQuery"),
    (r"bootstrap\.min\.js",           "Bootstrap"),
    (r"wp-content/themes",            "WordPress"),
    (r"Powered by Drupal",            "Drupal"),
    (r"laravel",                      "Laravel"),
    (r"csrf_token",                   "Django/CSRF"),
    (r"<\?php",                       "PHP"),
    (r"graphql",                      "GraphQL"),
    (r"_rails",                       "Rails"),
    (r"Shopify\.theme",               "Shopify"),
]

_SECURITY_HEADERS = [
    "content-security-policy",
    "x-frame-options",
    "x-xss-protection",
    "strict-transport-security",
    "permissions-policy",
    "x-content-type-options",
    "referrer-policy",
]


def fingerprint(resp: HttpResponse) -> dict:
    """
    Fingerprint a target from its HTTP response.

    Returns::

        {
            "technologies": ["Nginx", "PHP", "WordPress"],
            "security_headers": {"csp": True, "hsts": False, ...},
            "missing_security_headers": ["hsts", "csp"],
            "cookies": [...],
            "server": "nginx/1.24",
        }
    """
    techs: set[str] = set()
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    body_lower = resp.body.lower()

    # Header signatures
    for hdr, pattern, label in _HEADER_SIGS:
        val = headers_lower.get(hdr, "")
        if val and re.search(pattern, val, re.I):
            techs.add(label)

    # Body signatures
    for pattern, label in _BODY_SIGS:
        if re.search(pattern, resp.body, re.I):
            techs.add(label)

    # Security headers audit
    sec: dict[str, bool] = {}
    missing: list[str] = []
    for h in _SECURITY_HEADERS:
        present = h in headers_lower
        short = h.replace("x-", "").replace("-", "_")
        sec[short] = present
        if not present:
            missing.append(h)

    return {
        "technologies":              sorted(techs),
        "security_headers":          sec,
        "missing_security_headers":  missing,
        "server":                    headers_lower.get("server", ""),
        "cookies":                   _parse_cookies(headers_lower),
    }


def _parse_cookies(headers: dict[str, str]) -> list[dict]:
    cookies: list[dict] = []
    raw = headers.get("set-cookie", "")
    if not raw:
        return cookies
    for part in raw.split(","):
        part = part.strip()
        if "=" not in part:
            continue
        attrs = [a.strip() for a in part.split(";")]
        name_val = attrs[0].split("=", 1) if attrs else []
        if len(name_val) != 2:
            continue
        info = {
            "name":      name_val[0],
            "value":     name_val[1][:40],
            "httponly":  any("httponly" in a.lower() for a in attrs),
            "secure":    any("secure" in a.lower() for a in attrs),
            "samesite":  next((a.split("=")[1] for a in attrs if "samesite" in a.lower()), ""),
        }
        cookies.append(info)
    return cookies
