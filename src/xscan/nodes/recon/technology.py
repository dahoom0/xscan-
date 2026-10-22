"""
technology-detect node
======================
Probes the target and fingerprints its technology stack.
Migrated from prototype recon/fingerprint.py into a proper DAG node.

Inputs:  target_url (str)
Outputs: technologies (list[str]), server (str), security_headers (dict),
         missing_security_headers (list[str]), cookies (list[dict]),
         http_status (int), response_time_ms (float)
"""
from __future__ import annotations
import re
import time
from typing import Any
from xscan.nodes.base import NodeBase, ExecutionContext
from xscan.nodes.emitter import NodeEmitter
from xscan.core.dag.node_registry import registry


@registry.register("technology-detect")
class TechnologyDetectNode(NodeBase, NodeEmitter):
    node_type = "technology-detect"

    # ── Signatures (from prototype fingerprint.py) ────────────────────

    _HEADER_SIGS: list[tuple[str, str, str]] = [
        ("server",        r"nginx",           "Nginx"),
        ("server",        r"apache",          "Apache"),
        ("server",        r"iis",             "IIS"),
        ("server",        r"lighttpd",        "Lighttpd"),
        ("server",        r"caddy",           "Caddy"),
        ("x-powered-by",  r"php",             "PHP"),
        ("x-powered-by",  r"asp\.net",        "ASP.NET"),
        ("x-powered-by",  r"express",         "Express.js"),
        ("x-powered-by",  r"next\.js",        "Next.js"),
        ("x-generator",   r"wordpress",       "WordPress"),
        ("x-generator",   r"drupal",          "Drupal"),
        ("set-cookie",    r"jsessionid",      "Java/Tomcat"),
        ("set-cookie",    r"laravel_session", "Laravel"),
        ("set-cookie",    r"csrftoken",       "Django"),
        ("set-cookie",    r"rack\.session",   "Ruby/Rack"),
        ("cf-ray",        r".",               "Cloudflare"),
        ("x-cache",       r".",               "CDN/Cache"),
    ]

    _BODY_SIGS: list[tuple[str, str]] = [
        # React — bundle markers and root div
        (r"react",                              "React"),
        (r'id=["\']root["\']',                  "React"),
        (r"__react",                            "React"),
        (r"_reactFiber",                        "React"),
        # Next.js
        (r"__NEXT_DATA__",                      "Next.js"),
        (r"_next/static",                       "Next.js"),
        # Angular — app-root tag, ng version attribute, scripts
        (r"<app-root",                          "Angular"),
        (r"ng-version",                         "Angular"),
        (r"angular(?:\.min)?\.js",              "Angular"),
        (r"main\.js.*type=[\"']module[\"']",    "Angular"),
        # Vue
        (r"vue\.js|createApp\(",                "Vue.js"),
        (r'id=["\']app["\']',                   "Vue.js"),
        # jQuery
        (r"jquery",                             "jQuery"),
        # Bootstrap
        (r"bootstrap(?:\.min)?\.(?:js|css)",    "Bootstrap"),
        # WordPress
        (r"wp-content/themes",                  "WordPress"),
        (r"wp-includes",                        "WordPress"),
        # Drupal
        (r"Powered by Drupal",                  "Drupal"),
        (r"drupal\.js",                         "Drupal"),
        # Laravel
        (r"laravel",                            "Laravel"),
        # Django
        (r"csrf_token|csrfmiddlewaretoken",     "Django/CSRF"),
        # GraphQL
        (r"graphql",                            "GraphQL"),
        # Rails
        (r"_rails",                             "Rails"),
        (r"rails-ujs",                          "Rails"),
        # Shopify
        (r"Shopify\.theme",                     "Shopify"),
        # Svelte
        (r"svelte",                             "Svelte"),
        # Ember
        (r"ember",                              "Ember"),
        # Express / Node
        (r"express",                            "Express.js"),
        # Juice Shop (OWASP) — specific marker
        (r"juice.shop|juiceshop|OWASP Juice",   "OWASP Juice Shop"),
    ]

    _SECURITY_HEADERS = [
        "content-security-policy", "x-frame-options",
        "x-xss-protection", "strict-transport-security",
        "permissions-policy", "x-content-type-options", "referrer-policy",
    ]

    def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
        t0 = self.emit_started(ctx)
        target_url: str = ctx.get("target_url", "")
        if not target_url:
            raise ValueError("technology-detect: target_url required")

        ctx.scope.assert_allowed(target_url, operation="http_request")

        import httpx
        headers_map: dict[str, str] = {}
        body = ""
        status_code = 0
        elapsed_ms = 0.0

        try:
            t_http = time.monotonic()
            resp = httpx.get(
                target_url,
                follow_redirects=True,
                timeout=ctx.config.get("timeout", 15),
                verify=False,
                headers={"User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36"
                )},
            )
            elapsed_ms = round((time.monotonic() - t_http) * 1000, 1)
            headers_map = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.text[:50_000]
            status_code = resp.status_code
        except Exception as exc:
            ctx.logger.warning("technology-detect HTTP error: %s", exc)
            self.emit_warning(ctx, f"HTTP error: {exc}")
            ms = (time.monotonic() - t0) * 1000
            self.emit_completed(ctx, metrics={"http_status": 0, "technologies_count": 0}, duration_ms=ms)
            return {
                "technologies": [], "server": "", "http_status": 0,
                "missing_security_headers": list(self._SECURITY_HEADERS),
                "security_headers": {}, "cookies": [],
                "response_time_ms": 0.0,
            }

        techs: set[str] = set()
        for hdr, pattern, label in self._HEADER_SIGS:
            val = headers_map.get(hdr, "")
            if val and re.search(pattern, val, re.I):
                techs.add(label)
        for pattern, label in self._BODY_SIGS:
            if re.search(pattern, body, re.I):
                techs.add(label)

        sec: dict[str, bool] = {}
        missing: list[str] = []
        for h in self._SECURITY_HEADERS:
            present = h in headers_map
            sec[h] = present
            if not present:
                missing.append(h)

        cookies: list[dict] = []
        raw_cookie = headers_map.get("set-cookie", "")
        if raw_cookie:
            for part in raw_cookie.split(","):
                attrs = [a.strip() for a in part.strip().split(";")]
                if "=" in attrs[0]:
                    n, v = attrs[0].split("=", 1)
                    cookies.append({
                        "name":     n,
                        "httponly": any("httponly" in a.lower() for a in attrs),
                        "secure":   any("secure" in a.lower() for a in attrs),
                        "samesite": next((a.split("=")[1] for a in attrs if "samesite" in a.lower()), ""),
                    })

        ms = (time.monotonic() - t0) * 1000
        self.emit_completed(ctx, metrics={
            "http_status":        status_code,
            "technologies_count": len(techs),
            "missing_headers":    len(missing),
            "response_ms":        round(elapsed_ms),
        }, duration_ms=ms)

        return {
            "technologies":            sorted(techs),
            "server":                  headers_map.get("server", ""),
            "security_headers":        sec,
            "missing_security_headers": missing,
            "cookies":                 cookies,
            "http_status":             status_code,
            "response_time_ms":        elapsed_ms,
            "response_body_snippet":   body[:2000],
        }
