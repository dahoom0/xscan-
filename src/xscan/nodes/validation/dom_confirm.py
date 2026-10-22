"""
dom-confirm node — browser confirmation for DOM XSS candidates
==============================================================
Static analysis can only *suspect* a DOM XSS flow: it cannot know whether the
tainted value actually reaches the sink, or whether the sink executes. This node
answers that in a real browser:

  * loads each candidate's test URL with alert/confirm/prompt hooked
  * triggers the sink the way a victim would — clicking a link whose href became
    ``javascript:``, firing the event that drives an event-handler sink
  * captures the DOM state proving the payload reached the sink (the attribute
    value) and any execution (a dialog fired)

Only real execution marks a candidate CONFIRMED. A sink that holds the payload
but never fires is reported as captured-but-unconfirmed evidence — never as a
finding, and never as "safe".

The browser is the system Chrome/Edge driven through Playwright: no browser
download is required, and every navigation passes through ScopeEngine.

Inputs:  fused_candidates | xss_candidates | dom_candidates,
         validated_candidates (existing results are preserved)
Outputs: dom_confirmations (list[dict])
         confirmed_candidates (list[dict])
         confirmed_count (int)
         validated_candidates (existing + this node's results)
         validated_count (int)
"""
from __future__ import annotations

import contextlib
import time
from typing import Any
from urllib.parse import urlsplit

from xscan.core.dag.node_registry import registry
from xscan.nodes.analysis.dompurify_scan import (
    _HOOK_SCRIPT,
    _launch_browser,
    _system_browser_present,
)
from xscan.nodes.analysis.stored_xss import _sink_kind
from xscan.nodes.base import ExecutionContext, NodeBase
from xscan.nodes.emitter import NodeEmitter

_MAX_CANDIDATES = 5
_DEFAULT_TIMEOUT_MS = 20_000  # Increased from 15_000 to handle slow sites

# Elements that can carry a javascript: URL and need a click to fire.
# a[href*="javascript:"] covers relative attribute values the application
# prefixes (e.g. an IDN-normalised or rewritten URL) as well as absolute ones.
_CLICK_SELECTORS = (
    'a[href^="javascript:"]',
    'a[href*="javascript:"]',
    'area[href^="javascript:"]',
    'a[href*="document.cookie"]',
    "[src^=\"javascript:\"]",
    'form[action^="javascript:"] button',
    'form[action^="javascript:"] input[type="submit"]',
)

# Sinks that fire only when the fragment CHANGES (e.g. jQuery hashchange
# handlers). Navigating once to ``...#payload`` does nothing: the handler fires
# on the *second* navigation, so we visit the bare page first, then the payload
# fragment — exactly what the exploit-server iframe does.
_HASH_EVENT_KINDS = {"selector_hashchange", "event_handler"}

# AngularJS compiles {{ ... }} expressions on page load, asynchronously after
# the load event. Give the framework a beat to boot before reading dialogs.
_CSTI_EXTRA_WAIT_MS = 1200


# DOM state that proves the payload reached a sink.
_DOM_STATE_JS = """
(payload) => {
  const out = [];
  if (!payload) return out;
  const needle = String(payload).slice(0, 40);
  document.querySelectorAll('*').forEach((el) => {
    Array.from(el.attributes || []).forEach((attr) => {
      if (String(attr.value).indexOf(needle) !== -1) {
        out.push({
          tag: el.tagName.toLowerCase(),
          id: el.id || '',
          attribute: attr.name,
          value: String(attr.value).slice(0, 200),
        });
      }
    });
  });
  return out.slice(0, 5);
}
"""

_EVENT_CLICK_JS = """
() => {
  const out = [];
  document.querySelectorAll('*').forEach((el) => {
    Array.from(el.attributes || []).forEach((attr) => {
      if (attr.name.indexOf('on') === 0 && String(attr.value).indexOf('alert') !== -1) {
        try { el.click(); out.push(el.tagName.toLowerCase() + '@' + attr.name); } catch (e) {}
      }
    });
  });
  return out.slice(0, 3);
}
"""


def _fragment_url(url: str) -> tuple[str, str] | None:
    """Split a test URL into (page, fragment) when it delivers via the fragment."""
    parts = urlsplit(url)
    if not parts.fragment:
        return None
    return (url.split("#", 1)[0], parts.fragment)


def _populate_dom_test_url(candidate: dict[str, Any]) -> None:
    """
    Generate best_test_url and best_payload for a DOM candidate using the first
    suggested test case. This ensures DOM candidates from dom-xss-detect can be
    properly tested by the browser confirmer even if xss-validate didn't generate
    a payload (because the candidate wasn't in the reflected candidate pool).
    """
    # Try to extract a test payload from test_cases if available
    test_cases = candidate.get("test_cases") or []
    if not test_cases:
        # Fall back to using the base URL if no test cases
        base_url = candidate.get("url", "")
        if base_url:
            candidate["best_test_url"] = base_url
            candidate["best_payload"] = ""
        return

    first_case = test_cases[0]
    payload = str(first_case.get("payload") or "")
    if not payload:
        # No payload in test case
        base_url = candidate.get("url", "")
        if base_url:
            candidate["best_test_url"] = base_url
            candidate["best_payload"] = ""
        return

    # Build test URL with the payload
    base_url = candidate.get("url", "")
    param = candidate.get("parameter") or candidate.get("param") or "q"

    if not base_url:
        candidate["best_payload"] = payload
        return

    # For fragment-based payloads (hash), append to URL
    if first_case.get("delivery") == "fragment" or param == "#":
        candidate["best_test_url"] = f"{base_url}#{payload}"
        candidate["best_payload"] = payload
        return

    # For query parameter payloads, build the URL properly
    from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

    try:
        parsed = urlparse(base_url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [payload]
        new_query = urlencode({k: v[0] for k, v in qs.items()})
        test_url = urlunparse(parsed._replace(query=new_query))
        candidate["best_test_url"] = test_url
        candidate["best_payload"] = payload
    except Exception:
        # Fallback: just set the base URL
        candidate["best_test_url"] = base_url
        candidate["best_payload"] = payload


@registry.register("dom-confirm")
class DomConfirmNode(NodeBase, NodeEmitter):
    node_type = "dom-confirm"

    def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
        t0 = self.emit_started(ctx)

        existing_validated: list[dict[str, Any]] = list(ctx.get("validated_candidates") or [])
        existing_confirmed = int(ctx.get("confirmed_count", 0) or 0)

        candidates = self._select_candidates(ctx)
        # Candidates sharing a page share one browser test. Prefer the one whose
        # sink semantics tell us how to TRIGGER execution — a navigation-only
        # candidate for the same page would waste the slot and fire nothing.
        candidates = self._prioritise_triggerable(candidates)
        limit = int(ctx.config.get("max_candidates", _MAX_CANDIDATES))
        candidates = candidates[:limit]

        if not candidates:
            self.emit_completed(ctx, metrics={"dom_candidates": 0, "confirmed": 0},
                                duration_ms=(time.monotonic() - t0) * 1000)
            return self._result(existing_validated, [], existing_confirmed)

        if not _system_browser_present():
            self.emit_warning(
                ctx,
                "No system Chrome/Edge found — DOM confirmation skipped "
                "(install Chrome/Edge, or run: playwright install chromium)",
            )
            self.emit_completed(ctx, metrics={"dom_candidates": len(candidates), "confirmed": 0},
                                duration_ms=(time.monotonic() - t0) * 1000)
            return self._result(existing_validated, [], existing_confirmed)

        try:
            from playwright.sync_api import sync_playwright
        except Exception as exc:
            self.emit_warning(ctx, f"playwright unavailable — DOM confirmation skipped: {exc}")
            self.emit_completed(ctx, metrics={"dom_candidates": len(candidates), "confirmed": 0},
                                duration_ms=(time.monotonic() - t0) * 1000)
            return self._result(existing_validated, [], existing_confirmed)

        results: list[dict[str, Any]] = []
        seen_urls: set[str] = set()
        try:
            with sync_playwright() as playwright:
                browser = _launch_browser(playwright)
                try:
                    for i, candidate in enumerate(candidates):
                        target = candidate.get("best_test_url") or candidate.get("url") or ""
                        page_key = target.split("#", 1)[0].rstrip("/")
                        if page_key in seen_urls:
                            # Same flow already browser-tested (the crawl often
                            # yields the same page under several spellings).
                            self.emit_progress(ctx, f"  skipping duplicate page: {target[:80]}")
                            continue
                        seen_urls.add(page_key)
                        self.emit_progress(
                            ctx, f"Confirming DOM [{i + 1}/{len(candidates)}] {target[:80]}"
                        )
                        result = self._confirm(ctx, browser, candidate)
                        results.append(result)
                        if result["confirmed"]:
                            self.emit_progress(
                                ctx,
                                f"  CONFIRMED {result['sink'] or 'dom sink'} — "
                                f"dialog fired with payload {result['payload'][:60]!r}",
                            )
                        else:
                            self.emit_progress(ctx, f"  not confirmed: {result['note']}")
                finally:
                    browser.close()
        except Exception as exc:
            self.emit_warning(ctx, f"DOM confirmation aborted: {str(exc)[:160]}")

        confirmed = [r["candidate"] for r in results if r["confirmed"]]
        validated = self._merge_validated(existing_validated, results)
        self.emit_completed(ctx, metrics={
            "dom_candidates":  len(candidates),
            "confirmed":       len(confirmed),
            "browser_checked": len(results),
        }, duration_ms=(time.monotonic() - t0) * 1000)

        return self._result(validated, results, existing_confirmed + len(confirmed))

    @staticmethod
    def _merge_validated(
        existing: list[dict[str, Any]],
        results: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Merge browser results into the validated list, replacing (not
        duplicating) the entry the HTTP validator already wrote for the same
        page + parameter.
        """
        def entry_key(entry: dict[str, Any]) -> tuple[str, str]:
            url = str(entry.get("best_test_url") or entry.get("url") or "").split("#", 1)[0]
            return (url.rstrip("/"), str(entry.get("parameter") or entry.get("param") or ""))

        merged: list[dict[str, Any]] = list(existing)
        for result in results:
            key = entry_key(result["candidate"])
            merged = [v for v in merged if entry_key(v) != key]
            merged.append(result["candidate"])
        return merged

    # ------------------------------------------------------------------

    @staticmethod
    def _result(
        validated: list[dict[str, Any]],
        results: list[dict[str, Any]],
        confirmed_count: int,
    ) -> dict[str, Any]:
        return {
            "dom_confirmations": [{
                "url":          r["url"],
                "param":        r["param"],
                "payload":      r["payload"],
                "sink":         r["sink"],
                "sink_kind":    r["sink_kind"],
                "interaction":  r["interaction"],
                "trigger_event": r["trigger_event"],
                "confirmed":    r["confirmed"],
                "dialog_fired": r["dialog_fired"],
                "dialogs":      r["dialogs"][:3],
                "dom_state":    r["dom_state"],
                "triggered":    r["triggered"],
                "delivered":    r["delivered"],
                "note":         r["note"],
                "why":          (r["candidate"].get("why") or []) if isinstance(r.get("candidate"), dict) else [],
            } for r in results],
            "confirmed_candidates": [r["candidate"] for r in results if r["confirmed"]],
            "confirmed_count":      confirmed_count,
            "validated_candidates": validated,
            "validated_count":      sum(1 for v in validated if v.get("validated")),
        }

    @staticmethod
    def _prioritise_triggerable(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Within each page, put candidates whose trigger is known first.

        Ordering is stable: a page's candidates keep their relative order, just
        re-ranked so the triggerable one claims the page slot in the browser.
        """
        def rank(raw: dict[str, Any]) -> int:
            profile = raw.get("encoding_profile") or {}
            kind = str(raw.get("sink_kind") or profile.get("sink_kind") or "")
            interaction = str(raw.get("interaction") or profile.get("interaction") or "")
            if kind in _HASH_EVENT_KINDS or raw.get("trigger_event") == "hashchange":
                return 0
            if interaction in ("click", "event", "submit"):
                return 1
            return 2

        return sorted(candidates, key=lambda c: (rank(c), c.get("url", "")))

    @staticmethod
    def _select_candidates(ctx: ExecutionContext) -> list[dict[str, Any]]:
        """
        Candidates that need browser verification: DOM flows (static analysis
        cannot prove execution) and stored flows whose reflection landed in a
        sink that needs a victim action (a javascript: URI in an href needs a
        click — no HTTP request can ever observe that).
        """
        pool: list[dict[str, Any]] = (
            ctx.get("fused_candidates")
            or ctx.get("xss_candidates")
            or ctx.get("dom_candidates")
            or []
        )
        selected: list[dict[str, Any]] = []
        for raw in pool:
            if not (raw.get("best_test_url") or raw.get("url")):
                continue
            profile = raw.get("encoding_profile") or {}
            if raw.get("xss_type") == "stored":
                # Stored candidates only need the browser when the reflection
                # context cannot be executed by a plain page load.
                ca = raw.get("context_analysis") or {}
                kind = _sink_kind(
                    str(ca.get("context", "") or ""),
                    str(ca.get("attribute_name", "") or ""),
                )
                if kind:
                    selected.append(raw)
                continue
            is_dom = (
                raw.get("xss_type") == "dom"
                or profile.get("xss_type") == "dom"
                or bool(raw.get("sink_kind"))
                or bool(profile.get("sink_kind"))
                or bool(raw.get("requires_browser"))
            )
            # HTTP validation can never prove execution for script/template
            # contexts (the code runs client-side); the browser is the only
            # judge, so inconclusive script-context candidates are selected too.
            ca_ctx = str((raw.get("context_analysis") or {}).get("context") or "")
            needs_browser_judge = ca_ctx.startswith("script_") or (
                str(profile.get("sink_capability") or "") == "js_execution"
            )
            if is_dom or (
                needs_browser_judge and raw.get("validation_status") == "inconclusive"
            ):
                # For DOM candidates without a best_test_url, generate one
                # using the first suggested payload from test_cases if available
                if not raw.get("best_test_url") and raw.get("xss_type") == "dom":
                    _populate_dom_test_url(raw)
                selected.append(raw)
        return selected

    def _confirm(
        self,
        ctx: ExecutionContext,
        browser: Any,
        candidate: dict[str, Any],
    ) -> dict[str, Any]:
        profile = candidate.get("encoding_profile") or {}
        result: dict[str, Any] = {
            "url":          str(candidate.get("best_test_url") or candidate.get("url") or ""),
            "param":        str(candidate.get("parameter") or candidate.get("param") or ""),
            "payload":      str(candidate.get("best_payload") or ""),
            "sink":         str(candidate.get("sink") or profile.get("sink") or ""),
            "sink_kind":    str(candidate.get("sink_kind") or profile.get("sink_kind") or ""),
            "interaction":  str(candidate.get("interaction") or profile.get("interaction") or "none"),
            "trigger_event": str(
                candidate.get("trigger_event") or profile.get("trigger_event") or ""
            ),
            "confirmed":    False,
            "dialog_fired": False,
            "dialogs":      [],
            "dom_state":    [],
            "triggered":    [],
            "delivered":    False,
            "note":         "",
        }

        if not result["url"]:
            result["note"] = "no test url"
            result["candidate"] = self._mark(candidate, result)
            return result

        try:
            ctx.scope.assert_allowed(result["url"], operation="http_request")
        except Exception as exc:
            result["note"] = f"scope_blocked: {exc}"
            result["candidate"] = self._mark(candidate, result)
            return result

        timeout_ms = int(ctx.config.get("timeout_ms", _DEFAULT_TIMEOUT_MS))
        fragment = _fragment_url(result["url"])
        is_hash_event = (
            result["sink_kind"] in _HASH_EVENT_KINDS or result["trigger_event"] == "hashchange"
        )
        # Stored flow: the payload is not delivered by a URL — it has to be
        # POSTed to the storage form first, exactly like the manual lab
        # solution (post a comment carrying the payload, then view the post).
        stored_action = str(candidate.get("stored_at") or "")
        stored_param = str(candidate.get("parameter") or "")
        page = None
        try:
            page = browser.new_page()
            page.add_init_script(script=_HOOK_SCRIPT)
            if stored_action and stored_param:
                result["delivered"] = self._deliver_stored_payload(
                    page, stored_action, stored_param, result["payload"], timeout_ms,
                )
                if result["delivered"]:
                    # Form submission already landed us on the post-display
                    # page — re-navigating would re-fetch the pre-submission
                    # form page and lose the payload. The form target IS the
                    # candidate's display page. (Mutate the candidate dict
                    # directly: result["candidate"] is attached afterwards.)
                    result["url"] = page.url
                    candidate["best_test_url"] = page.url
                    fragment = None
            if fragment and is_hash_event:
                # Two-step delivery: the hashchange handler only fires when the
                # fragment CHANGES, so land on the page first, then navigate to
                # the payload fragment (what the exploit iframe does).
                page.goto(fragment[0], wait_until="load", timeout=timeout_ms)
                page.wait_for_timeout(300)
                page.evaluate("(f) => { location.hash = f; }", fragment[1])
            else:
                page.goto(result["url"], wait_until="load", timeout=timeout_ms)
            page.wait_for_timeout(300)
            if result["sink_kind"] == "csti":
                # Angular compiles templates asynchronously after load.
                page.wait_for_timeout(_CSTI_EXTRA_WAIT_MS)

            result["dom_state"] = list(page.evaluate(_DOM_STATE_JS, result["payload"]) or [])

            if result["sink_kind"] == "url_attribute":
                result["triggered"] = self._click_url_triggers(page)
            elif result["interaction"] == "event" or result["sink_kind"] == "event_handler":
                result["triggered"] = list(page.evaluate(_EVENT_CLICK_JS) or [])
            page.wait_for_timeout(400)

            dialogs = list(page.evaluate("() => window.__xscan_dialogs || []") or [])
            result["dialogs"] = dialogs
            result["dialog_fired"] = bool(dialogs)
            
            # Mark as confirmed ONLY if dialogs fired 
            # (actual execution, not just reflection in DOM)
            result["confirmed"] = bool(dialogs)
            if not dialogs and result["dom_state"] and self._is_inert_script_payload(
                result["payload"]
            ):
                # Failure analysis: the payload reached the sink but <script>
                # inserted via innerHTML/insertAdjacentHTML never executes.
                # One budgeted retry with the next ranked candidate (an
                # event-handler element, which DOES fire when inserted).
                alt = self._next_refined_candidate(candidate, result["payload"])
                if alt:
                    retry = self._confirm(ctx, browser, alt)
                    if retry["confirmed"]:
                        retry["note"] = (
                            "first candidate inert in DOM (<script> via innerHTML "
                            "does not execute); refined candidate executed"
                        )
                        retry["parent_candidate"] = result["payload"]
                        result.update(retry)
                        result["candidate"] = retry["candidate"]
                        return result
            if not dialogs:
                result["note"] = (
                    "sink holds the payload but no execution observed"
                    if result["dom_state"]
                    else "payload not observed in DOM"
                )
        except Exception as exc:
            result["note"] = f"browser error: {str(exc)[:160]}"
        finally:
            if page is not None:
                with contextlib.suppress(Exception):
                    page.close()

        result["candidate"] = self._mark(candidate, result)
        return result

    def _deliver_stored_payload(
        self,
        page: Any,
        action: str,
        parameter: str,
        payload: str,
        timeout_ms: int,
    ) -> bool:
        """
        Submit the payload through the ORIGINAL storage form (real page context,
        method + hidden fields preserved), mirroring the lab's manual flow:
        post a comment carrying the payload, then view the post.
        """
        try:
            page.goto(action, wait_until="load", timeout=timeout_ms)
            form = page.locator("form").first
            if form.count() == 0:
                return False
            # Fill every fillable control so required fields never block the
            # submit; the parameter receives the payload, everything else a
            # plausible filler value.
            controls = form.locator(
                "input[type='text'], input[type='url'], input[type='email'], "
                "input[type='number'], input[type='password'], input:not([type]), textarea"
            )
            filled = False
            for i in range(controls.count()):
                control = controls.nth(i)
                name = control.get_attribute("name") or ""
                if name == parameter:
                    control.fill(payload)
                    filled = True
                elif name:
                    control.fill("xscan-probe")
            if not filled:
                return False
            form.locator("button[type='submit'], input[type='submit']").first.click(
                timeout=timeout_ms
            )
            page.wait_for_load_state("load", timeout=timeout_ms)
            return True
        except Exception:
            # Fallback: no matching form in the DOM — replay the POST directly.
            try:
                page.evaluate(
                    """([action, parameter, payload]) => {
                        const fd = new FormData();
                        fd.append(parameter, payload);
                        fetch(action, { method: 'POST', body: fd });
                    }""",
                    [action, parameter, payload],
                )
                page.wait_for_timeout(300)
                return True
            except Exception:
                return False

    @staticmethod
    def _click_url_triggers(page: Any) -> list[str]:
        """Click links whose href became a javascript: URI — the victim's action."""
        triggered: list[str] = []
        for selector in _CLICK_SELECTORS:
            if len(triggered) >= 3:
                break
            try:
                element = page.query_selector(selector)
                if element is None:
                    continue
                element.click(timeout=3000)
                triggered.append(selector)
                page.wait_for_timeout(250)
            except Exception:
                continue
        return triggered

    @staticmethod
    def _is_inert_script_payload(payload: str) -> bool:
        """<script> blocks inserted via innerHTML/insertAdjacentHTML never run."""
        low = payload.strip().lower()
        return low.startswith("<script") or ("<script" in low and "on" not in low)

    @staticmethod
    def _next_refined_candidate(
        candidate: dict[str, Any], failed_payload: str
    ) -> dict[str, Any] | None:
        """
        Next ranked candidate for the same sink, from the detector's synthesis
        ordering — the deterministic second attempt after an inert payload.
        """
        ranked = [p for p in (candidate.get("payloads") or []) if p and p != failed_payload]
        if not ranked:
            return None
        refined = dict(candidate)
        refined["best_payload"] = ranked[0]
        refined["payloads"] = ranked
        url = str(candidate.get("best_test_url") or candidate.get("url") or "")
        base = str(candidate.get("url") or url.split("#", 1)[0])
        # Rebuild the delivery URL when the payload is embedded in it.
        if failed_payload and failed_payload in url:
            refined["best_test_url"] = url.replace(failed_payload, ranked[0])
        elif base:
            refined["best_test_url"] = base
        return refined

    @staticmethod
    def _mark(candidate: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        """Attach validation status + browser evidence + model to the candidate."""
        updated = dict(candidate)
        confirmed = bool(result["confirmed"])
        updated.update({
            # Only real execution counts as validation: a payload that reached a
            # sink but never ran is evidence, not a finding (and never "safe").
            "validated":         confirmed,
            "sink_reached":      bool(result["dom_state"]),
            "confirmed":         confirmed,
            "validation_status": "confirmed" if confirmed else "inconclusive",
            "best_payload":      result["payload"],
            "best_test_url":     result["url"],
            "browser_evidence": {
                "dialog_fired": result["dialog_fired"],
                "dialogs":      result["dialogs"][:3],
                "dom_state":    result["dom_state"],
                "triggered":    result["triggered"],
                "note":         result["note"],
            },
        })
        if confirmed:
            updated["confidence"] = "high"
            # The finding must explain WHY the payload works: build the
            # vulnerability model from the candidate's own evidence and attach
            # the derivation + WHY lines for the report.
            try:
                from xscan.schemas.vuln_model import build_model_from_candidate

                model = build_model_from_candidate(updated)
                model.attacker_control = "confirmed"
                updated["vuln_model"] = model.model_dump(mode="json")
                updated["why"] = model.explain()
            except Exception:
                pass
        return updated
