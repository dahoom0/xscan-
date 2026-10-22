"""
XScan Scan Engine
=================
Orchestrates the full scan pipeline:

  Stage 1  Recon     — probe target, fingerprint technologies
  Stage 2  Crawl     — discover URLs and forms
  Stage 3  Probe     — inject XSS canary/payloads into params and forms
  Stage 4  Analyse   — LLM specialist reviews each candidate
  Stage 5  Report    — produce terminal / JSON / HTML output

All progress is reported via a callback so the CLI can display it
with a Rich Live panel.
"""
from __future__ import annotations

import datetime
import uuid
from pathlib import Path
from typing import Callable, Optional

from xscan.core.models import ScanResult
from xscan.http.client import ScanClient
from xscan.recon.fingerprint import fingerprint
from xscan.crawler.spider import Spider
from xscan.candidates.xss_prober import XssProber
from xscan.llm.analyst import LLMAnalyst
from xscan.llm.ollama import OllamaClient
from xscan.reporting.reporter import Reporter

# Max pages per profile
_PROFILE_PAGES = {"fast": 20, "balanced": 60, "deep": 150}
_PROFILE_DEPTH = {"fast": 2,  "balanced": 3,  "deep": 5}


class ScanEngine:
    """
    Run a full or partial scan against a target.

    Usage::

        engine = ScanEngine(
            target="https://example.com",
            profile="balanced",
            no_llm=False,
            progress_cb=print,
        )
        result = engine.run()
    """

    def __init__(
        self,
        target: str,
        profile: str = "balanced",
        no_llm: bool = False,
        output_path: Optional[str] = None,
        output_format: str = "terminal",
        progress_cb: Optional[Callable[[str, str], None]] = None,
    ) -> None:
        self.target = target.rstrip("/")
        self.profile = profile
        self.no_llm = no_llm
        self.output_path = output_path
        self.output_format = output_format
        self._cb = progress_cb or (lambda stage, msg: None)
        self._scan_id = str(uuid.uuid4())[:8].upper()

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def run(self) -> ScanResult:
        result = ScanResult(
            target=self.target,
            scan_id=self._scan_id,
            start_time=datetime.datetime.now().isoformat(),
            profile=self.profile,
        )

        with ScanClient(base_url=self.target) as client:

            # ── Stage 1: Recon ──────────────────────────────────────────
            self._cb("recon", f"Probing target: {self.target}")
            resp = client.get(self.target)
            result.requests_sent += 1

            if resp.status_code == 0:
                result.errors.append(f"Could not reach target: {self.target}")
                result.end_time = datetime.datetime.now().isoformat()
                return result

            self._cb("recon", f"  HTTP {resp.status_code}  ({resp.elapsed_ms:.0f}ms)")
            fp = fingerprint(resp)
            result.technologies = fp["technologies"]

            if fp["technologies"]:
                self._cb("recon", f"  Technologies: {', '.join(fp['technologies'])}")
            if fp["missing_security_headers"]:
                self._cb("recon",
                    f"  Missing security headers: "
                    f"{', '.join(fp['missing_security_headers'][:4])}"
                )

            # ── Stage 2: Crawl ──────────────────────────────────────────
            max_pages = _PROFILE_PAGES.get(self.profile, 60)
            max_depth = _PROFILE_DEPTH.get(self.profile, 3)
            self._cb("crawl", f"Crawling (max {max_pages} pages, depth {max_depth})...")

            spider = Spider(
                base_url=self.target,
                client=client,
                max_pages=max_pages,
                max_depth=max_depth,
            )
            try:
                urls, forms = spider.crawl(
                    progress_cb=lambda msg: self._cb("crawl", msg)
                )
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                result.errors.append(f"Crawl error: {exc}")
                urls, forms = [self.target], []

            result.urls_discovered = urls
            result.forms_discovered = forms
            result.requests_sent += len(urls)
            self._cb("crawl",
                f"  Found {len(urls)} URLs, {len(forms)} forms"
            )

            # ── Stage 3: XSS Probing ────────────────────────────────────
            # Only probe URLs that have query parameters
            urls_with_params = [u for u in urls if "?" in u]
            self._cb("probe",
                f"Probing {len(urls_with_params)} parameterised URLs "
                f"+ {len(forms)} forms for XSS..."
            )

            prober = XssProber(client=client, profile=self.profile)
            try:
                candidates = prober.probe_urls(
                    urls_with_params,
                    progress_cb=lambda msg: self._cb("probe", msg),
                )
                candidates += prober.probe_forms(
                    forms,
                    progress_cb=lambda msg: self._cb("probe", msg),
                )
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                result.errors.append(f"Probe error: {exc}")
                candidates = []

            result.candidates = candidates
            result.requests_sent += prober.requests_sent
            self._cb("probe",
                f"  {len(candidates)} candidate(s) found "
                f"({prober.requests_sent} requests)"
            )

            # ── Stage 4: LLM Analysis ───────────────────────────────────
            if candidates and not self.no_llm:
                model = self._pick_model()
                self._cb("analyse",
                    f"Analysing {len(candidates)} candidate(s) with {model}..."
                )
                analyst = LLMAnalyst(model=model)
                try:
                    findings = analyst.analyse_batch(
                        candidates,
                        progress_cb=lambda msg: self._cb("analyse", msg),
                    )
                except KeyboardInterrupt:
                    raise
                except Exception as exc:
                    result.errors.append(f"LLM analysis error: {exc}")
                    # Fall back to raw candidates as findings
                    findings = [analyst._auto_finding(c) for c in candidates]
                result.findings = findings
            elif candidates and self.no_llm:
                # Promote all candidates to findings without LLM
                from xscan.llm.analyst import LLMAnalyst as _A
                _analyst = _A()
                result.findings = [_analyst._auto_finding(c) for c in candidates]
            else:
                result.findings = []

            self._cb("report",
                f"  {len(result.findings)} finding(s)"
            )

        result.end_time = datetime.datetime.now().isoformat()
        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _pick_model(self) -> str:
        """Return the configured model, falling back to first available."""
        # Check config file
        config = Path.home() / ".xscan" / "config.toml"
        if config.exists():
            text = config.read_text(encoding="utf-8")
            import re
            m = re.search(r'^\s*model\s*=\s*"([^"]+)"', text, re.MULTILINE)
            if m:
                return m.group(1)
        # Ask Ollama
        try:
            client = OllamaClient()
            status = client.status()
            if status.reachable and status.models:
                # Prefer loaded models
                running = [m for m in status.models if m.running]
                if running:
                    return running[0].name
                return status.models[0].name
        except Exception:
            pass
        return "qwen3:14b"
