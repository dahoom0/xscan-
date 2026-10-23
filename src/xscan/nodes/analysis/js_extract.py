"""
js-extractor node — Phase C
============================
Extracts all JavaScript (inline + external) from crawled pages.
Stores raw JS content as artifacts; passes structured JsFile records
to downstream AST / taint nodes.

Inputs:  target_url (str), urls (list[str])
Outputs: js_files (list[dict])  — each entry is a JsFile record
         js_file_count (int)
         inline_count (int)

JsFile record fields:
  url       — source URL ("inline:{page_url}:{index}" for inline)
  source    — "inline" | "external"
  content   — raw JS text (capped at 200 KB per file)
  size      — byte length
"""
from __future__ import annotations

import re
import time
from typing import Any
from urllib.parse import urljoin

import httpx

from xscan.core.dag.node_registry import registry
from xscan.nodes.base import ExecutionContext, NodeBase
from xscan.nodes.emitter import NodeEmitter

_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36"
_MAX_JS_BYTES = 200_000   # 200 KB per file — protects memory
_MAX_FILES    = 50        # cap total files per scan


@registry.register("js-extractor")
class JsExtractorNode(NodeBase, NodeEmitter):

    def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
        t0 = self.emit_started(ctx)

        target_url: str      = ctx.get("target_url", "")
        urls:       list[str] = ctx.get("urls", [target_url]) if target_url else []
        
        # Also include post-submission pages from form-submitter
        submitted_pages: list[dict[str, Any]] = ctx.get("submitted_form_pages", [])
        additional_urls = [p["url"] for p in submitted_pages]
        
        # Combine all URLs to scan
        all_urls = urls + additional_urls
        
        max_files:  int       = int(ctx.config.get("max_files", _MAX_FILES))

        js_files:    list[dict[str, Any]] = []
        seen_urls:   set[str]   = set()
        inline_count = 0

        with httpx.Client(
            follow_redirects=True, timeout=12,
            verify=False, headers={"User-Agent": _UA},
        ) as client:

            for page_url in all_urls[:30]:  # limit pages scanned for JS
                try:
                    ctx.scope.assert_allowed(page_url, operation="http_request")
                    resp = client.get(page_url)
                except Exception:
                    continue

                if resp.status_code != 200:
                    continue

                html = resp.text

                # Inline scripts
                for i, script in enumerate(self._inline_scripts(html)):
                    if len(js_files) >= max_files:
                        break
                    if len(script.strip()) < 20:
                        continue
                    inline_count += 1
                    js_files.append({
                        "url":    f"inline:{page_url}:{i}",
                        "source": "inline",
                        "content": script[:_MAX_JS_BYTES],
                        "size":   len(script),
                        "page":   page_url,
                    })

                # External scripts
                for src in self._script_srcs(html, page_url):
                    if len(js_files) >= max_files:
                        break
                    if src in seen_urls:
                        continue
                    seen_urls.add(src)
                    try:
                        ctx.scope.assert_allowed(src, operation="http_request")
                        r = client.get(src)
                        if r.status_code == 200:
                            content = r.text[:_MAX_JS_BYTES]
                            js_files.append({
                                "url":    src,
                                "source": "external",
                                "content": content,
                                "size":   len(r.content),
                                "page":   page_url,
                            })
                    except Exception:
                        continue

                if len(js_files) >= max_files:
                    break

        ms = (time.monotonic() - t0) * 1000
        self.emit_completed(ctx, metrics={
            "js_files":    len(js_files),
            "inline":      inline_count,
            "external":    len(js_files) - inline_count,
            "pages_scanned": len(all_urls),
            "submitted_pages_processed": len(submitted_pages),
        }, duration_ms=ms)

        return {
            "js_files":      js_files,
            "js_file_count": len(js_files),
            "inline_count":  inline_count,
        }

    @staticmethod
    def _inline_scripts(html: str) -> list[str]:
        return re.findall(r"<script(?:[^>]*)>(.*?)</script>", html, re.DOTALL | re.I)

    @staticmethod
    def _script_srcs(html: str, base_url: str) -> list[str]:
        srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
        result = []
        for src in srcs:
            if src.startswith(("http://", "https://")):
                result.append(src)
            else:
                result.append(urljoin(base_url, src))
        return result
