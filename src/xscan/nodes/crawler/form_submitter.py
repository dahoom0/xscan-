"""
Interactive Form Submitter Node
=================================
Submits discovered forms with benign test values and collects post-submission
response pages for downstream analysis.

This is critical for catching dynamically-loaded scripts that only appear
after form submission (e.g., searchResults.js loading after a search form submit).

Inputs:
  - forms (list[dict]): Forms discovered by crawler
  - target_url (str): Base target URL
  - urls (list[str]): Already-discovered pages

Outputs:
  - submitted_form_pages (list[dict]): Post-submission response pages
  - submission_count (int): Number of forms submitted
  - submission_errors (list[dict]): Failed submissions
"""
from __future__ import annotations

import time
from typing import Any

import httpx
from bs4 import BeautifulSoup

from xscan.core.dag.node_registry import registry
from xscan.nodes.base import ExecutionContext, NodeBase
from xscan.nodes.emitter import NodeEmitter

_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36"
)

# Benign test values for form inputs — safe to submit without triggering security alerts
_TEST_VALUES = {
    "text":     "xscTest123",
    "email":    "test@example.com",
    "password": "xscTest123",
    "search":   "xscTest",
    "q":        "xscTest",
    "textarea": "xscTest123",
    "select":   "option1",
    "number":   "1",
    "date":     "2024-01-01",
    "tel":      "1234567890",
}


@registry.register("form-submitter")
class FormSubmitterNode(NodeBase):
    """Submit discovered forms with benign test values and collect response pages."""

    def __init__(self) -> None:
        """Initialize the form submitter."""
        self._emitter = NodeEmitter()
        self._submitted_urls: set[str] = set()

    def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
        """
        Submit forms with benign test values and collect response pages.

        Args:
            ctx: Execution context containing forms, target_url, urls

        Returns:
            Dictionary with submitted_form_pages and submission statistics
        """
        forms = ctx.get("forms", [])
        target_url = ctx.get("target_url", "")
        already_discovered = set(ctx.get("urls", []))

        if not forms or not target_url:
            return {
                "submitted_form_pages": [],
                "submission_count": 0,
                "submission_errors": [],
                "new_pages_found": 0,
            }

        t0 = self._emitter.emit_started(ctx)
        submitted_pages: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []

        with httpx.Client(
            follow_redirects=True,
            timeout=ctx.config.get("http_timeout", 12),
            verify=False,
            headers={"User-Agent": _UA},
        ) as client:

            for form_idx, form in enumerate(forms[:20]):  # Limit submissions to avoid excessive traffic
                try:
                    ctx.scope.assert_allowed(
                        form.get("action", target_url),
                        operation="http_request",
                    )
                except Exception:
                    errors.append({
                        "form_index": form_idx,
                        "action": form.get("action", ""),
                        "error": "scope_check_failed",
                    })
                    continue

                result = self._submit_form(
                    client, form, ctx, target_url
                )

                if result["success"]:
                    # Record the submission action URL
                    if result["final_url"] not in self._submitted_urls:
                        self._submitted_urls.add(result["final_url"])

                        # If this is a new page, collect it
                        if result["final_url"] not in already_discovered:
                            submitted_pages.append({
                                "url": result["final_url"],
                                "method": form.get("method", "GET"),
                                "source_form_action": form.get("action", ""),
                                "response_status": result["status_code"],
                                "response_size": len(result["response_body"]),
                                "content_type": result["content_type"],
                                "has_scripts": result["has_scripts"],
                                "script_count": result["script_count"],
                            })

                    self._emitter.emit_progress(
                        ctx,
                        f"Form {form_idx + 1}/{len(forms)}: "
                        f"submitted to {form.get('action', target_url)} → "
                        f"{result['status_code']} "
                        f"({result['script_count']} inline scripts found)",
                    )
                else:
                    errors.append({
                        "form_index": form_idx,
                        "action": form.get("action", ""),
                        "error": result.get("error", "unknown"),
                    })

        ms = (time.monotonic() - t0) * 1000
        self._emitter.emit_completed(
            ctx,
            metrics={
                "forms_submitted": len(forms),
                "responses_collected": len(submitted_pages),
                "new_pages_found": len(submitted_pages),
                "submission_errors": len(errors),
            },
            duration_ms=ms,
        )

        return {
            "submitted_form_pages": submitted_pages,
            "submission_count": len(forms),
            "submission_errors": errors,
            "new_pages_found": len(submitted_pages),
        }

    def _submit_form(
        self,
        client: httpx.Client,
        form: dict[str, Any],
        ctx: ExecutionContext,
        target_url: str,
    ) -> dict[str, Any]:
        """
        Submit a single form and return the response.

        Args:
            client: HTTP client
            form: Form metadata (action, method, inputs)
            ctx: Execution context
            target_url: Base target URL

        Returns:
            Dictionary with success flag and response data
        """
        action = form.get("action", "") or target_url
        method = (form.get("method", "GET") or "GET").upper()
        inputs = form.get("inputs", [])

        # Build form data
        form_data: dict[str, Any] = {}
        for inp in inputs:
            name = inp.get("name", "")
            input_type = inp.get("type", "text").lower()
            if not name:
                continue

            # Use test value based on input type
            test_value = _TEST_VALUES.get(input_type, _TEST_VALUES.get("text", "xscTest"))
            form_data[name] = test_value

        try:
            # Submit the form
            if method == "POST":
                resp = client.post(
                    action,
                    data=form_data,
                    timeout=12,
                )
            else:  # GET
                resp = client.get(
                    action,
                    params=form_data,
                    timeout=12,
                )

            if resp.status_code != 200:
                return {
                    "success": False,
                    "error": f"HTTP {resp.status_code}",
                }

            # Check content type
            content_type = resp.headers.get("content-type", "")
            if "text/html" not in content_type:
                return {
                    "success": False,
                    "error": "non_html_response",
                }

            # Parse response and count inline scripts
            html = resp.text
            soup = BeautifulSoup(html, "html.parser")
            inline_scripts = soup.find_all("script")
            has_inline = any(s.string for s in inline_scripts if not s.get("src"))
            inline_count = sum(1 for s in inline_scripts if not s.get("src"))

            return {
                "success": True,
                "final_url": str(resp.url),
                "status_code": resp.status_code,
                "response_body": html,
                "content_type": content_type,
                "has_scripts": has_inline or len(inline_scripts) > 0,
                "script_count": inline_count,
            }

        except httpx.TimeoutException:
            return {
                "success": False,
                "error": "timeout",
            }
        except httpx.RequestError as exc:
            return {
                "success": False,
                "error": f"request_error: {str(exc)[:100]}",
            }
        except Exception as exc:
            return {
                "success": False,
                "error": f"unexpected: {str(exc)[:100]}",
            }
