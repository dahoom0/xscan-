"""
screenshot-capture node
=======================
Captures screenshots of live web hosts using gowitness.

Input:   live_urls (list[str]) from http-probe
Outputs: screenshots (dict[str, dict]) — per-URL screenshot metadata
         screenshot_count (int) — number of successful captures
         screenshot_observations (list[dict]) — gowitness execution metadata
"""
from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Any

from xscan.core.dag.node_registry import registry
from xscan.nodes.base import ExecutionContext, NodeBase
from xscan.nodes.emitter import NodeEmitter
from xscan.runtime.resolver import get_runtime
from xscan.schemas.recon import ReconToolStatus


@registry.register("screenshot-capture")
class ScreenshotCaptureNode(NodeBase, NodeEmitter):
    node_type = "screenshot-capture"

    def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
        t0 = self.emit_started(ctx)

        # Configuration
        screenshot_enabled: bool = ctx.config.get("screenshot_enabled", True)
        timeout: int = int(ctx.config.get("screenshot_timeout", 15))
        max_hosts: int = int(ctx.config.get("screenshot_max_hosts", 20))

        # If disabled, return empty
        if not screenshot_enabled:
            self.emit_progress(ctx, "Screenshots disabled in config")
            ms = (time.monotonic() - t0) * 1000
            self.emit_completed(ctx, metrics={
                "screenshot_count": 0,
            }, duration_ms=ms)
            return {
                "screenshots": {},
                "screenshot_count": 0,
                "screenshot_observations": [],
            }

        live_urls: list[str] = ctx.get("live_urls", [])
        if not live_urls:
            self.emit_progress(ctx, "No live URLs to screenshot")
            ms = (time.monotonic() - t0) * 1000
            self.emit_completed(ctx, metrics={
                "screenshot_count": 0,
            }, duration_ms=ms)
            return {
                "screenshots": {},
                "screenshot_count": 0,
                "screenshot_observations": [],
            }

        runtime = get_runtime()

        # Check if gowitness is available
        gowitness_path = runtime.which("gowitness")
        if not gowitness_path:
            self.emit_warning(ctx, "gowitness not found; skipping screenshots")
            ms = (time.monotonic() - t0) * 1000
            self.emit_completed(ctx, metrics={
                "screenshot_count": 0,
            }, duration_ms=ms)
            return {
                "screenshots": {},
                "screenshot_count": 0,
                "screenshot_observations": [
                    {
                        "tool": "gowitness",
                        "status": ReconToolStatus.TOOL_UNAVAILABLE.value,
                        "observation": "gowitness binary not found",
                    }
                ],
            }

        # Create screenshot output directory
        output_dir = Path(ctx.config.get("output_dir", ".")) / "screenshots"
        output_dir.mkdir(parents=True, exist_ok=True)

        # Limit URLs for performance
        urls_to_capture = live_urls[:max_hosts]
        self.emit_progress(ctx, f"Capturing {len(urls_to_capture)} screenshots...")

        screenshots: dict[str, dict] = {}
        capture_count = 0

        for url in urls_to_capture:
            try:
                # Scope check
                ctx.scope.assert_allowed(url, operation="screenshot")

                # Generate output filename based on URL hash (for reference, though gowitness names its own files)
                _url_hash = hashlib.md5(url.encode()).hexdigest()[:8]

                # Run gowitness
                # gowitness scan -u <url> -o <output_dir> --timeout <seconds>
                cmd = [
                    gowitness_path,
                    "scan",
                    "-u", url,
                    "-o", str(output_dir),
                    "--timeout", str(timeout),
                ]

                result = runtime.run(cmd, timeout=timeout + 5)

                if result.returncode == 0:
                    # Check if screenshot file was created
                    # gowitness creates files with naming pattern: <hostname>-<timestamp>.png
                    # For simplicity, we check if any new PNG was created
                    existing_pngs = list(output_dir.glob("*.png"))
                    if existing_pngs:
                        # Use the most recent PNG
                        latest_png = max(existing_pngs, key=lambda p: p.stat().st_mtime)
                        rel_path = latest_png.relative_to(ctx.config.get("output_dir", "."))
                        screenshots[url] = {
                            "url": url,
                            "screenshot_path": str(rel_path),
                            "status": "captured",
                            "timestamp": time.time(),
                            "file_size": latest_png.stat().st_size,
                        }
                        capture_count += 1
                        self.emit_progress(ctx, f"  ✓ {url} → {latest_png.name}")
                    else:
                        screenshots[url] = {
                            "url": url,
                            "status": "error",
                            "error_message": "Screenshot file not created",
                            "timestamp": time.time(),
                        }
                        self.emit_progress(ctx, f"  ✗ {url} (file not created)")
                else:
                    screenshots[url] = {
                        "url": url,
                        "status": "error",
                        "error_message": result.stderr[:200],
                        "timestamp": time.time(),
                        "exit_code": result.returncode,
                    }
                    self.emit_progress(ctx, f"  ✗ {url} (exit {result.returncode})")

            except TimeoutError:
                screenshots[url] = {
                    "url": url,
                    "status": "timeout",
                    "timestamp": time.time(),
                }
                self.emit_progress(ctx, f"  ⏱ {url} (timeout)")

            except Exception as exc:
                screenshots[url] = {
                    "url": url,
                    "status": "error",
                    "error_message": str(exc)[:200],
                    "timestamp": time.time(),
                }
                self.emit_progress(ctx, f"  ✗ {url} ({str(exc)[:50]})")

        # Build gowitness observation for metadata
        gowitness_obs = {
            "tool": "gowitness",
            "status": ReconToolStatus.COMPLETED_WITH_RESULTS.value if capture_count > 0 else ReconToolStatus.COMPLETED_NO_RESULTS.value,
            "observation": f"gowitness: {capture_count}/{len(urls_to_capture)} screenshots captured",
            "results": [url for url, data in screenshots.items() if data.get("status") == "captured"],
        }

        ms = (time.monotonic() - t0) * 1000
        self.emit_completed(ctx, metrics={
            "screenshot_count": capture_count,
            "screenshots_attempted": len(urls_to_capture),
        }, duration_ms=ms)

        return {
            "screenshots": screenshots,
            "screenshot_count": capture_count,
            "screenshot_observations": [gowitness_obs],
        }
