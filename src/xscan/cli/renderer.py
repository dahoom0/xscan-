"""
XScan Terminal Renderer
=======================
Renders structured NodeEvents to the terminal during a live scan.

Three verbosity levels:
  normal   — summaries and state transitions only (default)
  verbose  — per-node details and metrics
  debug    — full internal state, timings, model calls

Two output modes:
  --quiet  — only final summary line
  --json   — machine-readable final JSON to stdout

Architecture:
  NodeEvent → EventBus → TerminalRenderer.handle_event() → Rich console
  (never accumulates full log history in RAM — events are fire-and-forget)
"""
from __future__ import annotations

import time
from datetime import datetime, UTC
from typing import Any

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from xscan.core.events import NodeEvent, NodeEventType, ScanSummary
from xscan.schemas.events import DomainEvent


_NODE_ICON = {
    NodeEventType.STARTED:   "[dim]RUN [/dim]",
    NodeEventType.PROGRESS:  "[dim]    [/dim]",
    NodeEventType.WARNING:   "[yellow]WARN[/yellow]",
    NodeEventType.COMPLETED: "[green]DONE[/green]",
    NodeEventType.FAILED:    "[red]FAIL[/red]",
    NodeEventType.SKIPPED:   "[dim]SKIP[/dim]",
}

_NODE_LABEL_WIDTH = 22


class TerminalRenderer:
    """
    Subscribes to the EventBus and renders scan events to a Rich console.

    Usage::

        renderer = TerminalRenderer(console, verbose=False)
        renderer.start(scan_id, target_url, profile)
        # ... scan runs, events flow in via EventBus ...
        renderer.finish(summary)
    """

    def __init__(
        self,
        console: Console,
        verbose: bool = False,
        debug: bool = False,
        quiet: bool = False,
        json_mode: bool = False,
    ) -> None:
        self.con = console
        self.verbose = verbose
        self.debug = debug
        self.quiet = quiet
        self.json_mode = json_mode
        self._scan_start = time.monotonic()
        self._node_starts: dict[str, float] = {}
        # Track per-node status for the workflow progress table
        self._node_status: dict[str, str] = {}
        self._activity: list[str] = []   # last N activity lines (capped)
        self._MAX_ACTIVITY = 8

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self, scan_id: str, target_url: str, profile: str, workflow_name: str) -> None:
        self._scan_start = time.monotonic()
        self._profile = profile
        if self.quiet or self.json_mode:
            return
        self.con.print()
        # Only show profile when explicitly non-default, and hide workflow name
        # (it's an internal detail derived from profile)
        profile_tag = f"  [dim]{profile}[/dim]" if profile != "balanced" else ""
        self.con.print(
            f"[bold cyan]XScan[/bold cyan]"
            f"  [dim]Scan:[/dim] [yellow]{scan_id}[/yellow]"
            f"{profile_tag}"
        )
        self.con.print(f"[dim]Target:[/dim] {target_url}\n")

    def finish(self, summary: ScanSummary) -> None:
        if self.json_mode:
            import json
            self.con.print(json.dumps(summary.model_dump(), indent=2))
            return

        if self.quiet:
            status = "completed" if summary.status == "completed" else "failed"
            self.con.print(
                f"{summary.confirmed_findings} confirmed findings  "
                f"[dim]({summary.candidates} candidates  "
                f"{summary.duration_s:.1f}s)[/dim]"
            )
            return

        self.con.print()
        self.con.print("-" * 48)
        status_label = (
            "[green]SCAN COMPLETE[/green]"
            if summary.status == "completed"
            else "[red]SCAN FAILED[/red]"
        )
        self.con.print(f"  {status_label}\n")

        rows = [
            ("URLs crawled",        str(summary.urls_crawled)),
            ("Inputs analyzed",     str(summary.inputs_analyzed)),
            ("Reflections",         str(summary.reflections)),
            ("Candidates",          str(summary.candidates)),
            ("Confirmed findings",  str(summary.confirmed_findings)),
            ("Duration",            f"{summary.duration_s:.1f}s"),
            ("Scan ID",             summary.scan_id),
        ]
        for label, value in rows:
            self.con.print(f"  [dim]{label:<24}[/dim] {value}")

        if summary.technologies:
            self.con.print(
                f"\n  [dim]{'Technologies':<24}[/dim] "
                + "  ".join(f"[yellow]{t}[/yellow]" for t in summary.technologies)
            )

        self.con.print("-" * 48)
        self.con.print()

    # ------------------------------------------------------------------
    # Event handling
    # ------------------------------------------------------------------

    def handle_domain_event(self, event: DomainEvent) -> None:
        """Called by the EventBus for every node event during a scan."""
        payload = event.payload
        try:
            node_event = NodeEvent(**payload)
        except Exception:
            return
        self._handle_node_event(node_event)

    def _handle_node_event(self, ev: NodeEvent) -> None:
        if self.quiet or self.json_mode:
            return

        ts = datetime.now(UTC).strftime("%H:%M:%S")
        node_id = ev.node_id
        etype = NodeEventType(ev.event_type) if isinstance(ev.event_type, str) else ev.event_type
        icon = _NODE_ICON.get(etype, "    ")

        # Track timing
        if etype == NodeEventType.STARTED:
            self._node_starts[node_id] = time.monotonic()
            self._node_status[node_id] = "running"
            if not self.debug:  # debug shows full detail below
                self.con.print(
                    f"  {ts}  {icon}  [cyan]{node_id:<{_NODE_LABEL_WIDTH}}[/cyan]"
                )
            return

        if etype == NodeEventType.COMPLETED:
            self._node_status[node_id] = "done"
            elapsed = ""
            if node_id in self._node_starts:
                ms = (time.monotonic() - self._node_starts[node_id]) * 1000
                elapsed = f"  [dim]{ms / 1000:.1f}s[/dim]"

            # Build summary line from metrics
            summary = self._metrics_summary(ev.metrics)
            self.con.print(
                f"  {ts}  {icon}  [cyan]{node_id:<{_NODE_LABEL_WIDTH}}[/cyan]"
                f"  {summary}{elapsed}"
            )

            # Verbose: show per-metric details
            if self.verbose and ev.metrics:
                for k, v in ev.metrics.items():
                    self.con.print(f"  {'':>{_NODE_LABEL_WIDTH + 16}}  [dim]{k}: {v}[/dim]")

            return

        if etype == NodeEventType.FAILED:
            self._node_status[node_id] = "failed"
            self.con.print(
                f"  {ts}  {icon}  [cyan]{node_id:<{_NODE_LABEL_WIDTH}}[/cyan]"
                f"  [red]{ev.message or 'failed'}[/red]"
            )
            return

        if etype == NodeEventType.SKIPPED:
            self._node_status[node_id] = "skipped"
            if self.verbose or self.debug:
                self.con.print(
                    f"  {ts}  {icon}  [dim]{node_id:<{_NODE_LABEL_WIDTH}}[/dim]"
                    f"  [dim]skipped[/dim]"
                )
            return

        if etype == NodeEventType.PROGRESS:
            if self.verbose or self.debug:
                self.con.print(
                    f"  {ts}  {icon}  [dim]{node_id:<{_NODE_LABEL_WIDTH}}[/dim]"
                    f"  {ev.message}"
                )
            return

        if etype == NodeEventType.WARNING:
            self.con.print(
                f"  {ts}  {icon}  [cyan]{node_id:<{_NODE_LABEL_WIDTH}}[/cyan]"
                f"  [yellow]{ev.message}[/yellow]"
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _metrics_summary(metrics: dict[str, Any]) -> str:
        """Produce a compact human-readable summary from metrics dict."""
        if not metrics:
            return ""
        # Priority order for common metric keys
        priority = [
            "urls", "urls_discovered", "forms", "forms_found",
            "inputs_analyzed", "reflections", "candidates",
            "likely_vulnerable", "confirmed", "technologies_count",
            "http_status",
        ]
        parts: list[str] = []
        seen: set[str] = set()

        for key in priority:
            if key in metrics:
                parts.append(f"{metrics[key]} {key.replace('_', ' ')}")
                seen.add(key)

        # Any remaining keys
        for k, v in metrics.items():
            if k not in seen and not k.startswith("_"):
                parts.append(f"{v} {k.replace('_', ' ')}")

        return "  ".join(parts[:4])   # cap at 4 items to keep lines short
