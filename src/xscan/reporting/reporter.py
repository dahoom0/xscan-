"""
XScan Reporter
==============
Renders ScanResult to terminal (Rich), JSON, or basic HTML.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from xscan.core.models import Finding, ScanResult, Severity

_SEVERITY_COLOUR = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH:     "red",
    Severity.MEDIUM:   "yellow",
    Severity.LOW:      "cyan",
    Severity.INFO:     "dim",
}

_SEVERITY_ICON = {
    Severity.CRITICAL: "[CRIT]",
    Severity.HIGH:     "[HIGH]",
    Severity.MEDIUM:   "[MED] ",
    Severity.LOW:      "[LOW] ",
    Severity.INFO:     "[INFO]",
}


class Reporter:

    def __init__(self, console: Optional[Console] = None) -> None:
        self.con = console or Console(highlight=False)

    # ------------------------------------------------------------------
    # Terminal report
    # ------------------------------------------------------------------

    def print_terminal(self, result: ScanResult) -> None:
        self.con.print()

        # ── Header ──────────────────────────────────────────────────────
        self.con.print(Panel(
            f"[bold cyan]XScan Report[/bold cyan]\n\n"
            f"Target   {result.target}\n"
            f"Scan ID  {result.scan_id}\n"
            f"Started  {result.start_time[:19]}\n"
            f"Finished {result.end_time[:19] if result.end_time else '—'}\n"
            f"Profile  {result.profile}",
            expand=False,
        ))

        # ── Stats ────────────────────────────────────────────────────────
        self.con.print(
            f"URLs crawled:    [cyan]{len(result.urls_discovered)}[/cyan]    "
            f"Forms found:  [cyan]{len(result.forms_discovered)}[/cyan]    "
            f"Requests sent: [cyan]{result.requests_sent}[/cyan]    "
            f"Candidates:   [cyan]{len(result.candidates)}[/cyan]\n"
        )

        # ── Technologies ─────────────────────────────────────────────────
        if result.technologies:
            self.con.print(
                "[bold]Technologies detected:[/bold]  " +
                "  ".join(f"[yellow]{t}[/yellow]" for t in result.technologies) + "\n"
            )

        # ── Findings ─────────────────────────────────────────────────────
        if not result.findings:
            self.con.print("[green]No vulnerabilities found.[/green]\n")
        else:
            self.con.print(f"[bold]Findings ({len(result.findings)}):[/bold]\n")
            for finding in sorted(result.findings, key=lambda f: list(Severity).index(f.severity)):
                self._print_finding(finding)

        # ── Errors ───────────────────────────────────────────────────────
        if result.errors:
            self.con.print(f"\n[dim]Errors during scan ({len(result.errors)}):[/dim]")
            for e in result.errors[:5]:
                self.con.print(f"  [dim]{e}[/dim]")

    def _print_finding(self, f: Finding) -> None:
        col = _SEVERITY_COLOUR.get(f.severity, "white")
        icon = _SEVERITY_ICON.get(f.severity, "")
        self.con.print(Panel(
            f"[{col}]{icon} {f.id} — {f.type.value.upper()}[/{col}]\n\n"
            f"[bold]URL:[/bold]          {f.url}\n"
            f"[bold]Parameter:[/bold]    {f.parameter}\n"
            f"[bold]Payload:[/bold]      {f.payload}\n"
            f"[bold]Description:[/bold]  {f.description}\n"
            f"[bold]Evidence:[/bold]     {f.evidence[:120]}\n"
            f"[bold]Analysis:[/bold]     {f.llm_analysis}\n"
            f"[bold]Remediation:[/bold]  {f.remediation}",
            expand=False,
        ))

    # ------------------------------------------------------------------
    # JSON report
    # ------------------------------------------------------------------

    def to_json(self, result: ScanResult, path: Optional[str] = None) -> str:
        data = {
            "scan_id":    result.scan_id,
            "target":     result.target,
            "start_time": result.start_time,
            "end_time":   result.end_time,
            "profile":    result.profile,
            "stats": {
                "urls_crawled":   len(result.urls_discovered),
                "forms_found":    len(result.forms_discovered),
                "requests_sent":  result.requests_sent,
                "candidates":     len(result.candidates),
                "findings":       len(result.findings),
            },
            "technologies": result.technologies,
            "findings": [
                {
                    "id":          f.id,
                    "type":        f.type.value,
                    "severity":    f.severity.value,
                    "url":         f.url,
                    "parameter":   f.parameter,
                    "payload":     f.payload,
                    "evidence":    f.evidence,
                    "description": f.description,
                    "remediation": f.remediation,
                    "llm_analysis":f.llm_analysis,
                    "timestamp":   f.timestamp,
                }
                for f in result.findings
            ],
        }
        out = json.dumps(data, indent=2)
        if path:
            Path(path).write_text(out, encoding="utf-8")
        return out

    # ------------------------------------------------------------------
    # HTML report
    # ------------------------------------------------------------------

    def to_html(self, result: ScanResult, path: Optional[str] = None) -> str:
        rows = ""
        for f in result.findings:
            rows += f"""
            <tr class="sev-{f.severity.value}">
              <td>{f.id}</td>
              <td>{f.severity.value.upper()}</td>
              <td>{f.type.value}</td>
              <td>{f.url}</td>
              <td>{f.parameter}</td>
              <td><code>{f.payload}</code></td>
              <td>{f.description}</td>
              <td>{f.remediation}</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>XScan Report — {result.target}</title>
<style>
  body {{ font-family: sans-serif; margin: 2em; background: #0d1117; color: #e6edf3; }}
  h1 {{ color: #58a6ff; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 0.9em; }}
  th {{ background: #161b22; color: #8b949e; padding: 8px 12px; text-align: left; }}
  td {{ border-bottom: 1px solid #21262d; padding: 8px 12px; vertical-align: top; }}
  code {{ background: #161b22; padding: 2px 6px; border-radius: 4px; color: #e3b341; }}
  .sev-critical td:nth-child(2) {{ color: #ff7b72; font-weight: bold; }}
  .sev-high td:nth-child(2) {{ color: #f85149; }}
  .sev-medium td:nth-child(2) {{ color: #e3b341; }}
  .sev-low td:nth-child(2) {{ color: #79c0ff; }}
  .meta {{ color: #8b949e; margin-bottom: 2em; }}
</style>
</head>
<body>
<h1>XScan Security Report</h1>
<div class="meta">
  <strong>Target:</strong> {result.target} &nbsp;|&nbsp;
  <strong>Scan ID:</strong> {result.scan_id} &nbsp;|&nbsp;
  <strong>Date:</strong> {result.start_time[:19]} &nbsp;|&nbsp;
  <strong>Profile:</strong> {result.profile} &nbsp;|&nbsp;
  <strong>Findings:</strong> {len(result.findings)}
</div>
<table>
<thead>
  <tr>
    <th>ID</th><th>Severity</th><th>Type</th><th>URL</th>
    <th>Parameter</th><th>Payload</th><th>Description</th><th>Remediation</th>
  </tr>
</thead>
<tbody>
{rows if rows else '<tr><td colspan="8">No vulnerabilities found.</td></tr>'}
</tbody>
</table>
</body>
</html>"""

        if path:
            Path(path).write_text(html, encoding="utf-8")
        return html
