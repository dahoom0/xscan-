"""
Multi-Target Scan Support
==========================
Helper functions for scanning multiple targets from files or stdin.

This module extends the CLI to support:
  - xscan xss --urls targets.txt
  - cat urls.txt | xscan xss --stdin
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Optional

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from xscan.core.dag.engine import DAGEngine
from xscan.core.dag.checkpoint import MemoryCheckpoint
from xscan.core.scope.engine import ScopeEngine
from xscan.core.scope.policy import PolicyEngine
from xscan.core.events import ScanSummary
from xscan.schemas.scan import Target
from xscan.workflows.loader import WorkflowLoader
from xscan.events import bus
from xscan.schemas.events import EventType
from xscan.targets import TargetLoader, TargetSet, TargetQueue, TargetStatus


def run_multi_target_scan(
    *,
    scan_id: str,
    urls_file: Optional[str],
    use_stdin: bool,
    profile: str,
    wf_name: str,
    verbose: bool,
    debug: bool,
    quiet: bool,
    json_out: bool,
    no_llm: bool,
    spa: bool,
    output: Optional[str],
    console: Console,
) -> None:
    """
    Run an XSS scan against multiple targets.

    This function handles the multi-target workflow:
      1. Load targets from file or stdin
      2. Normalize and deduplicate
      3. Validate through scope/policy
      4. Execute DAG for each target
      5. Aggregate results
    """
    from xscan.cli.renderer import TerminalRenderer

    # Load targets
    loader = TargetLoader(
        progress_cb=lambda msg: (
            console.print(f"[dim]{msg}[/dim]") if not quiet and not json_out else None
        )
    )

    try:
        if use_stdin:
            target_set = loader.load_from_stdin(assessment_id=scan_id)
        elif urls_file:
            target_set = loader.load_from_file(urls_file, assessment_id=scan_id)
        else:
            console.print("[red]Error:[/red] No target source specified")
            raise SystemExit(1)
    except Exception as exc:
        console.print(f"[red]Error loading targets:[/red] {exc}")
        raise SystemExit(1)

    # Check if we have any valid targets
    valid_targets = target_set.valid_targets
    blocked_targets = target_set.blocked_targets

    if blocked_targets and not quiet and not json_out:
        console.print(
            f"[yellow]Blocked {len(blocked_targets)} targets (out of scope)[/yellow]"
        )

    if not valid_targets:
        console.print("[red]No valid targets to scan.[/red]")
        raise SystemExit(1)

    if not quiet and not json_out:
        console.print(
            f"[cyan]Scanning {len(valid_targets)} target(s)[/cyan] "
            f"(profile: {profile})"
        )

    # Create execution queue
    queue = loader.to_queue(target_set)

    # Load workflow once (reused for all targets)
    wf_loader = WorkflowLoader()
    try:
        workflow = wf_loader.load(wf_name)
    except Exception as exc:
        console.print(f"[red]Error loading workflow:[/red] {exc}")
        raise SystemExit(1)

    # Track results across all targets
    t0 = time.monotonic()
    all_candidates: list[dict[str, Any]] = []
    all_findings: list[dict[str, Any]] = []
    target_summaries: list[dict[str, Any]] = []

    # Progress display
    if not quiet and not json_out:
        _run_with_progress(
            queue=queue,
            workflow=workflow,
            scan_id=scan_id,
            profile=profile,
            no_llm=no_llm,
            spa=spa,
            verbose=verbose,
            console=console,
            all_candidates=all_candidates,
            all_findings=all_findings,
            target_summaries=target_summaries,
        )
    else:
        # Quiet mode - no progress display
        _run_quiet(
            queue=queue,
            workflow=workflow,
            scan_id=scan_id,
            profile=profile,
            no_llm=no_llm,
            spa=spa,
            all_candidates=all_candidates,
            all_findings=all_findings,
            target_summaries=target_summaries,
        )

    duration = time.monotonic() - t0

    # Print summary
    _print_multi_summary(
        console=console,
        scan_id=scan_id,
        queue=queue,
        duration=duration,
        all_candidates=all_candidates,
        all_findings=all_findings,
        quiet=quiet,
        json_out=json_out,
        output=output,
        target_summaries=target_summaries,
    )


def _run_with_progress(
    *,
    queue: TargetQueue,
    workflow: Any,
    scan_id: str,
    profile: str,
    no_llm: bool,
    spa: bool,
    verbose: bool,
    console: Console,
    all_candidates: list,
    all_findings: list,
    target_summaries: list,
) -> None:
    """Run scans with rich progress display."""

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        main_task = progress.add_task(
            f"[cyan]Scanning targets...",
            total=queue.total_targets,
        )

        while not queue.is_complete():
            entry = queue.get_next()
            if entry is None:
                break

            target = entry.target
            queue.mark_running(target.target_id)

            progress.update(
                main_task,
                description=f"[cyan]Scanning: {target.hostname[:40]}",
            )

            # Run single target scan
            result = _scan_single_target(
                target=target,
                workflow=workflow,
                scan_id=scan_id,
                profile=profile,
                no_llm=no_llm,
                spa=spa,
            )

            if result["success"]:
                queue.mark_completed(target.target_id, run_id=result.get("run_id", ""))
                all_candidates.extend(result.get("candidates", []))
                all_findings.extend(result.get("findings", []))
                target_summaries.append({
                    "target_id": target.target_id,
                    "url": target.normalized_url,
                    "status": "completed",
                    "candidates": len(result.get("candidates", [])),
                    "findings": len(result.get("findings", [])),
                })
            else:
                queue.mark_failed(target.target_id, error=result.get("error", "Unknown error"))
                target_summaries.append({
                    "target_id": target.target_id,
                    "url": target.normalized_url,
                    "status": "failed",
                    "error": result.get("error", ""),
                })

            progress.advance(main_task)

            # Print verbose output per target
            if verbose and result.get("candidates"):
                for cand in result["candidates"]:
                    param = cand.get("parameter", "?")
                    url = cand.get("url", target.normalized_url)[:50]
                    console.print(f"  [dim]Found candidate in '{param}' at {url}...[/dim]")


def _run_quiet(
    *,
    queue: TargetQueue,
    workflow: Any,
    scan_id: str,
    profile: str,
    no_llm: bool,
    spa: bool,
    all_candidates: list,
    all_findings: list,
    target_summaries: list,
) -> None:
    """Run scans without progress display."""

    while not queue.is_complete():
        entry = queue.get_next()
        if entry is None:
            break

        target = entry.target
        queue.mark_running(target.target_id)

        result = _scan_single_target(
            target=target,
            workflow=workflow,
            scan_id=scan_id,
            profile=profile,
            no_llm=no_llm,
            spa=spa,
        )

        if result["success"]:
            queue.mark_completed(target.target_id, run_id=result.get("run_id", ""))
            all_candidates.extend(result.get("candidates", []))
            all_findings.extend(result.get("findings", []))
            target_summaries.append({
                "target_id": target.target_id,
                "url": target.normalized_url,
                "status": "completed",
                "candidates": len(result.get("candidates", [])),
                "findings": len(result.get("findings", [])),
            })
        else:
            queue.mark_failed(target.target_id, error=result.get("error", ""))
            target_summaries.append({
                "target_id": target.target_id,
                "url": target.normalized_url,
                "status": "failed",
                "error": result.get("error", ""),
            })


def _scan_single_target(
    *,
    target: Any,
    workflow: Any,
    scan_id: str,
    profile: str,
    no_llm: bool,
    spa: bool,
) -> dict[str, Any]:
    """
    Execute a scan for a single target.

    Returns a dict with:
      - success: bool
      - candidates: list
      - findings: list
      - run_id: str
      - error: str (if failed)
    """
    import uuid

    try:
        # Create per-target run ID
        run_id = uuid.uuid4().hex[:8].upper()

        # Build scope for this target
        scope = ScopeEngine.from_target(scan_id, target.normalized_url)
        policy = PolicyEngine()
        cp = MemoryCheckpoint()

        engine = DAGEngine(
            workflow=workflow,
            scope=scope,
            policy=policy,
            checkpoint=cp,
            no_llm=no_llm,
        )

        run = engine.execute(
            scan_id=scan_id,
            inputs={
                "target_url": target.normalized_url,
                "scan_id": scan_id,
                "profile": profile,
                "spa_mode": True if spa else None,
            },
        )

        # Extract results from run
        all_outputs: dict = {}
        for node_id, nr in run.node_results.items():
            if nr.output:
                all_outputs.update(nr.output)

        # Mirror the single-target summary: prefer the newest candidate store
        # (fusion merges reflected + DOM + stored + tool observations).
        candidates = (
            all_outputs.get("fused_candidates")
            or all_outputs.get("xss_candidates")
            or all_outputs.get("triaged_candidates")
            or all_outputs.get("candidates")
            or []
        )
        if not isinstance(candidates, list):
            candidates = []

        # Confirmed findings live on the report node's finding_count, falling
        # back to whatever validation recorded.
        finding_count = int(
            all_outputs.get("finding_count")
            or all_outputs.get("confirmed_count", 0)
            or 0
        )
        findings = all_outputs.get("findings", [])
        if not isinstance(findings, list) or len(findings) < finding_count:
            findings = [
                {"target_url": target.normalized_url, "index": i}
                for i in range(finding_count)
            ]

        return {
            "success": True,
            "run_id": run_id,
            "candidates": candidates,
            "findings": findings,
        }

    except Exception as exc:
        return {
            "success": False,
            "error": str(exc),
            "candidates": [],
            "findings": [],
        }


def _print_multi_summary(
    *,
    console: Console,
    scan_id: str,
    queue: TargetQueue,
    duration: float,
    all_candidates: list,
    all_findings: list,
    quiet: bool,
    json_out: bool,
    output: Optional[str],
    target_summaries: list,
) -> None:
    """Print the multi-target scan summary."""

    if json_out:
        import json
        data = {
            "scan_id": scan_id,
            "duration_s": round(duration, 1),
            "targets": queue.summary(),
            "total_candidates": len(all_candidates),
            "total_findings": len(all_findings),
            "target_results": target_summaries,
        }
        console.print(json.dumps(data, indent=2))
        return

    if quiet:
        # One-line summary only
        console.print(
            f"Scan {scan_id}: {queue.completed_count}/{queue.total_targets} targets, "
            f"{len(all_candidates)} candidates, {len(all_findings)} findings "
            f"({duration:.1f}s)"
        )
        return

    # Full summary
    console.print()
    console.print("[bold]===========================================================[/bold]")
    console.print("[bold cyan]Multi-Target Scan Complete[/bold cyan]")
    console.print("[bold]===========================================================[/bold]")
    console.print()

    # Target statistics table
    table = Table(show_header=False, box=None)
    table.add_column("key", style="dim")
    table.add_column("value")

    table.add_row("Scan ID:", scan_id)
    table.add_row("Duration:", f"{duration:.1f}s")
    table.add_row("Total Targets:", str(queue.total_targets))
    table.add_row("Completed:", f"[green]{queue.completed_count}[/green]")
    if queue.failed_count > 0:
        table.add_row("Failed:", f"[red]{queue.failed_count}[/red]")
    if queue.blocked_count > 0:
        table.add_row("Blocked:", f"[yellow]{queue.blocked_count}[/yellow]")
    table.add_row("Total Candidates:", str(len(all_candidates)))
    table.add_row("Total Findings:", str(len(all_findings)))

    console.print(table)

    # Show per-target results if verbose
    if target_summaries and len(target_summaries) <= 20:
        console.print()
        console.print("[dim]Per-target results:[/dim]")
        for ts in target_summaries:
            status_icon = "[green]OK  [/green]" if ts["status"] == "completed" else "[red]FAIL[/red]"
            console.print(
                f"  {status_icon}  {ts['url'][:60]} "
                f"({ts.get('candidates', 0)} candidates, {ts.get('findings', 0)} findings)"
            )

    console.print()

    # Save JSON report if requested
    if output:
        import json
        data = {
            "scan_id": scan_id,
            "duration_s": round(duration, 1),
            "targets": queue.summary(),
            "total_candidates": len(all_candidates),
            "total_findings": len(all_findings),
            "target_results": target_summaries,
        }
        Path(output).write_text(json.dumps(data, indent=2), encoding="utf-8")
        console.print(f"[dim]Report saved: {output}[/dim]\n")
