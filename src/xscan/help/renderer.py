"""
XScan Help Renderer
===================
Renders help content to the terminal using Rich.

Supports:
  - Full Markdown files (via rich.markdown)
  - Inline topic dicts (title + body text)
  - Search result lists
  - Guided menu
  - Topic list
  - Not-found / no-results messages
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from .search import SearchResult

_console = Console()


class HelpRenderer:
    """All terminal rendering for the help system."""

    def __init__(self, console: Console | None = None) -> None:
        self.con = console or _console

    # ------------------------------------------------------------------
    # Markdown file
    # ------------------------------------------------------------------

    def render_file(self, path: Path) -> None:
        content = path.read_text(encoding="utf-8")
        self.con.print()
        self.con.print(Markdown(content))
        self.con.print()

    # ------------------------------------------------------------------
    # Inline topic (dict with "title" and "body" keys)
    # ------------------------------------------------------------------

    def render_inline(self, topic: dict[str, Any]) -> None:
        title = topic.get("title", "")
        body = topic.get("body", "")
        self.con.print()
        if title:
            self.con.print(Panel(Text(title, style="bold cyan"), box=box.SIMPLE))
        self.con.print(Markdown(body))
        self.con.print()

    # ------------------------------------------------------------------
    # Search results
    # ------------------------------------------------------------------

    def render_search_results(self, query: str, results: list[SearchResult]) -> None:
        self.con.print()
        self.con.print(
            f"[bold]Search results for:[/bold] [yellow]{query}[/yellow]\n"
        )
        table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold blue")
        table.add_column("Topic", style="cyan", no_wrap=True, min_width=28)
        table.add_column("Title", min_width=30)
        table.add_column("Snippet", min_width=40)

        for r in results:
            table.add_row(
                f"xscan help {r.topic_key}",
                r.title,
                r.snippet or "[dim]—[/dim]",
            )
        self.con.print(table)
        self.con.print(
            "[dim]Run [cyan]xscan help <topic>[/cyan] to read a result.[/dim]\n"
        )

    def no_search_results(self, query: str) -> None:
        self.con.print(
            f"\n[yellow]No results found for:[/yellow] {query}\n"
            "Try broader keywords, or run [cyan]xscan help topics[/cyan] to list all topics.\n"
        )

    # ------------------------------------------------------------------
    # Guided menu
    # ------------------------------------------------------------------

    def render_guided_menu(self, menu: list[dict[str, str]]) -> None:
        self.con.print()
        self.con.print(Panel(
            "[bold cyan]What are you trying to do?[/bold cyan]",
            box=box.ROUNDED,
            expand=False,
        ))
        self.con.print()
        for i, item in enumerate(menu, start=1):
            label = item.get("label", "")
            topic = item.get("topic", "")
            self.con.print(f"  [bold]{i:>2}.[/bold]  {label}")
        self.con.print()
        self.con.print(
            "[dim]Run [cyan]xscan help <topic>[/cyan] for any item, "
            "or [cyan]xscan help search \"<query>\"[/cyan] for free-text search.[/dim]\n"
        )

    # ------------------------------------------------------------------
    # Topic list
    # ------------------------------------------------------------------

    def render_topic_list(self, topics: list[str]) -> None:
        self.con.print()
        self.con.print("[bold]Available help topics[/bold]\n")
        # Print in three columns
        col_width = max(len(t) for t in topics) + 4 if topics else 30
        cols = 3
        for i, topic in enumerate(topics):
            end = "\n" if (i + 1) % cols == 0 or i == len(topics) - 1 else ""
            self.con.print(f"  [cyan]{topic:<{col_width}}[/cyan]", end=end)
        self.con.print()
        self.con.print(
            "[dim]Run [cyan]xscan help <topic>[/cyan] to read any topic.[/dim]\n"
        )

    # ------------------------------------------------------------------
    # Not found
    # ------------------------------------------------------------------

    def not_found(self, topic: str, available: list[str]) -> None:
        self.con.print(
            f"\n[red]Help topic not found:[/red] [yellow]{topic}[/yellow]\n"
        )
        # Suggest similar topics
        suggestions = self._similar(topic, available)
        if suggestions:
            self.con.print("[bold]Did you mean?[/bold]")
            for s in suggestions:
                self.con.print(f"  [cyan]xscan help {s}[/cyan]")
            self.con.print()
        self.con.print(
            "Run [cyan]xscan help topics[/cyan] to list all available topics.\n"
        )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _similar(query: str, candidates: list[str], n: int = 5) -> list[str]:
        """Return up to *n* candidates that share at least one word with query."""
        q_words = set(query.lower().replace("-", " ").split())
        scored = []
        for c in candidates:
            c_words = set(c.lower().replace("-", " ").split())
            overlap = len(q_words & c_words)
            if overlap:
                scored.append((overlap, c))
        scored.sort(reverse=True)
        return [c for _, c in scored[:n]]
