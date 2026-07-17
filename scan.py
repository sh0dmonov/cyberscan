#!/usr/bin/env python3
"""
WebAuditAgent — CLI Tool
=========================
Ishlatish:
  python scan.py scan --url https://example.com
  python scan.py scan --url https://example.com --depth deep --output ./reports/
  python scan.py scan --url https://example.com --format html --format pdf

Huquqiy ogohlantirish:
  Faqat ruxsat etilgan tizimlarni tekshiring. Ruxsatsiz skanerlash qonun bilan taqiqlanadi.
"""
import asyncio
import io
import sys

# Windows UTF-8 encoding fix
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from datetime import datetime
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text
from rich import box

app = typer.Typer(
    name="webaudit",
    help="WebAuditAgent -- Web xavfsizlik skaneri (faqat ruxsat etilgan maqsadlar uchun)",
    add_completion=False,
)
console = Console(force_terminal=True, highlight=False)

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "bold orange3",
    "MEDIUM":   "bold yellow",
    "LOW":      "bold green",
    "INFO":     "bold cyan",
}
SEVERITY_LABEL = {
    "CRITICAL": "[CRITICAL]", "HIGH": "[HIGH]",
    "MEDIUM": "[MEDIUM]",     "LOW":  "[LOW]",  "INFO": "[INFO]",
}


def _print_banner():
    console.print(Panel.fit(
        "[bold cyan]WebAuditAgent v1.0[/bold cyan]\n"
        "[dim]Web Application Security Scanner[/dim]\n"
        "[bold red]!! FAQAT RUXSAT ETILGAN TIZIMLAR UCHUN !![/bold red]",
        border_style="cyan",
    ))


def _print_findings_table(findings: list):
    if not findings:
        console.print("\n[green]>> Hech qanday zaiflik topilmadi.[/green]")
        return

    table = Table(
        show_header=True, header_style="bold white on dark_blue",
        box=box.ROUNDED, expand=True,
    )
    table.add_column("#",  width=4, justify="right", style="dim")
    table.add_column("Severity",    width=12)
    table.add_column("CVSS",        width=6, justify="center")
    table.add_column("Zaiflik nomi",           min_width=28)
    table.add_column("Tool",        width=22, style="dim")
    table.add_column("Confidence",  width=10)

    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "INFO")
        color = SEVERITY_COLORS.get(sev, "white")
        label = SEVERITY_LABEL.get(sev, sev)
        cvss = f.get("cvss_score")
        table.add_row(
            str(i),
            f"[{color}]{label}[/{color}]",
            f"[{color}]{cvss:.1f}[/{color}]" if cvss else "--",
            f.get("vulnerability_name", "")[:50],
            f.get("tool_name", ""),
            f.get("confidence", ""),
        )

    console.print(table)


@app.command()
def scan(
    url: str = typer.Option(..., "--url", "-u", help="Skanerlash manzili (URL)"),
    depth: str = typer.Option("standard", "--depth", "-d",
        help="Scan chuqurligi: quick | standard | deep"),
    output: Path = typer.Option(Path("./reports"), "--output", "-o",
        help="Hisobot saqlash papkasi"),
    formats: List[str] = typer.Option(["html"], "--format", "-f",
        help="Hisobot formati: html | pdf (bir nechta: -f html -f pdf)"),
    yes: bool = typer.Option(False, "--yes", "-y",
        help="Ruxsatnomani avtomatik tasdiqlash (skript rejimi)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Batafsil log"),
):
    """
    Berilgan URL'ni skanerlaydi va hisobot yaratadi.

    Misol:\n
      python scan.py scan --url https://example.com\n
      python scan.py scan --url http://localhost:8080 --depth deep -f html -f pdf
    """
    _print_banner()

    # URL tekshirish
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    if depth not in ("quick", "standard", "deep"):
        console.print(f"[red]Noto'g'ri depth: {depth}[/red]")
        raise typer.Exit(1)

    console.print(Panel(
        f"[bold yellow]!! HUQUQIY OGOHLANTIRISH !![/bold yellow]\n\n"
        f"Skanerlash manzili: [cyan]{url}[/cyan]\n"
        f"Chuqurlik: [cyan]{depth}[/cyan]\n\n"
        f"[dim]Ushbu vosita faqat sizga tegishli yoki yozma ruxsat olingan\n"
        f"tizimlarni tekshirish uchun mo'ljallangan.\n"
        f"Ruxsatsiz skanerlash qonun bilan taqiqlanadi.[/dim]",
        border_style="yellow",
    ))

    if not yes:
        confirmed = typer.confirm(
            "\n[?] Men ushbu saytni tekshirishga vakolatliman. Davom etamanmi?",
            default=False,
        )
        if not confirmed:
            console.print("[red]Skanerlash bekor qilindi.[/red]")
            raise typer.Exit(0)

    console.print(f"\n[bold cyan]>> Skanerlash boshlanyapti...[/bold cyan]\n")

    # ── Async scan ─────────────────────────────────────────────────────
    findings, duration, modules = asyncio.run(
        _run_with_progress(url, depth, verbose)
    )

    # ── Natijalar ──────────────────────────────────────────────────────
    from collections import Counter
    sev_counts = Counter(f.get("severity", "INFO") for f in findings)

    console.print(f"\n[bold green]>> Scan yakunlandi![/bold green] "
                  f"[dim]({duration:.0f} soniya)[/dim]\n")

    console.print("[bold]Natijalar xulosasi:[/bold]")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        cnt = sev_counts.get(sev, 0)
        if cnt > 0:
            color = SEVERITY_COLORS[sev]
            label = SEVERITY_LABEL.get(sev, sev)
            console.print(f"   [{color}]{label:12}[/{color}] : {cnt} ta")

    console.print()
    _print_findings_table(findings)

    # ── Hisobot yaratish ───────────────────────────────────────────────
    from agent.report.builder import ReportBuilder
    builder = ReportBuilder()

    console.print(f"\n[bold]📄 Hisobot yaratilmoqda...[/bold]")
    html_content = builder.build_html(
        findings=findings,
        target_url=url,
        scan_duration=duration,
        modules_used=modules,
    )

    output.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    from urllib.parse import urlparse
    domain = urlparse(url).netloc.replace(".", "_").replace(":", "_")
    base_name = f"audit_{domain}_{timestamp}"

    saved = []

    if "html" in formats:
        html_path = output / f"{base_name}.html"
        builder.save_html(html_content, html_path)
        saved.append(("HTML", html_path))

    if "pdf" in formats:
        pdf_path = output / f"{base_name}.pdf"
        result = builder.save_pdf(html_content, pdf_path)
        if result:
            saved.append(("PDF", pdf_path))
        else:
            console.print("[yellow]⚠️  PDF yaratilmadi — weasyprint o'rnatilmagan.[/yellow]")
            console.print("[dim]   pip install weasyprint[/dim]")

    # ── Saqlangan fayllar ──────────────────────────────────────────────
    if saved:
        console.print()
        console.print(Panel(
            "\n".join(f"[green]SAVED {fmt}:[/green] [cyan]{path}[/cyan]" for fmt, path in saved),
            title="[bold]Hisobot fayllari[/bold]",
            border_style="green",
        ))

    if sev_counts.get("CRITICAL", 0) > 0 or sev_counts.get("HIGH", 0) > 0:
        console.print(Panel(
            f"[bold red]{sev_counts.get('CRITICAL', 0)} ta CRITICAL, "
            f"{sev_counts.get('HIGH', 0)} ta HIGH zaiflik topildi!\n[/bold red]"
            f"[dim]Darhol choralar ko'rish tavsiya etiladi.[/dim]",
            border_style="red",
            title="!! Muhim",
        ))


async def _run_with_progress(url: str, depth: str, verbose: bool):
    """Progress bar bilan async scan."""
    from agent.cli_runner import run_scan_cli

    last_msg = [""]

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30),
        TextColumn("[cyan]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task("[cyan]Skanerlanyapti...", total=100)

        async def on_progress(msg: str, pct: int):
            last_msg[0] = msg
            progress.update(task, completed=pct, description=f"[cyan]{msg}")

        findings, duration, modules = await run_scan_cli(
            target_url=url,
            scan_depth=depth,
            progress_cb=on_progress,
        )
        progress.update(task, completed=100, description="[green]>> Yakunlandi!")

    return findings, duration, modules


@app.command()
def version():
    """Versiya ma'lumotlari."""
    console.print("[bold cyan]WebAuditAgent[/bold cyan] v1.0")
    console.print("[dim]Bitiruv diplom loyihasi -- Kiber Xavfsizlik 2026[/dim]")
    console.print("[dim]Faqat ruxsat etilgan maqsadlar uchun[/dim]")


if __name__ == "__main__":
    app()
