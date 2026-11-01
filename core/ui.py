from __future__ import annotations

import sys
from datetime import datetime

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.align import Align
    from rich.prompt import Prompt, Confirm
    from rich import box
    _RICH = True
except ImportError:
    _RICH = False

from core import (Finding, __version__, AUTHOR, WEBSITE,
                  VULNERABLE, LIKELY, INCONCLUSIVE, CLEAR, ERROR)

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

console = Console() if _RICH else None

LABEL = {
    VULNERABLE: "VULNERABLE",
    LIKELY: "LIKELY EXPOSED",
    INCONCLUSIVE: "NOT CONFIRMED",
    CLEAR: "NOT VULNERABLE",
    ERROR: "SCAN ERROR",
}

COLOR = {
    VULNERABLE: "red",
    LIKELY: "yellow",
    INCONCLUSIVE: "cyan",
    CLEAR: "green",
    ERROR: "bright_black",
}

CHIP_BG = {
    VULNERABLE: "red",
    LIKELY: "dark_orange3",
    INCONCLUSIVE: "dark_cyan",
    CLEAR: "green4",
    ERROR: "grey37",
}

ORDER = {VULNERABLE: 0, LIKELY: 1, INCONCLUSIVE: 2, ERROR: 3, CLEAR: 4}

_WORDMARK = r"""
 ____  _          _ _ ____  ____
/ ___|| |__   ___| | |___ \/ ___|  ___ __ _ _ __
\___ \| '_ \ / _ \ | | __) \___ \ / __/ _` | '_ \
 ___) | | | |  __/ | |/ __/ ___) | (_| (_| | | | |
|____/|_| |_|\___|_|_|_____|____/ \___\__,_|_| |_|
"""


def _plain(msg: str) -> None:
    try:
        print(msg)
    except UnicodeEncodeError:
        enc = (sys.stdout.encoding or "ascii")
        print(msg.encode(enc, "replace").decode(enc))


def banner() -> None:
    if _RICH:
        console.print(Text(_WORDMARK, style="bold cyan"))
        body = Text()
        body.append("2-in-1 web RCE scanner", style="bold white")
        body.append(f"   v{__version__}\n\n", style="dim")
        body.append("Node2Shell  ", style="bold cyan")
        body.append("CVE-2026-111497\n", style="white")
        body.append("PHP2Shell   ", style="bold cyan")
        body.append("CVE-2026-109618 / CVE-2026-109619\n\n", style="white")
        body.append("Made by ", style="dim")
        body.append(AUTHOR, style="bold green")
        body.append("  ·  ", style="dim")
        body.append(WEBSITE, style="underline cyan")
        console.print(Panel(body, border_style="cyan", box=box.DOUBLE, padding=(1, 3)))
    else:
        _plain(_WORDMARK)
        _plain(f"2-in-1 web RCE scanner  v{__version__}")
        _plain("Node2Shell  CVE-2026-111497")
        _plain("PHP2Shell   CVE-2026-109618 / CVE-2026-109619")
        _plain(f"Made by {AUTHOR}  ·  {WEBSITE}")
        _plain("-" * 60)


def footer() -> None:
    if _RICH:
        console.print(Align.center(Text(f"{AUTHOR}  ·  {WEBSITE}", style="dim")))
    else:
        _plain(f"{AUTHOR} · {WEBSITE}")


def info(msg: str) -> None:
    console.print(f"[cyan][*][/cyan] {msg}") if _RICH else _plain(f"[*] {msg}")


def ok(msg: str) -> None:
    console.print(f"[green][+][/green] {msg}") if _RICH else _plain(f"[+] {msg}")


def warn(msg: str) -> None:
    console.print(f"[yellow][!][/yellow] {msg}") if _RICH else _plain(f"[!] {msg}")


def error(msg: str) -> None:
    console.print(f"[bold red][x][/bold red] {msg}") if _RICH else _plain(f"[x] {msg}")


def menu(options: list[tuple[str, str]]) -> str | None:
    rows = list(enumerate(options, start=1))
    if _RICH:
        t = Table.grid(padding=(0, 2))
        t.add_column(style="bold cyan", justify="right")
        t.add_column()
        for i, (_, desc) in rows:
            t.add_row(str(i), desc)
        t.add_row(str(len(rows) + 1), "Both modules")
        t.add_row("0", "Exit")
        console.print(Panel(t, title="[bold]Select a scan[/bold]", border_style="cyan", box=box.ROUNDED))
        choices = [str(i) for i, _ in rows] + [str(len(rows) + 1), "0"]
        choice = Prompt.ask("  Your choice", choices=choices, default=str(len(rows) + 1))
    else:
        _plain("\nSelect a scan:")
        for i, (_, desc) in rows:
            _plain(f"  {i}) {desc}")
        _plain(f"  {len(rows) + 1}) Both modules")
        _plain("  0) Exit")
        choice = input(f"  Your choice [{len(rows) + 1}]: ").strip() or str(len(rows) + 1)

    if choice == "0":
        return None
    if choice == str(len(rows) + 1):
        return "both"
    try:
        idx = int(choice) - 1
    except ValueError:
        return None
    if not 0 <= idx < len(options):
        return None
    return options[idx][0]


def ask_targets() -> str:
    hint = "domain / IP / URL — comma-separated, or @file.txt"
    if _RICH:
        return Prompt.ask(f"  Target(s) [dim]({hint})[/dim]").strip()
    return input(f"  Target(s) ({hint}): ").strip()


def ask_ports() -> str:
    hint = "blank = default web ports, 'all' = 1-65535, or e.g. 80,443,8000-8100"
    if _RICH:
        return Prompt.ask(f"  Port scan [dim]({hint})[/dim]", default="").strip()
    return input(f"  Port scan ({hint}): ").strip()


def ask_port_scan() -> bool:
    if _RICH:
        return Confirm.ask("  Discover open ports first (scan ports, not just 80/443)",
                           default=False)
    return input("  Discover open ports first? [y/N] ").strip().lower() in ("y", "yes")


def _ask_float(label: str, default: float) -> float:
    if _RICH:
        raw = Prompt.ask(f"  {label}", default=str(default)).strip()
    else:
        raw = input(f"  {label} [{default}]: ").strip()
    try:
        return float(raw) if raw else default
    except ValueError:
        return default


def _ask_int(label: str, default: int) -> int:
    if _RICH:
        raw = Prompt.ask(f"  {label}", default=str(default)).strip()
    else:
        raw = input(f"  {label} [{default}]: ").strip()
    try:
        return int(raw) if raw else default
    except ValueError:
        return default


def ask_advanced(defaults: dict) -> dict:
    prompt = ("  Configure advanced options (scheme, timeout, TLS verify)"
              if not _RICH else "  Configure advanced options (scheme, timeout, TLS verify)")
    want = (Confirm.ask(prompt, default=False) if _RICH
            else input(prompt + "? [y/N] ").strip().lower() in ("y", "yes"))
    opts = dict(defaults)
    if not want:
        return opts
    if _RICH:
        scheme = Prompt.ask("  Scheme", choices=["auto", "http", "https"], default="auto")
    else:
        scheme = input("  Scheme (auto/http/https) [auto]: ").strip().lower() or "auto"
    opts["scheme"] = None if scheme == "auto" else scheme
    opts["timeout"] = _ask_float("Per-request timeout (s)", defaults["timeout"])
    if _RICH:
        opts["verify_tls"] = Confirm.ask("  Verify TLS certificates", default=defaults["verify_tls"])
    else:
        opts["verify_tls"] = input("  Verify TLS certificates? [y/N] ").strip().lower() in ("y", "yes")
    return opts


def ask_port_options(defaults: dict) -> dict:
    opts = dict(defaults)
    opts["port_timeout"] = _ask_float("Per-port connect timeout (s)", defaults["port_timeout"])
    opts["port_workers"] = _ask_int("Concurrent port workers", defaults["port_workers"])
    return opts


def ask_authorization(target: str) -> bool:
    msg = f"Confirm you are authorized to scan '{target}'"
    if _RICH:
        return Confirm.ask(f"  [yellow]{msg}[/yellow]", default=False)
    return input(f"  {msg}? [y/N] ").strip().lower() in ("y", "yes")


def ask_authorization_many(targets: list[str]) -> bool:
    if len(targets) == 1:
        return ask_authorization(targets[0])
    preview = ", ".join(targets[:5]) + (f" … (+{len(targets) - 5} more)" if len(targets) > 5 else "")
    msg = f"Confirm you are authorized to scan all {len(targets)} targets"
    if _RICH:
        console.print(f"  [dim]Targets:[/dim] {preview}")
        return Confirm.ask(f"  [yellow]{msg}[/yellow]", default=False)
    _plain(f"  Targets: {preview}")
    return input(f"  {msg}? [y/N] ").strip().lower() in ("y", "yes")


def ask_scan_another() -> bool:
    if _RICH:
        return Confirm.ask("  Scan another target", default=False)
    return input("  Scan another target? [y/N] ").strip().lower() in ("y", "yes")


def scan_header(target: str, modules: list[str]) -> None:
    started = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if _RICH:
        t = Table.grid(padding=(0, 2))
        t.add_column(style="bold cyan", justify="right")
        t.add_column()
        t.add_row("Target", target)
        t.add_row("Modules", ", ".join(modules))
        t.add_row("Mode", "active detection (no RCE)")
        t.add_row("Started", started)
        console.print(Panel(t, title="[bold]Scan session[/bold]", border_style="cyan", box=box.ROUNDED))
    else:
        _plain(f"\nTarget : {target}")
        _plain(f"Modules: {', '.join(modules)}")
        _plain(f"Started: {started}")


def port_scan_start(host: str, count: int) -> None:
    info(f"Port scan on {host}: probing {count} port(s)…")


def make_port_progress():
    state = {"last_pct": -1}

    def cb(done: int, total: int, open_count: int) -> None:
        pct = done * 100 // total if total else 100
        if pct == state["last_pct"] and done < total:
            return
        state["last_pct"] = pct
        bar_w = 24
        filled = pct * bar_w // 100
        bar = "#" * filled + "-" * (bar_w - filled)
        line = f"  [{bar}] {pct:3d}%  {done}/{total} ports  ·  {open_count} open   "
        sys.stdout.write("\r" + line)
        sys.stdout.flush()
        if done >= total:
            sys.stdout.write("\n")
            sys.stdout.flush()

    return cb


def port_scan_result(host: str, open_ports: list[int]) -> None:
    if open_ports:
        shown = ", ".join(str(p) for p in open_ports)
        ok(f"{host}: {len(open_ports)} open port(s) — {shown}")
    else:
        warn(f"{host}: no open ports found in the scanned range")


def target_header(target: str, index: int, total: int) -> None:
    label = f"[{index}/{total}] {target}"
    if _RICH:
        console.rule(f"[bold cyan]{label}[/bold cyan]")
    else:
        _plain(f"\n==== {label} ====")


def overall_summary(total_targets: int, findings: list[Finding], elapsed: float) -> None:
    vuln = sum(1 for f in findings if f.verdict == VULNERABLE)
    flagged = sum(1 for f in findings if f.verdict in (LIKELY, INCONCLUSIVE))
    line = (f"Scanned {total_targets} target(s) in {elapsed:.1f}s  —  "
            f"{vuln} vulnerable · {flagged} needs attention · "
            f"{len(findings) - vuln - flagged} clear/other.")
    if _RICH:
        style = "red" if vuln else ("yellow" if flagged else "green")
        console.print(Panel(line, title="[bold]Overall[/bold]", border_style=style, box=box.DOUBLE))
    else:
        _plain("\n" + line)


def results(findings: list[Finding]) -> None:
    for f in sorted(findings, key=lambda x: ORDER.get(x.verdict, 9)):
        label = LABEL.get(f.verdict, f.verdict.upper())
        color = COLOR.get(f.verdict, "white")
        status_txt = f"HTTP {f.status}" if f.status is not None else ""
        if _RICH:
            text = Text()
            chip = f"bold white on {CHIP_BG.get(f.verdict, 'blue')}"
            text.append(f"  {label}  ", style=chip)
            if status_txt:
                text.append(f"   {status_txt}", style="dim")
            text.append(f"\n\n{f.detail}", style="white")
            console.print(Panel(text, title=f"[bold]{f.module}[/bold]  ·  {f.cve}",
                                subtitle=f"[dim]{f.url}[/dim]", subtitle_align="right",
                                title_align="left", border_style=color, box=box.HEAVY, padding=(1, 2)))
        else:
            head = f"\n[{f.module} · {f.cve}]  {f.url}"
            _plain(head)
            _plain(f"  {label}" + (f"  ({status_txt})" if status_txt else ""))
            _plain(f"  {f.detail}")


def ask_export() -> bool:
    if _RICH:
        return Confirm.ask("  Export results to a JSON report", default=False)
    return input("  Export results to a JSON report? [y/N] ").strip().lower() in ("y", "yes")


def ask_export_path(default: str) -> str:
    if _RICH:
        return Prompt.ask("  Report file path", default=default).strip()
    return input(f"  Report file path [{default}]: ").strip() or default
