#!/usr/bin/env python3
from __future__ import annotations

import argparse
import dataclasses
import json
import re
import sys
import time
import traceback
from datetime import datetime, timezone

from core import Finding, VULNERABLE, ERROR, WEBSITE, AUTHOR, __version__
from core import net, ports, ui, node2shell, php2shell

MODULES = {
    "node2shell": node2shell,
    "php2shell": php2shell,
}

DEFAULT_TIMEOUT = 15.0
DEFAULT_PORT_TIMEOUT = 1.0
DEFAULT_PORT_WORKERS = 100

DEBUG = False


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="shell2scan",
        description=("2-in-1 scanner for Node2Shell and PHP2Shell "
                     f"(authorized testing only). Made by {AUTHOR} — {WEBSITE}"),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-t", "--target", action="append", metavar="TARGET",
                   help="Domain, IP, or URL. Repeatable. Omit all for interactive mode.")
    p.add_argument("targets", nargs="*", metavar="TARGET",
                   help="Additional targets as positional arguments.")
    p.add_argument("-i", "--input", metavar="FILE",
                   help="Read targets from a text file (one per line; # comments allowed).")
    p.add_argument("--ports", metavar="SPEC",
                   help="Discover open ports before scanning, then probe each open web port. "
                        "'default' = common web ports, 'all' = 1-65535, or e.g. 80,443,8000-8100.")
    p.add_argument("--port-timeout", type=float, default=DEFAULT_PORT_TIMEOUT,
                   help=f"Per-port TCP connect timeout in seconds (default: {DEFAULT_PORT_TIMEOUT}).")
    p.add_argument("--port-workers", type=int, default=DEFAULT_PORT_WORKERS,
                   help=f"Concurrent port-scan workers (default: {DEFAULT_PORT_WORKERS}).")
    p.add_argument("--only", choices=list(MODULES), help="Run only one module (default: both).")
    p.add_argument("--scheme", choices=["http", "https"], help="Force a scheme (default: https then http).")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                   help=f"Per-request timeout seconds (default: {int(DEFAULT_TIMEOUT)}).")
    p.add_argument("--verify-tls", action="store_true", help="Verify TLS certificates (off by default).")
    p.add_argument("--json", metavar="FILE", help="Write findings to a JSON report file.")
    p.add_argument("--no-banner", action="store_true", help="Suppress the banner.")
    p.add_argument("-y", "--yes", action="store_true",
                   help="Confirm authorization without prompting (CI mode).")
    p.add_argument("--debug", action="store_true",
                   help="Print full tracebacks when a module errors.")
    p.add_argument("--version", action="version",
                   version=f"%(prog)s {__version__} - {AUTHOR} {WEBSITE}")
    return p.parse_args(argv)


def read_target_file(path: str) -> list[str]:
    with open(path, "r", encoding="utf-8") as fh:
        out = []
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line)
        return out


def collect_targets(args: argparse.Namespace) -> list[str]:
    raws: list[str] = list(args.target or []) + list(args.targets or [])
    if args.input:
        try:
            raws.extend(read_target_file(args.input))
        except OSError as exc:
            ui.error(f"Could not read target file '{args.input}': {exc}")

    targets: list[str] = []
    seen: set[str] = set()
    for raw in raws:
        try:
            norm = net.normalize_target(raw)
        except ValueError as exc:
            ui.error(str(exc))
            continue
        if norm not in seen:
            seen.add(norm)
            targets.append(norm)
    return targets


def resolve_ports(spec: str) -> list[int]:
    if spec.strip().lower() in ("", "default"):
        return list(ports.DEFAULT_WEB_PORTS)
    return ports.parse_ports(spec)


def _bases_for(target: str, scheme: str | None, port: int | None) -> list[str]:
    if scheme:
        return net.base_urls(target, scheme)
    if port is not None:
        hint = ports.scheme_for_port(port)
        if hint == "https":
            return [f"https://{target}", f"http://{target}"]
        if hint == "http":
            return [f"http://{target}", f"https://{target}"]
    return net.base_urls(target, None)


def run_modules(keys: list[str], target: str, scheme: str | None,
                timeout: float, verify_tls: bool, port: int | None = None) -> list[Finding]:
    s = net.session(timeout, verify_tls)
    bases = _bases_for(target, scheme, port)
    findings: list[Finding] = []
    try:
        for key in keys:
            module = MODULES[key]
            ui.info(f"Running {module.NAME} check…")
            try:
                result = module.scan(s, bases)
            except Exception as exc:
                ui.error(f"{module.NAME} module errored: {exc}")
                if DEBUG:
                    ui.error(traceback.format_exc())
                result = [Finding(module.NAME, module.CVE, target, ERROR, str(exc))]
            ui.results(result)
            findings.extend(result)
    finally:
        s.close()
    return findings


def scan_target(target: str, keys: list[str], scheme: str | None, timeout: float,
                verify_tls: bool, port_list: list[int] | None,
                port_timeout: float, port_workers: int) -> list[Finding]:
    names = [MODULES[k].NAME for k in keys]

    if port_list is None:
        ui.scan_header(target, names)
        return run_modules(keys, target, scheme, timeout, verify_tls)

    host, _ = net.split_host_port(target)
    ui.port_scan_start(host, len(port_list))
    open_ports = ports.scan_ports(host, port_list, port_timeout, port_workers,
                                  on_progress=ui.make_port_progress())
    ui.port_scan_result(host, open_ports)
    if not open_ports:
        finding = Finding("portscan", "-", host, ERROR,
                          "no open ports found in the scanned range — nothing to probe")
        ui.results([finding])
        return [finding]

    findings: list[Finding] = []
    for port in open_ports:
        sub = net.join_host_port(host, port)
        ui.scan_header(sub, names)
        findings.extend(run_modules(keys, sub, scheme, timeout, verify_tls, port=port))
    return findings


REPORT_SCHEMA_VERSION = "1.1"


def _finding_dict(f: Finding) -> dict:
    d = dataclasses.asdict(f)
    d["verdict_label"] = ui.LABEL.get(f.verdict, f.verdict.upper())
    return d


def write_report(path: str, groups: list[tuple[str, list[Finding]]],
                 modules: list[str], params: dict | None = None) -> None:
    all_findings = [f for _, findings in groups for f in findings]
    report = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "tool": "shell2scan",
        "version": __version__,
        "author": AUTHOR,
        "website": WEBSITE,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "modules": modules,
        "parameters": params or {},
        "summary": {
            "targets": len(groups),
            "findings": len(all_findings),
            "vulnerable": sum(1 for f in all_findings if f.verdict == VULNERABLE),
        },
        "targets": [
            {
                "target": target,
                "findings": [_finding_dict(f) for f in findings],
            }
            for target, findings in groups
        ],
    }
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        ui.ok(f"JSON report written to {path}")
    except OSError as exc:
        ui.error(f"Could not write JSON report: {exc}")


def export_report(groups: list[tuple[str, list[Finding]]], modules: list[str],
                  path: str | None, prompt: bool, params: dict | None = None) -> None:
    if path:
        write_report(path, groups, modules, params)
    elif prompt and ui.ask_export():
        write_report(ui.ask_export_path("report.json"), groups, modules, params)


def _parse_targets_input(raw: str) -> list[str]:
    raw = raw.strip()
    if raw.startswith("@") or raw.lower().startswith("file:"):
        path = raw[1:] if raw.startswith("@") else raw.split(":", 1)[1]
        try:
            raws = read_target_file(path.strip())
        except OSError as exc:
            ui.error(f"Could not read target file '{path.strip()}': {exc}")
            return []
    else:
        raws = [t for t in re.split(r"[,\s]+", raw) if t]

    targets, seen = [], set()
    for item in raws:
        try:
            norm = net.normalize_target(item)
        except ValueError as exc:
            ui.error(str(exc))
            continue
        if norm not in seen:
            seen.add(norm)
            targets.append(norm)
    return targets


def interactive() -> int:
    ui.banner()
    options = [(key, f"{MODULES[key].NAME:<11} — {MODULES[key].MENU_DESC}") for key in MODULES]
    while True:
        choice = ui.menu(options)
        if choice is None:
            break
        keys = list(MODULES) if choice == "both" else [choice]

        targets = _parse_targets_input(ui.ask_targets())
        if not targets:
            ui.error("No valid target entered.")
            continue

        opts = {"scheme": None, "timeout": DEFAULT_TIMEOUT, "verify_tls": False,
                "port_timeout": DEFAULT_PORT_TIMEOUT, "port_workers": DEFAULT_PORT_WORKERS}

        port_list = None
        if ui.ask_port_scan():
            try:
                port_list = resolve_ports(ui.ask_ports())
            except ValueError as exc:
                ui.error(f"Invalid port spec: {exc}")
                continue
            opts = ui.ask_port_options(opts)

        opts = ui.ask_advanced(opts)

        if not ui.ask_authorization_many(targets):
            ui.error("Authorization not confirmed — skipping.")
            continue

        names = [MODULES[k].NAME for k in keys]
        start = time.time()
        groups: list[tuple[str, list[Finding]]] = []
        all_findings: list[Finding] = []
        for i, target in enumerate(targets, start=1):
            ui.target_header(target, i, len(targets))
            findings = scan_target(target, keys, opts["scheme"], opts["timeout"],
                                   opts["verify_tls"], port_list,
                                   opts["port_timeout"], opts["port_workers"])
            groups.append((target, findings))
            all_findings.extend(findings)
        ui.overall_summary(len(targets), all_findings, time.time() - start)
        params = {
            "scheme": opts["scheme"], "timeout": opts["timeout"],
            "verify_tls": opts["verify_tls"], "port_timeout": opts["port_timeout"],
            "port_workers": opts["port_workers"],
        }
        export_report(groups, names, None, prompt=True, params=params)

        if not ui.ask_scan_another():
            break
    ui.footer()
    return 0


def cli(args: argparse.Namespace) -> int:
    if not args.no_banner:
        ui.banner()

    targets = collect_targets(args)
    if not targets:
        ui.error("No valid targets. Use -t/positional args or -i FILE.")
        return 2

    port_list = None
    if args.ports is not None:
        try:
            port_list = resolve_ports(args.ports)
        except ValueError as exc:
            ui.error(f"Invalid --ports value: {exc}")
            return 2

    if not args.yes and not ui.ask_authorization_many(targets):
        ui.error("Authorization not confirmed — aborting (use -y in CI).")
        return 3

    keys = [args.only] if args.only else list(MODULES)
    names = [MODULES[k].NAME for k in keys]

    start = time.time()
    groups: list[tuple[str, list[Finding]]] = []
    all_findings: list[Finding] = []
    for i, target in enumerate(targets, start=1):
        ui.target_header(target, i, len(targets))
        findings = scan_target(target, keys, args.scheme, args.timeout, args.verify_tls,
                               port_list, args.port_timeout, args.port_workers)
        groups.append((target, findings))
        all_findings.extend(findings)

    ui.overall_summary(len(targets), all_findings, time.time() - start)
    params = {
        "scheme": args.scheme, "timeout": args.timeout, "verify_tls": args.verify_tls,
        "ports": args.ports, "port_timeout": args.port_timeout,
        "port_workers": args.port_workers,
    }
    export_report(groups, names, args.json, prompt=not args.yes, params=params)
    ui.footer()

    return 1 if any(f.verdict == VULNERABLE for f in all_findings) else 0


def main(argv: list[str]) -> int:
    global DEBUG
    args = parse_args(argv)
    DEBUG = args.debug
    has_targets = bool(args.target or args.targets or args.input)
    if has_targets:
        return cli(args)
    cli_intent = args.yes or args.ports is not None or args.only or args.json
    if cli_intent or not sys.stdin.isatty():
        ui.error("No targets provided. Use -t/positional args or -i FILE (interactive mode needs a TTY).")
        return 2
    return interactive()


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (KeyboardInterrupt, EOFError):
        print()
        sys.exit(130)
