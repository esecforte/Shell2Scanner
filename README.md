# shell2scan

A 2-in-1 **detector** for two pre-authentication RCE vulnerability families. It
detects only and never achieves code execution. The `PHP2Shell` active probe can
crash a PHP-FPM worker on a vulnerable host, so run it only against systems you are
authorized to test.

| Module | CVE | Affected stack | Fixed in |
| --- | --- | --- | --- |
| `Node2Shell` | CVE-2026-111497 | Node.js / Bun / Envoy bundled Brotli decoder | Node.js 22.23.4 / 24.22.1 / 26.12.1, Bun 1.4.4 |
| `PHP2Shell` | CVE-2026-109618 / CVE-2026-109619 | PHP behind mod_php / PHP-FPM / LiteSpeed | PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 |

Each module combines a version fast-path, an active differential probe, and WAF
detection + bypass. It scans one or many targets per run and can optionally discover
open ports first (concurrent TCP connect scan) to probe every open web service.

Related unfixed companion issue **CVE-2026-115560** (no patch): mitigate with
`session.upload_progress.enabled=0` in `php.ini`. The PHP module appends this advisory
to every PHP finding.

## Authorization

Only scan systems you own or are explicitly authorized to test. The tool confirms
authorization before every scan; `-y` skips the prompt for automation.

## Install

```bash
git clone https://github.com/esecforte/shell2scan.git
cd shell2scan
python -m pip install -r requirements.txt
```

Requires Python 3.9+.

## Usage

Interactive:

```bash
python shell2scan.py
```

Scripted / CI:

```bash
python shell2scan.py -t example.com                         # both modules
python shell2scan.py -t 10.0.0.5 --only node2shell --scheme http -y
python shell2scan.py -t https://example.com --json report.json -y

# Multiple targets (repeat -t, or list them positionally)
python shell2scan.py -t a.example.com -t b.example.com 10.0.0.5 -y

# Read a target list from a file (one per line; blank lines and # comments ignored)
python shell2scan.py -i targets.txt --json report.json -y

# Port discovery: find open ports on each host, then probe every open web port
python shell2scan.py -t 10.0.0.5 --ports default -y          # common web ports
python shell2scan.py -i targets.txt --ports 80,443,8000-8100 -y
python shell2scan.py -t 10.0.0.5 --ports all --port-timeout 0.5 -y   # 1-65535
```

### Options

| Flag | Description |
| --- | --- |
| `-t, --target` | Domain, IP, or URL. Repeatable. Omit all for interactive mode. |
| `TARGET...` | Additional targets as positional arguments. |
| `-i, --input FILE` | Read targets from a text file (`#` comments allowed). |
| `--ports SPEC` | Discover open ports first. `default`, `all`, or a list/range like `80,443,8000-8100`. |
| `--port-timeout S` | Per-port TCP connect timeout in seconds (default: 1.0). |
| `--port-workers N` | Concurrent port-scan workers (default: 100). |
| `--only {node2shell,php2shell}` | Run a single module (default: both). |
| `--scheme {http,https}` | Force a scheme (default: try https then http). |
| `--timeout S` | Per-request timeout in seconds (default: 15). |
| `--verify-tls` | Verify TLS certificates (off by default). |
| `--json FILE` | Write findings to a JSON report. |
| `-y, --yes` | Confirm authorization without the prompt. |
| `--no-banner` | Suppress the banner. |
| `--debug` | Print full tracebacks when a module errors. |
| `--version` | Print the tool version and exit. |

Exit codes: `0` nothing vulnerable, `1` at least one `VULNERABLE`, `2` bad input,
`3` authorization declined, `130` interrupted.

## Verdicts

- `VULNERABLE` — a vulnerable Node.js / PHP version was identified, or an active probe triggered.
- `LIKELY EXPOSED` — the attack surface is present but not fully confirmed; verify the version on the host.
- `NOT CONFIRMED` — the active check could not be resolved cleanly (rejected by a size/WAF limit, dropped/timed out, unreadable baseline). A dropped or timed-out probe is never reported as `VULNERABLE`.
- `NOT VULNERABLE` — the affected signal / stack was not detected, or the version is patched.
- `SCAN ERROR` — the host was unreachable over the attempted scheme.

## Project layout

```
shell2scan/
├── shell2scan.py        CLI + interactive menu
├── core/
│   ├── __init__.py      Finding type, verdict constants
│   ├── net.py           Target normalization + HTTP session
│   ├── ports.py         Concurrent TCP-connect port discovery
│   ├── waf.py           WAF fingerprinting + bypass helpers
│   ├── node2shell.py    CVE-2026-111497 detection
│   ├── php2shell.py     CVE-2026-109618 / 109619 detection
│   └── ui.py            Banner, menu, result panels
├── test_shell2scan.py   Offline test suite (standard library only)
├── requirements.txt
└── LICENSE
```

## Tests

No extra dependencies or test runner required — the suite uses only the Python
standard library and never touches the network (the HTTP session is replaced
with in-memory doubles):

```bash
python test_shell2scan.py          # or: python -m unittest test_shell2scan
```

It covers target normalization, port parsing / scheme hints, the version
verdicts (Node.js / Bun / Envoy / PHP), WAF fingerprinting, the PHP active-probe
state machine, and JSON report generation.

## License

MIT — see [LICENSE](LICENSE). © 2026 eSecForte.
