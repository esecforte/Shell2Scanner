from __future__ import annotations

import re

import requests

from core import Finding, VULNERABLE, LIKELY, INCONCLUSIVE, CLEAR, ERROR
from core.waf import detect_waf, bypass_brotli_headers

NAME = "Node2Shell / HTTP2Shell / Broccoli2Shell"
CVE = "CVE-2026-111497"
MENU_DESC = "CVE-2026-111497  (Node.js / Bun Brotli decoder RCE — Node2Shell/HTTP2Shell/Broccoli2Shell)"

FIXED = {22: (22, 23, 4), 24: (24, 22, 1), 26: (26, 12, 1)}
EOL_MAJORS = {21, 23, 25}
BROTLI_MIN_MAJOR = 10
FIXED_BUN = (1, 4, 4)
BUN_MIN_AFFECTED = (1, 0, 21)
FIXED_STR = "22.23.4 / 24.22.1 / 26.12.1"
FIXED_BUN_STR = "1.4.4"

BR_VALID = b"\x3b"
BR_MALFORMED = b"\xff"

BROTLI_PROBE_PATHS = (
    "/",
    "/api",
    "/api/v1",
    "/api/v2",
    "/health",
    "/graphql",
    "/v1",
    "/app",
    "/data",
    "/json",
)

_NODE_VER_RE = re.compile(r"node(?:\.js)?[/ ]?v?(\d+)\.(\d+)\.(\d+)", re.IGNORECASE)
_NODE_HEADER_RE = re.compile(r"\bnode(?:\.js)?\b", re.IGNORECASE)
_BUN_VER_RE = re.compile(r"\bbun[/ ]?v?(\d+)\.(\d+)\.(\d+)", re.IGNORECASE)
_EXPRESS_RE = re.compile(r"\bexpress\b", re.IGNORECASE)
_ENVOY_RE = re.compile(r"\benvoy\b", re.IGNORECASE)
_ENVOY_VER_RE = re.compile(r"\benvoy/(\d+)\.(\d+)\.(\d+)", re.IGNORECASE)

ENVOY_FIXED = {
    36: (1, 36, 12),
    37: (1, 37, 8),
    38: (1, 38, 6),
    39: (1, 39, 3),
    40: (1, 40, 0),
}

_NGINX_APACHE_RE = re.compile(r"\b(nginx|apache|litespeed)\b", re.IGNORECASE)
_NEXTJS_RE = re.compile(r"\bnext\.?js\b", re.IGNORECASE)
_ETAG_NODE_RE = re.compile(r'^W/"[0-9a-f]+-[A-Za-z0-9+/=]{20,}"$')
_CANNOT_METHOD_RE = re.compile(
    r"Cannot (?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) /", re.IGNORECASE
)
_PASS_THROUGH_NOTE = ("server is Apache/Nginx/LiteSpeed which does not decode Brotli request "
                      "bodies by default — only a Node.js/Bun process behind it would be exposed")


def _fingerprint(session: requests.Session, base: str):
    try:
        r = session.get(base, timeout=session.timeout, verify=session.verify,
                        allow_redirects=True)
    except requests.RequestException as exc:
        return False, None, None, f"request failed: {exc.__class__.__name__}", None, False, ""

    header_blob = " ".join(f"{k}: {v}" for k, v in r.headers.items())
    powered = r.headers.get("X-Powered-By", "")
    server = r.headers.get("Server", "")
    etag = r.headers.get("ETag", "")

    node_version: tuple[int, int, int] | None = None
    bun_version: tuple[int, int, int] | None = None
    runtime = None

    m = _NODE_VER_RE.search(header_blob)
    if m:
        node_version = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
        runtime = "node"

    bm = _BUN_VER_RE.search(header_blob)
    if bm:
        bun_version = (int(bm.group(1)), int(bm.group(2)), int(bm.group(3)))
        runtime = "bun"

    is_express = bool(_EXPRESS_RE.search(powered))
    is_nextjs = bool(
        _NEXTJS_RE.search(powered)
        or r.headers.get("X-Nextjs-Cache")
        or r.headers.get("X-Nextjs-Stale-Time")
    )
    etag_node = bool(_ETAG_NODE_RE.match(etag)) if etag else False
    is_node = (
        bool(_NODE_HEADER_RE.search(header_blob))
        or is_express or is_nextjs or etag_node or runtime is not None
    )
    is_passthrough = bool(_NGINX_APACHE_RE.search(server)) and not is_node

    if not is_node:
        try:
            r404 = session.get(
                base.rstrip("/") + "/_s2s_probe_404",
                timeout=session.timeout, verify=session.verify, allow_redirects=False,
            )
            if _CANNOT_METHOD_RE.search(r404.text or ""):
                is_express = True
                is_node = True
        except requests.RequestException:
            pass

    detail = (f"X-Powered-By: {powered}" if powered
              else f"Server: {server}" if server
              else "no Node/Express/Bun header")
    return is_node, node_version, bun_version, detail, is_passthrough, is_express, header_blob


def _node_version_verdict(version: tuple[int, int, int] | None) -> str | None:
    if not version:
        return None
    major = version[0]
    if major < BROTLI_MIN_MAJOR:
        return None
    if major in FIXED:
        return "vulnerable" if version < FIXED[major] else "patched"
    if major < 22 or major in EOL_MAJORS:
        return "vulnerable"
    return None


def _bun_version_verdict(version: tuple[int, int, int] | None) -> str | None:
    if not version:
        return None
    if version < BUN_MIN_AFFECTED:
        return None
    return "vulnerable" if version < FIXED_BUN else "patched"


def _envoy_verdict(blob: str) -> tuple[str | None, str | None]:
    m = _ENVOY_VER_RE.search(blob)
    if not m:
        if _ENVOY_RE.search(blob):
            return "unknown", "Envoy (version not advertised; fix is 1.36.12/1.37.8/1.38.6/1.39.3/1.40.0)"
        return None, None
    ver = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    minor = ver[1]
    fixed = ENVOY_FIXED.get(minor)
    if fixed is None:
        return "unknown", f"Envoy {'.'.join(map(str, ver))} (not in a tracked release line)"
    verdict = "vulnerable" if ver < fixed else "patched"
    return verdict, f"Envoy {'.'.join(map(str, ver))}"


def _post(session: requests.Session, url: str, encoding: str, body: bytes,
          extra_headers: dict[str, str] | None = None) -> requests.Response:
    headers = {
        "Content-Encoding": encoding,
        "Content-Type": "application/json",
        "Accept-Encoding": "identity",
    }
    if extra_headers:
        headers.update(extra_headers)
    return session.post(url, data=body, headers=headers, timeout=session.timeout,
                        verify=session.verify, allow_redirects=False)


def _decodes_brotli(
    session: requests.Session, base: str
) -> tuple[bool | None, str | None, str | None, bool]:
    waf_found = None
    n_tried = 0
    n_415 = 0
    for path in BROTLI_PROBE_PATHS:
        url = base.rstrip("/") + path
        try:
            valid = _post(session, url, "br", BR_VALID)
            malformed = _post(session, url, "br", BR_MALFORMED)
        except requests.RequestException:
            continue

        n_tried += 1
        if waf_found is None:
            waf_found = detect_waf(valid) or detect_waf(malformed)

        if valid.status_code in (403, 429) or malformed.status_code in (403, 429):
            bypass_hdrs = bypass_brotli_headers({})
            try:
                valid2 = _post(session, url, "br", BR_VALID, extra_headers=bypass_hdrs)
                malformed2 = _post(session, url, "br", BR_MALFORMED, extra_headers=bypass_hdrs)
                if valid2.status_code != malformed2.status_code:
                    if valid2.status_code < 500 and malformed2.status_code >= 400:
                        return True, path, waf_found, False
            except requests.RequestException:
                pass
            continue

        if valid.status_code == 415 and malformed.status_code == 415:
            n_415 += 1
            continue

        if valid.status_code == malformed.status_code:
            continue
        if valid.status_code >= 500:
            continue
        if malformed.status_code < 400:
            continue
        return True, path, waf_found, False

    is_bp1 = n_tried > 0 and n_415 == n_tried
    return False, None, waf_found, is_bp1


def _evaluate(session: requests.Session, base: str) -> tuple[int, Finding]:
    is_node, node_version, bun_version, fp, is_passthrough, is_express, header_blob = _fingerprint(session, base)
    if fp.startswith("request failed"):
        return 0, Finding(NAME, CVE, base, ERROR, f"host unreachable over this scheme ({fp})")

    envoy_verdict, envoy_ver_str = _envoy_verdict(header_blob)

    exposed, probe_path, waf, is_bp1 = _decodes_brotli(session, base)
    waf_note = f" [WAF: {waf} detected]" if waf else ""

    node_vstate = _node_version_verdict(node_version)
    bun_vstate = _bun_version_verdict(bun_version)
    node_ver_str = ".".join(map(str, node_version)) if node_version else None
    bun_ver_str = ".".join(map(str, bun_version)) if bun_version else None

    if bun_vstate == "patched":
        return 1, Finding(NAME, CVE, base, CLEAR,
                          f"patched Bun {bun_ver_str} (>= fixed release {FIXED_BUN_STR}) — not affected")

    if node_vstate == "patched":
        return 1, Finding(NAME, CVE, base, CLEAR,
                          f"patched Node.js {node_ver_str} (>= fixed release {FIXED_STR}) — not affected")

    if bun_vstate == "vulnerable":
        if exposed is True:
            return 4, Finding(NAME, CVE, base, VULNERABLE,
                              f"vulnerable Bun {bun_ver_str} confirmed decoding untrusted Brotli "
                              f"at {probe_path}{waf_note} (fixed: Bun {FIXED_BUN_STR})")
        return 3, Finding(NAME, CVE, base, VULNERABLE,
                          f"vulnerable Bun {bun_ver_str}; Brotli surface not confirmed on tested "
                          f"paths{waf_note} (fixed: Bun {FIXED_BUN_STR})")

    if node_vstate == "vulnerable":
        express_note = ("; Express 5 body-parser 2.0.0–2.3.0 inflates br bodies by default "
                        "— mitigate with express.json({ inflate: false }) until patched"
                        if is_express else "")
        if exposed is True:
            return 4, Finding(NAME, CVE, base, VULNERABLE,
                              f"vulnerable Node.js {node_ver_str} confirmed decoding untrusted Brotli "
                              f"at {probe_path}{waf_note}{express_note} (fixed: Node.js {FIXED_STR})")
        if exposed is False:
            tested = ", ".join(BROTLI_PROBE_PATHS)
            return 2, Finding(NAME, CVE, base, LIKELY,
                              f"vulnerable Node.js {node_ver_str} but Brotli decoding not observed on "
                              f"tested paths ({tested}){waf_note}; verify express.json()/body-parser "
                              f"inflate option is active{express_note} (fixed: {FIXED_STR})")
        return 2, Finding(NAME, CVE, base, LIKELY,
                          f"vulnerable Node.js {node_ver_str}; Brotli probe inconclusive{waf_note} "
                          f"(fixed: {FIXED_STR})")

    if envoy_verdict == "vulnerable":
        tail = (f" and decodes Brotli at {probe_path}" if exposed is True
                else " (Brotli decompressor filter must be configured for exposure to apply)")
        return 3, Finding(NAME, CVE, base, VULNERABLE,
                          f"vulnerable {envoy_ver_str}{tail}{waf_note} "
                          "(fix: 1.36.12/1.37.8/1.38.6/1.39.3/1.40.0)")

    if envoy_verdict == "unknown":
        return 2, Finding(NAME, CVE, base, INCONCLUSIVE,
                          f"{envoy_ver_str}{waf_note} — check Envoy version against fixed releases; "
                          "note: Envoy is only exposed when the Brotli decompressor filter is configured")

    if exposed is True:
        passthrough_note = f" ({_PASS_THROUGH_NOTE})" if is_passthrough else ""
        return 3, Finding(NAME, CVE, base, LIKELY,
                          f"decodes untrusted Brotli at {probe_path}{waf_note}{passthrough_note} — "
                          "CVE-2026-111497 attack surface present; Node.js/Bun version not advertised "
                          f"so a patched runtime looks identical. Run `node -v` on the host (fixed: {FIXED_STR})")

    if is_node:
        if is_bp1:
            note = ("body-parser 1.x (Express 4) detected — no Brotli request-body support, "
                    "not exposed to this CVE vector")
        elif exposed is None:
            note = "Brotli differential inconclusive"
        else:
            note = f"does not decode untrusted Brotli on tested paths ({', '.join(BROTLI_PROBE_PATHS)})"
        return 1, Finding(NAME, CVE, base, CLEAR, f"Node/Express detected ({fp}); {note}{waf_note}")

    if is_passthrough:
        return 1, Finding(NAME, CVE, base, CLEAR, f"{_PASS_THROUGH_NOTE}{waf_note}")

    return 1, Finding(NAME, CVE, base, CLEAR, f"not a Node/Bun/Brotli-decoding target ({fp}){waf_note}")


def scan(session: requests.Session, bases: list[str]) -> list[Finding]:
    best_score, best = -1, None
    for base in bases:
        score, finding = _evaluate(session, base)
        if score > best_score:
            best_score, best = score, finding
        if score >= 3:
            break
    return [best] if best else []
