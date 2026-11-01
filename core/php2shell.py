from __future__ import annotations

import re

import requests

from core import Finding, VULNERABLE, LIKELY, INCONCLUSIVE, CLEAR, ERROR
from core.waf import detect_waf, bypass_multipart_headers

NAME = "PHP2Shell"
CVE = "CVE-2026-109618 / CVE-2026-109619"
MENU_DESC = "CVE-2026-109618 / 109619  (PHP mod_php / PHP-FPM RCE)"

FIXED = {(8, 2): (8, 2, 35), (8, 3): (8, 3, 36), (8, 4): (8, 4, 27), (8, 5): (8, 5, 12)}
FIXED_STR = "8.5.12 / 8.4.27 / 8.3.36 / 8.2.35"

CVE_115560_NOTE = (
    " | Also check CVE-2026-115560 (no fix released; set session.upload_progress.enabled=0 "
    "in php.ini as interim mitigation regardless of patch status)"
)

_PHP_VER_RE = re.compile(r"php/(\d+)\.(\d+)\.(\d+)([^\s;,]*)", re.IGNORECASE)

_DRUPAL_HDR_RE = re.compile(r"\bDrupal\b", re.IGNORECASE)
_DRUPAL_EXPIRES = "Sun, 19 Nov 1978"
_DRUPAL_COOKIE_RE = re.compile(r"\bSS?ESS[0-9a-f]{32}\b")
_LITESPEED_HDR_RE = re.compile(r"LiteSpeed", re.IGNORECASE)
_SYMFONY_DBG_RE = re.compile(r"X-Debug-Token", re.IGNORECASE)
_WP_COOKIE_RE = re.compile(r"\bwordpress_[0-9a-f]{32}\b|\bwp-settings-\d+\b")
_FWSESSION_RE = re.compile(r"\b[a-z][a-z0-9_]{2,}_session\b")
_XSRF_TOKEN_RE = re.compile(r"\bXSRF-TOKEN\b")
_JOOMLA_COOKIE_RE = re.compile(r"\bjoomla_user_state\b", re.IGNORECASE)
_CI_COOKIE_RE = re.compile(r"\bci[_]?4?_session\b", re.IGNORECASE)
_OPENCART_COOKIE_RE = re.compile(r"\bOCSESSID\b")
_PRESTASHOP_COOKIE_RE = re.compile(r"\bPrestaShop-[0-9a-f]{32}\b")
_MOODLE_COOKIE_RE = re.compile(r"\bMoodleSession")
_CAKEPHP_COOKIE_RE = re.compile(r"\bCAKEPHP\b")
_PHP_ERR_RE = re.compile(r"PHP (?:Fatal error|Warning|Notice|Parse error):", re.IGNORECASE)
_WP_BODY_RE = re.compile(r'<meta\s+name=["\']generator["\'][^>]+WordPress', re.IGNORECASE)
_DRUPAL_BODY_RE = re.compile(r'<meta\s+name=["\']generator["\'][^>]+Drupal', re.IGNORECASE)
_PHP_FPM_BODY = "File not found."

ENTRY_PATHS = (
    "/index.php",
    "/",
    "/wp-login.php",
    "/xmlrpc.php",
    "/app.php",
    "/public/index.php",
    "/wp-admin/admin-ajax.php",
    "/api/index.php",
    "/contact.php",
    "/upload.php",
)

MIB = 1024 * 1024
PROBE_PART_COUNTS = (2000, 12000, 50000)
NEST_DEPTH = 24
MAX_PROBE_BYTES = 6 * MIB
BOUNDARY = "s2sCVE2026109618"
BYPASS_BOUNDARY = "b0undary09618x"

FATAL_SIGNATURES = (
    "allowed memory size of",
    "tried to allocate",
    "out of memory",
    "php fatal error",
)
BLOCKED_CODES = {400, 403, 405, 413, 414, 431, 501}
_NO_ENDPOINT_CODES = {404, 405, 410}


def _get(session: requests.Session, url: str) -> requests.Response | None:
    try:
        return session.get(url, timeout=session.timeout, verify=session.verify,
                           allow_redirects=True)
    except requests.RequestException:
        return None


def _fingerprint(session: requests.Session, base: str):
    version, suffix, evidence, status = None, "", [], None
    reachable = False
    for path in ("", "/index.php", "/lib/upgrade.txt"):
        r = _get(session, base + path)
        if r is None:
            if not reachable:
                break
            continue
        reachable = True
        if status is None:
            status = r.status_code

        blob = f"{r.headers.get('X-Powered-By', '')} {r.headers.get('Server', '')}"
        m = _PHP_VER_RE.search(blob)
        if m and version is None:
            version = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
            suffix = m.group(4)
            evidence.append(f"PHP {'.'.join(map(str, version))}{suffix}")

        powered = r.headers.get("X-Powered-By", "")
        if "php" in powered.lower() and not m and f"X-Powered-By: {powered}" not in evidence:
            evidence.append(f"X-Powered-By: {powered}")

        if _DRUPAL_HDR_RE.search(r.headers.get("X-Generator", "")):
            _add(evidence, "X-Generator: Drupal")
        if r.headers.get("X-Drupal-Cache") and "X-Drupal-Cache" not in evidence:
            _add(evidence, "X-Drupal-Cache header (Drupal)")
        if _LITESPEED_HDR_RE.search(r.headers.get("X-LiteSpeed-Cache", "")) or \
                _LITESPEED_HDR_RE.search(r.headers.get("X-Turbo-Charged-By", "")):
            _add(evidence, "LiteSpeed header")
        if _SYMFONY_DBG_RE.search(" ".join(r.headers.keys())):
            _add(evidence, "Symfony X-Debug-Token header")
        if _DRUPAL_EXPIRES in r.headers.get("Expires", ""):
            _add(evidence, "Drupal Expires fingerprint")

        cookie_keys = " ".join(list(r.cookies.keys()) + list(session.cookies.keys()))
        cookie_lower = cookie_keys.lower()
        if "phpsessid" in cookie_lower and "PHPSESSID cookie" not in evidence:
            _add(evidence, "PHPSESSID cookie")
        if _DRUPAL_COOKIE_RE.search(cookie_keys):
            _add(evidence, "Drupal session cookie (SESS/SSESS)")
        if _WP_COOKIE_RE.search(cookie_keys):
            _add(evidence, "WordPress cookie")
        if _JOOMLA_COOKIE_RE.search(cookie_keys):
            _add(evidence, "Joomla cookie (joomla_user_state)")
        if _CI_COOKIE_RE.search(cookie_lower):
            _add(evidence, "CodeIgniter session cookie")
        if _XSRF_TOKEN_RE.search(cookie_keys):
            _add(evidence, "XSRF-TOKEN cookie (Laravel)")
        if _OPENCART_COOKIE_RE.search(cookie_keys):
            _add(evidence, "OCSESSID cookie (OpenCart)")
        if _PRESTASHOP_COOKIE_RE.search(cookie_keys):
            _add(evidence, "PrestaShop session cookie")
        if _MOODLE_COOKIE_RE.search(cookie_keys):
            _add(evidence, "MoodleSession cookie")
        if _CAKEPHP_COOKIE_RE.search(cookie_keys):
            _add(evidence, "CAKEPHP cookie (CakePHP <=3)")
        if _FWSESSION_RE.search(cookie_lower) and not any(
            x in evidence for x in (
                "WordPress cookie", "CodeIgniter session cookie",
                "Joomla cookie (joomla_user_state)", "XSRF-TOKEN cookie (Laravel)",
            )
        ):
            _add(evidence, "framework *_session cookie")

        body = r.text or ""
        if _PHP_ERR_RE.search(body):
            _add(evidence, "PHP error in response body")
        if _PHP_FPM_BODY in body and len(body.strip()) < 64:
            _add(evidence, "PHP-FPM bare error (File not found.)")
        if _WP_BODY_RE.search(body):
            _add(evidence, "WordPress generator meta")
        if _DRUPAL_BODY_RE.search(body):
            _add(evidence, "Drupal generator meta")
        if path == "/lib/upgrade.txt" and r.status_code == 200 and "moodle" in body.lower()[:512]:
            _add(evidence, "Moodle /lib/upgrade.txt")

    return reachable, version, suffix, evidence, status


def _add(lst: list[str], item: str) -> None:
    if item not in lst:
        lst.append(item)


def _version_verdict(version):
    branch = version[:2]
    if branch in FIXED:
        return "vulnerable" if version < FIXED[branch] else "patched"
    if branch < (8, 2):
        return "vulnerable"
    return None


def _multipart_headers(boundary: str, extra: dict[str, str] | None = None) -> dict[str, str]:
    h = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    if extra:
        h.update(extra)
    return h


def _control_body(boundary: str = BOUNDARY) -> bytes:
    return (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="probe"\r\n\r\n'
        "1\r\n"
        f"--{boundary}--\r\n"
    ).encode()


def _probe_body(part_count: int, boundary: str = BOUNDARY) -> bytes:
    nesting = "[a]" * NEST_DEPTH
    parts: list[str] = []
    total = 0
    for i in range(part_count):
        part = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="p[{i}]{nesting}"\r\n\r\n'
            "1\r\n"
        )
        parts.append(part)
        total += len(part)
        if total >= MAX_PROBE_BYTES:
            break
    parts.append(f"--{boundary}--\r\n")
    return "".join(parts).encode()


def _post(session: requests.Session, url: str, body: bytes,
          boundary: str = BOUNDARY,
          extra_headers: dict[str, str] | None = None) -> requests.Response | None:
    return _post_ex(session, url, body, boundary, extra_headers)[0]


def _post_ex(session: requests.Session, url: str, body: bytes,
             boundary: str = BOUNDARY,
             extra_headers: dict[str, str] | None = None) -> tuple[requests.Response | None, str]:
    headers = _multipart_headers(boundary, extra_headers)
    try:
        resp = session.post(url, data=body, headers=headers, timeout=session.timeout,
                            verify=session.verify, allow_redirects=False)
        return resp, "ok"
    except requests.Timeout:
        return None, "timeout"
    except requests.RequestException:
        return None, "error"


def _has_fatal(text: str) -> bool:
    low = text.lower()
    return any(sig in low for sig in FATAL_SIGNATURES)


def _drop_word(kind: str) -> str:
    return "timed out" if kind == "timeout" else "dropped the connection"


def _find_probe_url(session: requests.Session, base: str) -> tuple[str | None, requests.Response | None, str | None]:
    for path in ENTRY_PATHS:
        url = base.rstrip("/") + path
        ctrl = _post(session, url, _control_body())
        if ctrl is None:
            continue
        if ctrl.status_code in _NO_ENDPOINT_CODES:
            continue
        waf = detect_waf(ctrl)
        if ctrl.status_code in BLOCKED_CODES:
            bypass_hdrs = bypass_multipart_headers(BYPASS_BOUNDARY)
            ctrl2 = _post(session, url, _control_body(BYPASS_BOUNDARY),
                          boundary=BYPASS_BOUNDARY, extra_headers=bypass_hdrs)
            if ctrl2 is not None and ctrl2.status_code not in BLOCKED_CODES and \
               ctrl2.status_code not in _NO_ENDPOINT_CODES:
                return url, ctrl2, waf
            continue
        return url, ctrl, waf
    return None, None, None


def _active_check(session: requests.Session, url: str,
                  pre_control: requests.Response,
                  boundary: str = BOUNDARY):
    control = pre_control
    if control.status_code >= 500:
        return "control_5xx", (f"control multipart POST already returned HTTP "
                               f"{control.status_code}; baseline unreliable"), control.status_code

    for count in PROBE_PART_COUNTS:
        probe, kind = _post_ex(session, url, _probe_body(count, boundary), boundary=boundary)
        if probe is None:
            recheck = _post(session, url, _control_body(boundary), boundary=boundary)
            if recheck is None:
                return "probe_inconclusive", (f"a {count:,}-part nested-array probe {_drop_word(kind)} and a "
                                              "follow-up control POST also failed — host became unreachable "
                                              "mid-scan, cannot run the active check"), control.status_code
            if kind == "timeout":
                return "probe_inconclusive", (f"a {count:,}-part nested-array probe timed out while the control "
                                              "POST succeeded — the body may exceed a server upload/time limit "
                                              "on this link; cannot confirm a worker crash"), control.status_code
            return "probe_inconclusive", (f"a {count:,}-part nested-array probe dropped the connection while "
                                          "control POSTs before and after it succeeded — a possible worker "
                                          "crash, but a size-limit connection reset cannot be excluded"), control.status_code
        text = probe.text or ""
        if _has_fatal(text):
            return "fatal", (f"a {count:,}-part nested-array probe (small body) forced a PHP "
                             "memory fatal the control did not"), probe.status_code
        if (probe.status_code == 500 and not text.strip()
                and control.status_code < 500
                and control.status_code not in _NO_ENDPOINT_CODES):
            return "empty_500", (f"a {count:,}-part nested-array probe returned an empty HTTP 500 "
                                 f"the control (HTTP {control.status_code}) did not"), probe.status_code
        if probe.status_code in BLOCKED_CODES:
            bypass_hdrs = bypass_multipart_headers(BYPASS_BOUNDARY)
            probe2 = _post(session, url, _probe_body(count, BYPASS_BOUNDARY),
                           boundary=BYPASS_BOUNDARY, extra_headers=bypass_hdrs)
            if probe2 is not None:
                text2 = probe2.text or ""
                if _has_fatal(text2):
                    return "fatal", (f"a {count:,}-part nested-array probe forced a PHP memory fatal "
                                     "after WAF bypass"), probe2.status_code
                if (probe2.status_code == 500 and not text2.strip()
                        and control.status_code < 500):
                    return "empty_500", (f"a {count:,}-part nested-array probe returned empty HTTP 500 "
                                         "after WAF bypass"), probe2.status_code
            return "blocked", (f"nested-array probe rejected with HTTP {probe.status_code} "
                               "(a parts/size limit — patched build or WAF)"), probe.status_code

    return "clear", ("escalating nested-array probes were handled cleanly, as a patched "
                     "parser would"), control.status_code


def _with_115(detail: str, php_confirmed: bool) -> str:
    return detail + CVE_115560_NOTE if php_confirmed else detail


def _evaluate(session: requests.Session, base: str) -> tuple[int, Finding]:
    reachable, version, suffix, evidence, status = _fingerprint(session, base)
    if not reachable:
        return 0, Finding(NAME, CVE, base, ERROR, "host unreachable over this scheme")

    ver_str = f"{'.'.join(map(str, version))}{suffix}" if version else None
    vstate = _version_verdict(version) if version else None
    fp_php = bool(version or evidence)

    if vstate == "patched":
        return 2, Finding(NAME, CVE, base, CLEAR,
                          _with_115(f"patched PHP {ver_str} (>= fixed release {FIXED_STR}) — not affected", fp_php),
                          status)
    if vstate == "vulnerable" and not suffix:
        return 4, Finding(NAME, CVE, base, VULNERABLE,
                          _with_115(f"vulnerable PHP {ver_str} advertised (fixed: {FIXED_STR})", fp_php), status)

    probe_url, ctrl_resp, waf = _find_probe_url(session, base)
    waf_note = f" [WAF: {waf} detected]" if waf else ""
    php_confirmed = fp_php or (probe_url is not None)

    if probe_url is None:
        if vstate == "vulnerable":
            return 3, Finding(NAME, CVE, base, LIKELY,
                              _with_115(f"distro PHP {ver_str} is below the upstream fix ({FIXED_STR}) and "
                                        f"no PHP entry point accepted a probe POST{waf_note}; confirm with `php -v`",
                                        php_confirmed),
                              status)
        if evidence:
            return 1, Finding(NAME, CVE, base, CLEAR,
                              _with_115(f"PHP detected ({'; '.join(evidence)}) but no entry point accepted "
                                        f"a probe POST{waf_note} — cannot run active check", php_confirmed), status)
        return 1, Finding(NAME, CVE, base, CLEAR, f"no PHP indicators found{waf_note}", status)

    used_boundary = BYPASS_BOUNDARY if waf else BOUNDARY
    state, detail, pstatus = _active_check(session, probe_url, pre_control=ctrl_resp,
                                           boundary=used_boundary)
    probe_status = pstatus if pstatus is not None else status
    ver_note = f" (reported PHP {ver_str}, below the fix)" if vstate == "vulnerable" else ""

    if state in ("fatal", "empty_500"):
        return 4, Finding(NAME, CVE, base, VULNERABLE,
                          _with_115(f"{detail}{ver_note}{waf_note} — the vulnerable nested-array parser "
                                    f"(fixed: {FIXED_STR})", php_confirmed), probe_status)
    if state in ("blocked", "probe_inconclusive"):
        verdict = LIKELY if vstate == "vulnerable" else INCONCLUSIVE
        return (3 if verdict == LIKELY else 2), Finding(NAME, CVE, base, verdict,
                          _with_115(f"{detail}{ver_note}{waf_note}; confirm the PHP patch level on the host "
                                    f"(fixed: {FIXED_STR})", php_confirmed), probe_status)
    if state == "control_5xx":
        return 2, Finding(NAME, CVE, base, INCONCLUSIVE,
                          _with_115(f"{detail}{waf_note}; confirm with `php -v` (fixed: {FIXED_STR})",
                                    php_confirmed), probe_status)

    if vstate == "vulnerable":
        return 2, Finding(NAME, CVE, base, CLEAR,
                          _with_115(f"distro PHP {ver_str} is below the upstream fix but {detail} — a "
                                    f"backported patch is handling it{waf_note}", php_confirmed), probe_status)
    if evidence:
        return 2, Finding(NAME, CVE, base, CLEAR,
                          _with_115(f"PHP detected ({'; '.join(evidence)}) and {detail}{waf_note}",
                                    php_confirmed), probe_status)
    return 1, Finding(NAME, CVE, base, CLEAR,
                      _with_115(f"no PHP indicators and {detail}{waf_note}", php_confirmed), probe_status)


def scan(session: requests.Session, bases: list[str]) -> list[Finding]:
    best_score, best = -1, None
    for base in bases:
        score, finding = _evaluate(session, base)
        if score > best_score:
            best_score, best = score, finding
        if score >= 3:
            break
    return [best] if best else []
