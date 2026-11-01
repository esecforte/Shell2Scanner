from __future__ import annotations

import re

import requests

_WAF_HEADER_KEYS: dict[str, str] = {
    "cf-ray": "Cloudflare",
    "x-iinfo": "Imperva",
    "x-cdn": "Imperva",
    "x-amzn-requestid": "AWS WAF",
    "x-amzn-trace-id": "AWS WAF",
    "x-akamai-request-id": "Akamai",
    "x-check-cacheable": "Akamai",
    "x-wa-info": "F5 BIG-IP",
    "x-sucuri-id": "Sucuri",
    "x-datadome-cid": "DataDome",
    "x-kong-proxy-latency": "Kong",
}

_WAF_SERVER_RE: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bcloudflare\b", re.I), "Cloudflare"),
    (re.compile(r"\bincapsula\b", re.I), "Imperva"),
    (re.compile(r"mod_security|modsec", re.I), "ModSecurity"),
    (re.compile(r"\bbig.?ip\b", re.I), "F5 BIG-IP"),
    (re.compile(r"\bbarracuda\b", re.I), "Barracuda"),
    (re.compile(r"fortigate|fortiwaf", re.I), "FortiWeb"),
    (re.compile(r"\benvoy\b", re.I), "Envoy"),
]

_WAF_COOKIE_RE: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"visid_incap|incap_ses", re.I), "Imperva"),
    (re.compile(r"bni__", re.I), "Barracuda"),
    (re.compile(r"cf_clearance|__cfduid", re.I), "Cloudflare"),
    (re.compile(r"^ak_bmsc$", re.I), "Akamai"),
    (re.compile(r"datadome", re.I), "DataDome"),
]


def detect_waf(response: requests.Response) -> str | None:
    headers_lower = {k.lower(): v for k, v in response.headers.items()}

    for hkey, name in _WAF_HEADER_KEYS.items():
        if hkey in headers_lower:
            return name

    for field in ("server", "via", "x-powered-by"):
        val = headers_lower.get(field, "")
        for pattern, name in _WAF_SERVER_RE:
            if pattern.search(val):
                return name

    cookie_str = " ".join(response.cookies.keys())
    for pattern, name in _WAF_COOKIE_RE:
        if pattern.search(cookie_str):
            return name

    return None


def bypass_multipart_headers(boundary: str) -> dict[str, str]:
    return {
        "Content-Type": f"multipart/form-data ;\tboundary={boundary}",
        "Transfer-Encoding": "chunked",
        "X-Forwarded-For": "127.0.0.1",
    }


def bypass_brotli_headers(base_headers: dict[str, str]) -> dict[str, str]:
    out = dict(base_headers)
    out["Content-Encoding"] = "br"
    out["Transfer-Encoding"] = "chunked"
    out["X-Forwarded-For"] = "127.0.0.1"
    return out
