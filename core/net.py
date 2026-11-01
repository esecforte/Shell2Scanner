from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3.exceptions import InsecureRequestWarning
import urllib3

from core import USER_AGENT

urllib3.disable_warnings(InsecureRequestWarning)

_HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*$")


def normalize_target(raw: str) -> str:
    raw = raw.strip()
    if "://" in raw:
        parsed = urlparse(raw)
        raw = parsed.netloc or parsed.path
    host = raw.strip("/").split("/")[0]

    bracketed = host.startswith("[")
    bare_ipv6 = False
    if bracketed:
        hostonly = host[1:].split("]")[0]
    elif host.count(":") > 1:
        hostonly = host
        bare_ipv6 = True
    elif host.count(":") == 1:
        hostonly = host.rsplit(":", 1)[0]
    else:
        hostonly = host

    try:
        ipaddress.ip_address(hostonly)
        if bare_ipv6:
            return f"[{hostonly}]"
        return host
    except ValueError:
        pass

    if _HOST_RE.match(hostonly):
        return host
    raise ValueError(f"'{raw}' is not a valid domain, IP, or URL.")


def split_host_port(target: str) -> tuple[str, int | None]:
    if target.startswith("["):
        host, sep, rest = target[1:].partition("]")
        if sep:
            port = rest[1:] if rest.startswith(":") else ""
            return host, int(port) if port.isdigit() else None
        return target, None
    if target.count(":") > 1:
        return target, None
    host, sep, port = target.partition(":")
    if sep and port.isdigit():
        return host, int(port)
    return target, None


def join_host_port(host: str, port: int) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def base_urls(target: str, scheme: str | None) -> list[str]:
    if scheme in ("http", "https"):
        return [f"{scheme}://{target}"]
    return [f"https://{target}", f"http://{target}"]


class _TimeoutHTTPAdapter(HTTPAdapter):
    def __init__(self, *args, timeout: float | None = None, **kwargs):
        self._timeout = timeout
        super().__init__(*args, **kwargs)

    def send(self, request, **kwargs):
        if kwargs.get("timeout") is None:
            kwargs["timeout"] = self._timeout
        return super().send(request, **kwargs)


def session(timeout: float, verify_tls: bool) -> requests.Session:
    s = requests.Session()
    retry = Retry(total=1, connect=0, read=0, redirect=0, status=1,
                  status_forcelist=[502, 503, 504], backoff_factor=0.3,
                  raise_on_status=False)
    adapter = _TimeoutHTTPAdapter(max_retries=retry, timeout=timeout)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update({"User-Agent": USER_AGENT})
    s.verify = verify_tls
    s.timeout = timeout
    return s
