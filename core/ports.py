from __future__ import annotations

import concurrent.futures
import socket
from typing import Callable

DEFAULT_WEB_PORTS = [
    80, 81, 82, 83, 84, 85, 88, 300, 443, 444, 591, 593, 832, 888, 981,
    1311, 2082, 2083, 2086, 2087, 2095, 2096, 2480,
    3000, 3128, 3333, 4000, 4040, 4200, 4443, 4567, 4993,
    5000, 5104, 5443, 5555, 5601, 5800, 5984,
    6080, 6443, 6543, 7000, 7001, 7070, 7080, 7396, 7474, 7777,
    8000, 8001, 8008, 8009, 8014, 8042, 8060, 8069, 8080, 8081, 8083,
    8085, 8088, 8089, 8090, 8091, 8095, 8118, 8123, 8172, 8180, 8181,
    8200, 8222, 8243, 8280, 8281, 8333, 8443, 8500, 8530, 8531, 8686,
    8800, 8834, 8880, 8888, 8983,
    9000, 9001, 9002, 9043, 9060, 9080, 9090, 9091, 9200, 9443, 9800,
    9981, 9999, 10000, 10443, 11371, 12443, 16080, 18080, 18091, 18092,
    20720, 28017, 55440, 55672,
]

HTTPS_HINT_PORTS = {
    443, 444, 832, 981, 1311, 2083, 2087, 2096, 4443, 5443, 6443,
    8243, 8333, 8443, 8531, 8834, 9443, 10443, 11371, 12443,
}

HTTP_HINT_PORTS = {
    80, 81, 82, 83, 84, 85, 88, 300, 591, 593, 888, 2082, 2086, 2095,
    2480, 3000, 3128, 3333, 4000, 4040, 4200, 4567, 4993, 5000, 5104,
    5555, 5601, 5800, 5984, 6080, 6543, 7000, 7001, 7070, 7080, 7396,
    7474, 7777, 8000, 8001, 8008, 8009, 8014, 8042, 8060, 8069, 8080,
    8081, 8083, 8085, 8088, 8089, 8090, 8091, 8095, 8118, 8123, 8172,
    8180, 8181, 8200, 8222, 8280, 8281, 8500, 8530, 8686, 8800, 8880,
    8888, 8983, 9000, 9001, 9002, 9043, 9060, 9080, 9090, 9091, 9200,
    9800, 9981, 9999, 10000, 16080, 18080, 18091, 18092, 20720, 28017,
    55440, 55672,
}


def parse_ports(spec: str) -> list[int]:
    spec = spec.strip().lower()
    if spec == "all":
        return list(range(1, 65536))
    if not spec:
        raise ValueError("empty port specification")

    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                lo_s, hi_s = part.split("-", 1)
                lo, hi = int(lo_s), int(hi_s)
                if lo > hi:
                    lo, hi = hi, lo
                ports.update(range(lo, hi + 1))
            else:
                ports.add(int(part))
        except ValueError:
            raise ValueError(f"invalid port token: '{part}'") from None

    bad = [p for p in ports if not 1 <= p <= 65535]
    if bad:
        raise ValueError(f"port(s) out of range 1-65535: {sorted(bad)[:5]}")
    return sorted(ports)


def scheme_for_port(port: int) -> str | None:
    if port in HTTPS_HINT_PORTS:
        return "https"
    if port in HTTP_HINT_PORTS:
        return "http"
    return None


def _is_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def scan_ports(host: str, ports: list[int], timeout: float = 1.0,
               workers: int = 100,
               on_progress: Callable[[int, int, int], None] | None = None) -> list[int]:
    if not ports:
        return []
    if timeout <= 0:
        timeout = 1.0
    open_ports: list[int] = []
    total = len(ports)
    done = 0
    max_workers = max(1, min(workers, total))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_is_open, host, p, timeout): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            done += 1
            try:
                if fut.result():
                    open_ports.append(futures[fut])
            except Exception:
                pass
            if on_progress:
                on_progress(done, total, len(open_ports))
    return sorted(open_ports)
