from __future__ import annotations

from dataclasses import dataclass

__version__ = "1.1.0"

AUTHOR = "eSecForte"
WEBSITE = "https://esecforte.com"

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 shell2scan/1.1.0"
)

VULNERABLE = "vulnerable"
LIKELY = "likely"
INCONCLUSIVE = "inconclusive"
CLEAR = "not-detected"
ERROR = "error"


@dataclass
class Finding:
    module: str
    cve: str
    url: str
    verdict: str
    detail: str
    status: int | None = None


__all__ = [
    "Finding", "__version__", "AUTHOR", "WEBSITE", "USER_AGENT",
    "VULNERABLE", "LIKELY", "INCONCLUSIVE", "CLEAR", "ERROR",
]
