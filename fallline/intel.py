"""Threat intelligence: CISA KEV (known exploited) and EPSS (exploit likelihood).

Data is cached locally. Nothing is downloaded unless `update()` is called
(explicitly, via `fallline intel update` or the dashboard button). If there is
no cache and no network, scoring simply runs without it and says so.
"""

from __future__ import annotations

import json
import time
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
CACHE_TTL_SECONDS = 24 * 3600

Fetcher = Callable[[str], str]


def _http_get(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "FallLine/0.1 (defensive tool)"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        return resp.read().decode("utf-8")


class Intel:
    def __init__(self, cache_path: str | Path = "data/intel_cache.json", fetcher: Fetcher | None = None):
        self.cache_path = Path(cache_path)
        self.fetcher = fetcher or _http_get
        self.kev: set[str] = set()
        self.epss: dict[str, float] = {}
        self.updated_at: float | None = None
        self._load_cache()

    # -- cache ------------------------------------------------------------
    def _load_cache(self) -> None:
        if not self.cache_path.exists():
            return
        try:
            data = json.loads(self.cache_path.read_text(encoding="utf-8"))
            self.kev = set(data.get("kev", []))
            self.epss = {k: float(v) for k, v in data.get("epss", {}).items()}
            self.updated_at = data.get("updated_at")
        except (OSError, ValueError):
            pass  # corrupt cache: behave as if there is none

    def _save_cache(self) -> None:
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.cache_path.write_text(
            json.dumps(
                {
                    "updated_at": self.updated_at,
                    "kev": sorted(self.kev),
                    "epss": self.epss,
                }
            ),
            encoding="utf-8",
        )

    @property
    def available(self) -> bool:
        return self.updated_at is not None

    def is_stale(self) -> bool:
        return self.updated_at is None or time.time() - self.updated_at > CACHE_TTL_SECONDS

    # -- network ----------------------------------------------------------
    def update(self, cves: list[str] | None = None) -> str:
        """Refresh KEV and EPSS. Returns a short status message; never raises."""
        try:
            kev_json = json.loads(self.fetcher(KEV_URL))
            self.kev = {v["cveID"] for v in kev_json.get("vulnerabilities", [])}
        except (OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
            return (
                f"offline: could not refresh KEV ({exc.__class__.__name__}); "
                f"using {'cached' if self.available else 'no'} data"
            )
        wanted = sorted({c for c in (cves or []) if c.upper().startswith("CVE-")})
        for i in range(0, len(wanted), 50):
            chunk = wanted[i : i + 50]
            url = EPSS_URL + "?" + urllib.parse.urlencode({"cve": ",".join(chunk)})
            try:
                for row in json.loads(self.fetcher(url)).get("data", []):
                    self.epss[row["cve"]] = float(row["epss"])
            except (OSError, ValueError, KeyError, TypeError, RuntimeError):
                return "partial: KEV refreshed, EPSS unavailable"
        self.updated_at = time.time()
        self._save_cache()
        return f"updated: {len(self.kev)} KEV entries, {len(self.epss)} EPSS scores"

    # -- scoring ----------------------------------------------------------
    def factor(self, cves: list[str]) -> tuple[float, list[str]]:
        """Multiplier for attacker effort (smaller = easier) plus notes.

        In KEV (exploited in the wild): effort x0.5.
        EPSS e in 0..1: effort x(1 - 0.5*e).
        """
        factor, notes = 1.0, []
        for cve in cves:
            if cve in self.kev:
                factor *= 0.5
                notes.append(f"{cve} is in CISA KEV (exploited in the wild)")
            if cve in self.epss:
                factor *= 1 - 0.5 * min(max(self.epss[cve], 0.0), 1.0)
                notes.append(f"{cve} EPSS {self.epss[cve]:.2f}")
        return max(factor, 0.1), notes
