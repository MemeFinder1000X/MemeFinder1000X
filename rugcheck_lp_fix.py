"""Read-only RugCheck fallback for Solana LP lock/burn evidence.

RugCheck's public token report/summary endpoints expose LP lock state even when
Birdeye token-security is unavailable. This patch only fills LP evidence; it
does not execute trades or replace the existing security scoring algorithm.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from security_intelligence import SecurityIntelligence

logger = logging.getLogger(__name__)
_BASE = "https://api.rugcheck.xyz"
_TIMEOUT = 10
_CACHE_SECONDS = 300
_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
_ORIGINAL_ANALYZE = SecurityIntelligence.analyze


def _unwrap(value: Any) -> Any:
    current = value
    for _ in range(4):
        if isinstance(current, dict) and isinstance(current.get("data"), (dict, list)):
            current = current["data"]
        else:
            break
    return current


def _request(path: str) -> Any:
    request = Request(
        f"{_BASE}{path}",
        headers={"Accept": "application/json", "User-Agent": "MemeFinder1000X/1.0"},
        method="GET",
    )
    with urlopen(request, timeout=_TIMEOUT) as response:
        return json.loads(response.read().decode("utf-8"))


def _load(token_address: str) -> dict[str, Any]:
    cached = _CACHE.get(token_address)
    if cached and time.monotonic() - cached[0] < _CACHE_SECONDS:
        return cached[1]

    result: dict[str, Any] = {}
    try:
        summary = _unwrap(_request(f"/v1/tokens/{token_address}/report/summary"))
        if isinstance(summary, dict):
            result["summary"] = summary
    except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
        result["summary_error"] = str(exc)

    try:
        lockers = _unwrap(_request(f"/v1/tokens/{token_address}/lockers"))
        if isinstance(lockers, dict):
            result["lockers"] = lockers
        elif isinstance(lockers, list):
            result["lockers"] = {"lockers": lockers}
    except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
        result["lockers_error"] = str(exc)

    _CACHE[token_address] = (time.monotonic(), result)
    return result


def _apply_lp(finding: Any, report: dict[str, Any]) -> None:
    summary = report.get("summary")
    if not isinstance(summary, dict):
        return

    locked = summary.get("lpLocked")
    locked_pct = summary.get("lpLockedPct")
    if isinstance(locked, bool):
        finding.lp_status = "LOCKED" if locked else "UNLOCKED"
        finding.evidence.append(
            f"RugCheck LP lock status: {'locked' if locked else 'not locked'}"
        )
    try:
        if locked_pct is not None:
            pct = float(locked_pct)
            if 0 <= pct <= 100:
                finding.evidence.append(f"RugCheck LP locked percentage: {pct:.1f}%")
                if pct > 0:
                    finding.lp_status = "LOCKED"
    except (TypeError, ValueError):
        pass

    if summary.get("lpBurned") is True or summary.get("lp_burned") is True:
        finding.lp_lock_burn = "BURNED"
        finding.lp_status = "LOCKED"
        finding.evidence.append("RugCheck reports LP tokens burned")
    elif finding.lp_status == "LOCKED":
        finding.lp_lock_burn = "LOCKED"


def _apply_lockers(finding: Any, report: dict[str, Any]) -> None:
    lockers = report.get("lockers")
    if not isinstance(lockers, dict):
        return
    rows = lockers.get("lockers")
    if not isinstance(rows, list):
        return
    active = []
    burned = False
    for row in rows:
        if not isinstance(row, dict):
            continue
        if str(row.get("type", "")).lower() == "burned" or row.get("burned") is True:
            burned = True
        if row.get("locked") is True:
            active.append(row)

    if burned:
        finding.lp_lock_burn = "BURNED"
        finding.lp_status = "LOCKED"
        finding.evidence.append("RugCheck locker data reports burned LP tokens")
    elif active:
        finding.lp_status = "LOCKED"
        finding.lp_lock_burn = "LOCKED"
        finding.evidence.append(f"RugCheck active LP lockers found: {len(active)}")
    elif rows and finding.lp_status == "UNKNOWN":
        finding.lp_status = "UNLOCKED"
        finding.lp_lock_burn = "UNLOCKED / NOT BURNED"
        finding.evidence.append("RugCheck found no active LP lockers")


async def _analyze_with_rugcheck(self: SecurityIntelligence, provider: Any, token_address: str, top10_hint: Any = None) -> Any:
    finding = await _ORIGINAL_ANALYZE(self, provider, token_address, top10_hint)
    if finding.lp_status != "UNKNOWN" and finding.lp_lock_burn != "UNKNOWN":
        return finding

    report = await asyncio.to_thread(_load, token_address)
    _apply_lp(finding, report)
    _apply_lockers(finding, report)

    if finding.lp_status != "UNKNOWN" or finding.lp_lock_burn != "UNKNOWN":
        finding.warnings = [
            warning
            for warning in finding.warnings
            if warning != "Birdeye token-security unavailable; LP checks remain unverified."
        ]
        finding.evidence.append("LP evidence sourced from RugCheck read-only API")
        finding.unknown = [item for item in finding.unknown if item != "LP lock/burn proof"]
    else:
        finding.evidence.append("RugCheck LP verification unavailable")
    return finding


SecurityIntelligence.analyze = _analyze_with_rugcheck
SecurityIntelligence._mf_rugcheck_lp_fix_installed = True
