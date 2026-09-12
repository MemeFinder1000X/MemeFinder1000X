"""Stabilize Birdeye holder enrichment without changing scoring.

The scanner is read-only. This patch prevents transiently incomplete holder
responses from being cached for five minutes and derives holder count from
actual holder/distribution rows when an explicit total is absent.
"""
from __future__ import annotations

import time
from typing import Any

from birdeye_provider import BirdeyeProvider


_ORIGINAL_ANALYZE_TOKEN = BirdeyeProvider.analyze_token


def _holder_row_count(value: Any) -> int | None:
    """Return a holder count only from explicit count fields or holder rows."""
    if isinstance(value, dict):
        for key in ("holderCount", "holder_count", "totalHolders", "total_holders", "wallet_count", "total"):
            raw = value.get(key)
            try:
                number = int(float(raw))
            except (TypeError, ValueError):
                continue
            if number >= 0:
                return number
        for key in ("items", "holders", "list"):
            rows = value.get(key)
            if isinstance(rows, list):
                return len(rows)
        for child in value.values():
            found = _holder_row_count(child)
            if found is not None:
                return found
    elif isinstance(value, list):
        return len(value)
    return None


def _holder_count_from_snapshot(provider: BirdeyeProvider, snapshot: Any) -> int | None:
    if not hasattr(snapshot, "data") or not isinstance(snapshot.data, dict):
        return None
    for name in ("token_holders", "holder_profile", "holder_distribution"):
        found = _holder_row_count(snapshot.data.get(name))
        if found is not None:
            return found
    return None


async def _analyze_token_without_partial_cache(self: BirdeyeProvider, token_address: str) -> Any:
    """Use the normal enrichment, but don't cache snapshots missing holder data."""
    snapshot = await _ORIGINAL_ANALYZE_TOKEN(self, token_address)
    required = {"holder_profile", "holder_distribution"}
    available = set(getattr(snapshot, "available_endpoints", []))
    if not required.issubset(available):
        async with self._cache_lock:
            self._snapshot_cache.pop(token_address, None)
    return snapshot


# Replace only the snapshot method. All endpoint behavior and scoring remain unchanged.
BirdeyeProvider.analyze_token = _analyze_token_without_partial_cache


_ORIGINAL_RISK_EVIDENCE = BirdeyeProvider.risk_evidence


def _risk_evidence_with_row_count(self: BirdeyeProvider, snapshot: Any) -> Any:
    evidence = _ORIGINAL_RISK_EVIDENCE(self, snapshot)
    if getattr(evidence, "holder_count", None) is None:
        count = _holder_count_from_snapshot(self, snapshot)
        if count is not None:
            evidence.holder_count = count
            evidence.unknown = [item for item in evidence.unknown if item != "holder count"]
            evidence.evidence.append(f"Birdeye holder rows observed: {count}")
    return evidence


BirdeyeProvider.risk_evidence = _risk_evidence_with_row_count
BirdeyeProvider._mf_holder_consistency_fix_installed = True
