"""Stabilize Birdeye holder enrichment without changing scoring.

The scanner is read-only. This patch prevents transiently incomplete holder
responses from being cached for five minutes and derives holder count only
from actual total-holder fields, never from the top-holder distribution rows.
"""
from __future__ import annotations

from typing import Any

from birdeye_provider import BirdeyeProvider


_ORIGINAL_ANALYZE_TOKEN = BirdeyeProvider.analyze_token


def _explicit_holder_count(value: Any) -> int | None:
    """Return only explicit total-holder fields from a provider payload."""
    if isinstance(value, dict):
        for key in ("holderCount", "holder_count", "totalHolders", "total_holders", "wallet_count", "total"):
            raw = value.get(key)
            try:
                number = int(float(raw))
            except (TypeError, ValueError):
                continue
            if number >= 0:
                return number
        for child in value.values():
            found = _explicit_holder_count(child)
            if found is not None:
                return found
    return None


def _holder_count_from_snapshot(snapshot: Any) -> int | None:
    if not hasattr(snapshot, "data") or not isinstance(snapshot.data, dict):
        return None
    # The holder endpoint is the source for total holder count. Do not infer
    # count from holder_distribution: that payload intentionally contains only
    # the selected top-N wallets.
    return _explicit_holder_count(snapshot.data.get("token_holders"))


async def _analyze_token_without_partial_cache(self: BirdeyeProvider, token_address: str) -> Any:
    """Use normal enrichment, but don't cache snapshots missing holder data."""
    snapshot = await _ORIGINAL_ANALYZE_TOKEN(self, token_address)
    required = {"holder_profile", "holder_distribution"}
    available = set(getattr(snapshot, "available_endpoints", []))
    if not required.issubset(available):
        async with self._cache_lock:
            self._snapshot_cache.pop(token_address, None)
    return snapshot


BirdeyeProvider.analyze_token = _analyze_token_without_partial_cache


_ORIGINAL_RISK_EVIDENCE = BirdeyeProvider.risk_evidence


def _risk_evidence_with_explicit_count(self: BirdeyeProvider, snapshot: Any) -> Any:
    evidence = _ORIGINAL_RISK_EVIDENCE(self, snapshot)
    if getattr(evidence, "holder_count", None) is None:
        count = _holder_count_from_snapshot(snapshot)
        if count is not None:
            evidence.holder_count = count
            evidence.unknown = [item for item in evidence.unknown if item != "holder count"]
            evidence.evidence.append(f"Birdeye holder count: {count}")
    return evidence


BirdeyeProvider.risk_evidence = _risk_evidence_with_explicit_count
BirdeyeProvider._mf_holder_consistency_fix_installed = True
