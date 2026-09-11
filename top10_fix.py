"""Safer Top-10 holder concentration extraction for Birdeye distribution data."""
from __future__ import annotations

from typing import Any

from birdeye_provider import BirdeyeProvider


def _unwrap(value: Any) -> Any:
    current = value
    for _ in range(4):
        if isinstance(current, dict) and isinstance(current.get("data"), (dict, list)):
            current = current["data"]
        else:
            break
    return current


def _percent(value: Any) -> float | None:
    if isinstance(value, dict):
        value = next((value.get(k) for k in ("percent_of_supply", "percentOfSupply") if value.get(k) is not None), None)
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if number < 0:
        return None
    if number <= 1:
        number *= 100
    return number if number <= 100 else None


def _sum_top10_items(source: Any) -> float | None:
    """Sum the actual per-wallet supply percentages when a holder list exists."""
    source = _unwrap(source)

    def walk(node: Any) -> float | None:
        if isinstance(node, dict):
            for key in ("items", "holders", "list"):
                value = node.get(key)
                if isinstance(value, list):
                    percentages: list[float] = []
                    for item in value[:10]:
                        if not isinstance(item, dict):
                            continue
                        parsed = _percent(item)
                        if parsed is None:
                            parsed = _percent(item.get("percent_of_supply"))
                        if parsed is not None:
                            percentages.append(parsed)
                    if percentages:
                        return min(100.0, sum(percentages))
            for value in node.values():
                found = walk(value)
                if found is not None:
                    return found
        elif isinstance(node, list):
            percentages: list[float] = []
            for item in node[:10]:
                if not isinstance(item, dict):
                    continue
                parsed = _percent(item)
                if parsed is not None:
                    percentages.append(parsed)
            if percentages:
                return min(100.0, sum(percentages))
            for value in node:
                found = walk(value)
                if found is not None:
                    return found
        return None

    return walk(source)


def _strict_top10(cls: type[BirdeyeProvider], source: Any) -> float | None:
    """Prefer actual top-wallet percentages; only then use explicit aggregate fields."""
    summed = _sum_top10_items(source)
    if summed is not None:
        return summed

    source = _unwrap(source)
    if not isinstance(source, (dict, list)):
        return None

    exact_keys = (
        "top10_holder",
        "top10Holder",
        "top10_holder_percent",
        "top10HolderPercent",
        "top10_holder_percentage",
        "top10HolderPercentage",
    )

    def walk(node: Any) -> float | None:
        if isinstance(node, dict):
            for key in exact_keys:
                if key in node:
                    parsed = _percent(node[key])
                    if parsed is not None:
                        return parsed
            for key in ("summary", "holder_summary"):
                value = node.get(key)
                if isinstance(value, dict):
                    parsed = walk(value)
                    if parsed is not None:
                        return parsed
            for value in node.values():
                parsed = walk(value)
                if parsed is not None:
                    return parsed
        elif isinstance(node, list):
            for value in node:
                parsed = walk(value)
                if parsed is not None:
                    return parsed
        return None

    return walk(source)


_original_holder_distribution = BirdeyeProvider.holder_distribution


async def _holder_distribution_with_items(self: BirdeyeProvider, token_address: str) -> Any:
    """Request the actual top-holder items so concentration can be independently summed."""
    async with self._cache_lock:
        cached = self._holder_distribution_cache.get(token_address)
        if cached:
            import time
            if time.monotonic() - cached[0] < 300:
                return cached[1]
    data = await self._get(
        "/holder/v1/distribution",
        {
            "token_address": token_address,
            "address_type": "wallet",
            "mode": "top",
            "top_n": 10,
            "include_list": "true",
            "limit": 10,
        },
    )
    async with self._cache_lock:
        import time
        self._holder_distribution_cache[token_address] = (time.monotonic(), data)
    return data


BirdeyeProvider._extract_top10_percent = classmethod(_strict_top10)
BirdeyeProvider.holder_distribution = _holder_distribution_with_items
BirdeyeProvider._mf_top10_fix_installed = True
