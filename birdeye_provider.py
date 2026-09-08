"""Read-only Birdeye Data Services client.

This module is deliberately independent from the Telegram handlers. It uses
only documented read-only endpoints, never signs transactions, and never logs
the API key or response bodies that might contain sensitive wallet data.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)
BIRDEYE_API = "https://public-api.birdeye.so"
BIRDEYE_API_BASE_URL_ENV = "BIRDEYE_API_BASE_URL"
BIRDEYE_API_KEY_ENV = "BIRDEYE_API_KEY"
BIRDEYE_CHAIN = "solana"
BIRDEYE_TIMEOUT_SECONDS = 12
BIRDEYE_MAX_RETRIES = 3
BIRDEYE_REQUEST_INTERVAL_SECONDS = 1.05
SNAPSHOT_CACHE_SECONDS = 300
WALLET_PNL_CACHE_SECONDS = 300
WALLET_PNL_DETAILS_CACHE_SECONDS = 300
DEFAULT_TOKEN_ENDPOINTS = (
    ("token_creation_info", "/defi/token_creation_info"),
    ("token_security", "/defi/token_security"),
    ("token_holders", "/defi/v3/token/holder"),
    ("liquidity_history", "/defi/v3/liquidity/history/token"),
    ("first_buyers", "/token/v1/first-buyers"),
    ("top_traders", "/defi/v2/tokens/top_traders"),
)


class BirdeyeError(Exception):
    """Raised for an unavailable or invalid Birdeye response."""


@dataclass
class BirdeyeSnapshot:
    token_address: str
    data: dict[str, Any] = field(default_factory=dict)
    available_endpoints: list[str] = field(default_factory=list)
    unavailable_endpoints: dict[str, str] = field(default_factory=dict)


@dataclass
class BirdeyeRiskEvidence:
    holder_count: int | None = None
    top10_holder_percent: float | None = None
    risk_flags: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    unknown: list[str] = field(default_factory=list)


class BirdeyeProvider:
    """Small read-only client with authentication, pacing, and bounded retries."""

    def __init__(self) -> None:
        self._last_request_at = 0.0
        self._request_lock = asyncio.Lock()
        self._snapshot_cache: dict[str, tuple[float, BirdeyeSnapshot]] = {}
        self._security_cache: dict[str, tuple[float, Any]] = {}
        self._wallet_pnl_cache: dict[str, tuple[float, Any]] = {}
        self._wallet_pnl_details_cache: dict[str, tuple[float, Any]] = {}
        self._holder_profile_cache: dict[str, tuple[float, Any]] = {}
        self._holder_distribution_cache: dict[str, tuple[float, Any]] = {}
        self._cache_lock = asyncio.Lock()

    def _api_key(self) -> str:
        key = os.getenv(BIRDEYE_API_KEY_ENV)
        if not key:
            raise BirdeyeError(f"{BIRDEYE_API_KEY_ENV} is not configured")
        return key

    def _base_url(self) -> str:
        return os.getenv(BIRDEYE_API_BASE_URL_ENV, BIRDEYE_API).rstrip("/")

    async def _request(self, method: str, path: str, params: dict[str, Any] | None = None, body: dict[str, Any] | None = None) -> Any:
        query = f"?{urlencode(params)}" if params else ""
        url = f"{self._base_url()}{path}{query}"
        encoded_body = json.dumps(body).encode("utf-8") if body is not None else None
        last_error: Exception | None = None
        for attempt in range(BIRDEYE_MAX_RETRIES):
            async with self._request_lock:
                wait = BIRDEYE_REQUEST_INTERVAL_SECONDS - (time.monotonic() - self._last_request_at)
                if wait > 0:
                    await asyncio.sleep(wait)
                self._last_request_at = time.monotonic()
            headers = {"Accept": "application/json", "X-API-KEY": self._api_key(), "X-CHAIN": BIRDEYE_CHAIN, "User-Agent": "MemeFinder1000X/1.0"}
            if encoded_body is not None:
                headers["Content-Type"] = "application/json"
            request = Request(url, data=encoded_body, headers=headers, method=method)
            try:
                response = await asyncio.to_thread(urlopen, request, timeout=BIRDEYE_TIMEOUT_SECONDS)
                with response:
                    payload = json.loads(response.read().decode("utf-8"))
                if not isinstance(payload, dict) or payload.get("success") is False:
                    message = payload.get("message") if isinstance(payload, dict) else None
                    detail = f": {message}" if message else ""
                    raise BirdeyeError(f"Birdeye returned an unsuccessful response{detail}")
                return payload.get("data")
            except HTTPError as error:
                last_error = error
                if error.code not in (408, 425, 429, 500, 502, 503, 504):
                    raise BirdeyeError(f"Birdeye returned HTTP {error.code}") from error
                retry_after = error.headers.get("Retry-After")
                try:
                    delay = float(retry_after) if retry_after else 2**attempt
                except ValueError:
                    delay = 2**attempt
                await asyncio.sleep(min(12, max(1, delay)))
            except (URLError, TimeoutError, OSError, json.JSONDecodeError, BirdeyeError) as error:
                last_error = error
                if attempt < BIRDEYE_MAX_RETRIES - 1:
                    await asyncio.sleep(2**attempt)
        if isinstance(last_error, HTTPError):
            raise BirdeyeError(f"Birdeye returned HTTP {last_error.code} after {BIRDEYE_MAX_RETRIES} attempts") from last_error
        raise BirdeyeError(f"Birdeye request failed after {BIRDEYE_MAX_RETRIES} attempts: {last_error}") from last_error

    async def _get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        return await self._request("GET", path, params=params)

    async def _post(self, path: str, body: dict[str, Any] | None = None) -> Any:
        return await self._request("POST", path, body=body)

    async def authenticate(self) -> tuple[bool, str]:
        try:
            data = await self._get("/defi/networks")
            if isinstance(data, list) or isinstance(data, dict):
                return True, "authenticated"
            return False, "Birdeye returned an unexpected network-list response"
        except BirdeyeError as error:
            logger.warning("Birdeye authentication check failed: %s", error)
            return False, str(error)

    async def security_snapshot(self, token_address: str) -> Any:
        async with self._cache_lock:
            cached = self._security_cache.get(token_address)
            if cached and time.monotonic() - cached[0] < SNAPSHOT_CACHE_SECONDS:
                return cached[1]
        data = await self._get("/defi/token_security", {"address": token_address})
        async with self._cache_lock:
            self._security_cache[token_address] = (time.monotonic(), data)
        return data

    async def analyze_token(self, token_address: str) -> BirdeyeSnapshot:
        """Fetch token enrichment plus the dedicated holder aggregations."""
        async with self._cache_lock:
            cached = self._snapshot_cache.get(token_address)
            if cached and time.monotonic() - cached[0] < SNAPSHOT_CACHE_SECONDS:
                return cached[1]
        snapshot = BirdeyeSnapshot(token_address=token_address)
        for name, path in DEFAULT_TOKEN_ENDPOINTS:
            try:
                data = await self._get(path, {"address": token_address})
                snapshot.data[name] = data
                snapshot.available_endpoints.append(name)
            except BirdeyeError as error:
                snapshot.unavailable_endpoints[name] = str(error)
        dedicated = (
            ("holder_profile", self.holder_profile),
            ("holder_distribution", self.holder_distribution),
        )
        for name, loader in dedicated:
            try:
                snapshot.data[name] = await loader(token_address)
                snapshot.available_endpoints.append(name)
            except BirdeyeError as error:
                snapshot.unavailable_endpoints[name] = str(error)
        async with self._cache_lock:
            self._snapshot_cache[token_address] = (time.monotonic(), snapshot)
        return snapshot

    async def holder_profile(self, token_address: str) -> Any:
        async with self._cache_lock:
            cached = self._holder_profile_cache.get(token_address)
            if cached and time.monotonic() - cached[0] < SNAPSHOT_CACHE_SECONDS:
                return cached[1]
        data = await self._get("/token/v1/holder-profile", {"token_address": token_address, "interval": "1h", "include_zero_balance": "false"})
        async with self._cache_lock:
            self._holder_profile_cache[token_address] = (time.monotonic(), data)
        return data

    async def holder_distribution(self, token_address: str) -> Any:
        async with self._cache_lock:
            cached = self._holder_distribution_cache.get(token_address)
            if cached and time.monotonic() - cached[0] < SNAPSHOT_CACHE_SECONDS:
                return cached[1]
        data = await self._get("/holder/v1/distribution", {"token_address": token_address, "address_type": "wallet", "mode": "top", "top_n": 10, "include_list": "false"})
        async with self._cache_lock:
            self._holder_distribution_cache[token_address] = (time.monotonic(), data)
        return data

    async def wallet_pnl(self, wallet_address: str) -> Any:
        async with self._cache_lock:
            cached = self._wallet_pnl_cache.get(wallet_address)
            if cached and time.monotonic() - cached[0] < WALLET_PNL_CACHE_SECONDS:
                return cached[1]
        data = await self._get("/wallet/v2/pnl/summary", {"wallet": wallet_address})
        async with self._cache_lock:
            self._wallet_pnl_cache[wallet_address] = (time.monotonic(), data)
        return data

    async def wallet_pnl_details(self, wallet_address: str) -> Any:
        async with self._cache_lock:
            cached = self._wallet_pnl_details_cache.get(wallet_address)
            if cached and time.monotonic() - cached[0] < WALLET_PNL_DETAILS_CACHE_SECONDS:
                return cached[1]
        data = await self._post("/wallet/v2/pnl/details", {"wallet": wallet_address, "duration": "90d", "position_scope": "cumulative", "offset": 0, "limit": 100})
        async with self._cache_lock:
            self._wallet_pnl_details_cache[wallet_address] = (time.monotonic(), data)
        return data

    @staticmethod
    def _find_number(data: Any, keys: tuple[str, ...]) -> float | None:
        """Find a numeric field at any useful nesting level without guessing a value."""
        if isinstance(data, dict):
            lowered = {str(k).lower(): v for k, v in data.items()}
            for key in keys:
                value = lowered.get(key.lower())
                if value is not None and not isinstance(value, (dict, list)):
                    try:
                        return float(value)
                    except (TypeError, ValueError):
                        pass
            for value in data.values():
                found = BirdeyeProvider._find_number(value, keys)
                if found is not None:
                    return found
        elif isinstance(data, list):
            for value in data:
                found = BirdeyeProvider._find_number(value, keys)
                if found is not None:
                    return found
        return None

    @staticmethod
    def _percent(value: Any) -> float | None:
        try:
            number = float(value)
        except (TypeError, ValueError):
            return None
        if number < 0:
            return None
        if number <= 1:
            number *= 100
        return number if number <= 100 else None

    @classmethod
    def _extract_top10_percent(cls, source: Any) -> float | None:
        """Extract top-10 supply share from documented profile/distribution shapes."""
        if not isinstance(source, (dict, list)):
            return None
        if isinstance(source, dict):
            for key in ("top10_holder", "top10Holder", "top10_holder_percent", "top10HolderPercent"):
                value = source.get(key)
                if isinstance(value, dict):
                    value = next((value.get(k) for k in ("percent_of_supply", "percentOfSupply", "percent", "percentage") if value.get(k) is not None), None)
                parsed = cls._percent(value)
                if parsed is not None:
                    return parsed
            for key in ("holder_summary", "summary"):
                nested = source.get(key)
                parsed = cls._extract_top10_percent(nested)
                if parsed is not None:
                    return parsed
        return None

    def risk_evidence(self, snapshot: BirdeyeSnapshot) -> BirdeyeRiskEvidence:
        evidence = BirdeyeRiskEvidence()
        holders = snapshot.data.get("token_holders")
        holder_sources = [holders, snapshot.data.get("holder_profile"), snapshot.data.get("holder_distribution")]
        raw_count = None
        for source in holder_sources:
            raw_count = self._find_number(source, ("total", "holderCount", "holder_count", "totalHolders", "total_holders", "holders", "wallet_count"))
            if raw_count is not None and raw_count >= 0:
                break
        if raw_count is not None:
            evidence.holder_count = int(raw_count)

        raw_top10 = None
        for source in (snapshot.data.get("holder_profile"), snapshot.data.get("holder_distribution"), holders):
            raw_top10 = self._extract_top10_percent(source)
            if raw_top10 is not None:
                break
        if raw_top10 is not None:
            evidence.top10_holder_percent = raw_top10
        if evidence.top10_holder_percent is not None:
            if evidence.top10_holder_percent >= 70:
                evidence.risk_flags.append("top-holder concentration >=70%")
            elif evidence.top10_holder_percent >= 50:
                evidence.risk_flags.append("top-holder concentration >=50%")
            evidence.evidence.append(f"Birdeye top-10 holder concentration: {evidence.top10_holder_percent:.1f}%")
        else:
            evidence.unknown.append("holder concentration")
        if evidence.holder_count is None:
            evidence.unknown.append("holder count")
        if "token_security" not in snapshot.available_endpoints:
            evidence.unknown.append("Birdeye token security")
        if "liquidity_history" not in snapshot.available_endpoints:
            evidence.unknown.append("Birdeye liquidity history")
        if "token_creation_info" not in snapshot.available_endpoints:
            evidence.unknown.append("Birdeye token creation info")
        top_traders = snapshot.data.get("top_traders")
        if isinstance(top_traders, dict):
            items = top_traders.get("items") or top_traders.get("data") or []
            if isinstance(items, list):
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    tags = item.get("tags") or item.get("labels") or []
                    text = str(tags).lower()
                    if any(term in text for term in ("dev", "developer", "insider")):
                        evidence.risk_flags.append("developer/insider tag observed in top traders")
                        evidence.evidence.append("Birdeye top-trader labeling observed")
                        break
        return evidence
