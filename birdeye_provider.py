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
BIRDEYE_API_KEY_ENV = "BIRDEYE_API_KEY"
BIRDEYE_CHAIN = "solana"
BIRDEYE_TIMEOUT_SECONDS = 12
BIRDEYE_MAX_RETRIES = 3
# Conservative Standard-package pacing. Higher-tier limits do not justify
# bursting because endpoint-specific limits still apply.
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
    """Raw, source-attributed Birdeye data for one Solana token."""

    token_address: str
    data: dict[str, Any] = field(default_factory=dict)
    available_endpoints: list[str] = field(default_factory=list)
    unavailable_endpoints: dict[str, str] = field(default_factory=dict)


@dataclass
class BirdeyeRiskEvidence:
    """Conservative holder/security/liquidity evidence for the scanner."""

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
        self._wallet_pnl_cache: dict[str, tuple[float, Any]] = {}
        self._wallet_pnl_details_cache: dict[str, tuple[float, Any]] = {}
        self._cache_lock = asyncio.Lock()

    def _api_key(self) -> str:
        key = os.getenv(BIRDEYE_API_KEY_ENV)
        if not key:
            raise BirdeyeError(f"{BIRDEYE_API_KEY_ENV} is not configured")
        return key

    async def _request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
    ) -> Any:
        query = f"?{urlencode(params)}" if params else ""
        url = f"{BIRDEYE_API}{path}{query}"
        encoded_body = json.dumps(body).encode("utf-8") if body is not None else None
        last_error: Exception | None = None
        for attempt in range(BIRDEYE_MAX_RETRIES):
            async with self._request_lock:
                wait = BIRDEYE_REQUEST_INTERVAL_SECONDS - (
                    time.monotonic() - self._last_request_at
                )
                if wait > 0:
                    await asyncio.sleep(wait)
                self._last_request_at = time.monotonic()
            headers = {
                "Accept": "application/json",
                "X-API-KEY": self._api_key(),
                "X-CHAIN": BIRDEYE_CHAIN,
                "User-Agent": "MemeFinder1000X/1.0",
            }
            if encoded_body is not None:
                headers["Content-Type"] = "application/json"
            request = Request(
                url,
                data=encoded_body,
                headers=headers,
                method=method,
            )
            try:
                response = await asyncio.to_thread(
                    urlopen, request, timeout=BIRDEYE_TIMEOUT_SECONDS
                )
                with response:
                    payload = json.loads(response.read().decode("utf-8"))
                if not isinstance(payload, dict) or payload.get("success") is False:
                    raise BirdeyeError("Birdeye returned an unsuccessful response")
                return payload.get("data")
            except HTTPError as error:
                last_error = error
                if error.code not in (408, 425, 429, 500, 502, 503, 504):
                    raise BirdeyeError(
                        f"Birdeye returned HTTP {error.code}"
                    ) from error
                retry_after = error.headers.get("Retry-After")
                try:
                    delay = float(retry_after) if retry_after else 2**attempt
                except ValueError:
                    delay = 2**attempt
                await asyncio.sleep(min(12, max(1, delay)))
            except (
                URLError,
                TimeoutError,
                OSError,
                json.JSONDecodeError,
                BirdeyeError,
            ) as error:
                last_error = error
                if attempt < BIRDEYE_MAX_RETRIES - 1:
                    await asyncio.sleep(2**attempt)
        raise BirdeyeError("Birdeye did not respond after several attempts") from last_error

    async def _get(
        self, path: str, params: dict[str, Any] | None = None
    ) -> Any:
        return await self._request("GET", path, params=params)

    async def _post(
        self, path: str, body: dict[str, Any] | None = None
    ) -> Any:
        return await self._request("POST", path, body=body)

    async def authenticate(self) -> tuple[bool, str]:
        """Check the key with the documented network-list endpoint.

        Returns status text only; it never returns or logs the credential.
        """
        try:
            data = await self._get("/defi/networks")
            if isinstance(data, list) or isinstance(data, dict):
                return True, "authenticated"
            return False, "Birdeye returned an unexpected network-list response"
        except BirdeyeError as error:
            logger.warning("Birdeye authentication check failed: %s", error)
            return False, str(error)

    async def analyze_token(self, token_address: str) -> BirdeyeSnapshot:
        """Fetch documented Solana token enrichment endpoints.

        Endpoint failures are isolated so one plan restriction does not erase
        the evidence returned by other endpoints.
        """
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
                # Do not include remote response bodies or credentials in the
                # user-facing evidence.
                snapshot.unavailable_endpoints[name] = str(error)
        async with self._cache_lock:
            self._snapshot_cache[token_address] = (time.monotonic(), snapshot)
        return snapshot

    async def wallet_pnl(self, wallet_address: str) -> Any:
        """Read a wallet's documented P&L summary without signing anything."""
        async with self._cache_lock:
            cached = self._wallet_pnl_cache.get(wallet_address)
            if cached and time.monotonic() - cached[0] < WALLET_PNL_CACHE_SECONDS:
                return cached[1]
        data = await self._get(
            "/wallet/v2/pnl/summary",
            {"wallet": wallet_address},
        )
        async with self._cache_lock:
            self._wallet_pnl_cache[wallet_address] = (time.monotonic(), data)
        return data

    async def wallet_pnl_details(self, wallet_address: str) -> Any:
        """Read documented wallet-wide token P&L details without signing."""
        async with self._cache_lock:
            cached = self._wallet_pnl_details_cache.get(wallet_address)
            if cached and time.monotonic() - cached[0] < WALLET_PNL_DETAILS_CACHE_SECONDS:
                return cached[1]
        data = await self._post(
            "/wallet/v2/pnl/details",
            {
                "wallet": wallet_address,
                "duration": "90d",
                "position_scope": "cumulative",
                "offset": 0,
                "limit": 100,
            },
        )
        async with self._cache_lock:
            self._wallet_pnl_details_cache[wallet_address] = (time.monotonic(), data)
        return data

    @staticmethod
    def risk_evidence(snapshot: BirdeyeSnapshot) -> BirdeyeRiskEvidence:
        """Extract only fields observed in documented endpoint responses."""
        result = BirdeyeRiskEvidence()
        holders = snapshot.data.get("token_holders")
        if isinstance(holders, dict):
            holder_count = holders.get("holder")
            top10 = holders.get("top10_hold_percent")
            if isinstance(holder_count, int):
                result.holder_count = holder_count
                result.evidence.append(f"Birdeye holder count: {holder_count}")
            try:
                result.top10_holder_percent = float(top10)
            except (TypeError, ValueError):
                pass
            if result.top10_holder_percent is not None:
                result.evidence.append(
                    "Birdeye top-10 holder concentration: "
                    f"{result.top10_holder_percent:.1f}%"
                )
                if result.top10_holder_percent >= 70:
                    result.risk_flags.append(
                        "very high top-10 holder concentration (Birdeye)"
                    )
                elif result.top10_holder_percent >= 50:
                    result.risk_flags.append(
                        "high top-10 holder concentration (Birdeye)"
                    )
        else:
            result.unknown.extend(["holder count", "top-holder concentration"])

        if "token_security" not in snapshot.available_endpoints:
            result.unknown.append("Birdeye token security")
        if "liquidity_history" not in snapshot.available_endpoints:
            result.unknown.extend(
                ["historical liquidity", "exit liquidity", "liquidity-removal history"]
            )
        if "token_creation_info" not in snapshot.available_endpoints:
            result.unknown.append("Birdeye token creation information")

        traders = snapshot.data.get("top_traders")
        records: list[dict[str, Any]] = []
        if isinstance(traders, dict) and isinstance(traders.get("items"), list):
            records = [
                item for item in traders["items"] if isinstance(item, dict)
            ]
        tagged = 0
        for record in records:
            tags = record.get("tags")
            if not isinstance(tags, list):
                continue
            normalized = " ".join(str(tag).lower() for tag in tags)
            if "developer" in normalized or "insider" in normalized:
                tagged += 1
        if tagged:
            result.evidence.append(
                f"Birdeye labeled {tagged} top-trader record(s) with "
                "developer/insider tags; labels are signals, not ownership proof"
            )
        elif records:
            result.evidence.append(
                "Birdeye top-trader activity returned with no observed "
                "developer/insider tags"
            )
        else:
            result.unknown.append("developer/insider trader activity")
        return result
