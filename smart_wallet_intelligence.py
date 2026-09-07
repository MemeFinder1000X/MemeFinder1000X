"""Read-only Smart Wallet Intelligence backed by Birdeye's indexed API.

Birdeye is deliberately kept behind the provider interface.  The bot does
not connect wallets, sign transactions, or infer ownership.  A missing key,
provider error, or insufficient history returns UNKNOWN instead of a guess.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from statistics import median
from typing import Any, Callable
from urllib.parse import urlencode
from urllib.request import Request, urlopen


logger = logging.getLogger(__name__)

BIRDEYE_API_BASE = os.getenv("BIRDEYE_API_BASE_URL", "https://public-api.birdeye.so").rstrip("/")
BIRDEYE_TOP_TRADERS_PATH = "/defi/v2/tokens/top_traders"
BIRDEYE_WALLET_SUMMARY_PATH = "/wallet/v2/pnl/summary"

# A wallet is not scored from one successful trade.  Birdeye's wallet PnL
# summary reports unique_tokens, so five distinct token observations is the
# documented minimum for this module.
MIN_HISTORICAL_OBSERVATIONS = 5
MIN_DECIDED_TRADES = 10
MIN_SMART_WALLET_SCORE = 60
MAX_TOP_TRADERS = 10
MAX_WALLETS_TO_PROFILE = 3
HTTP_TIMEOUT_SECONDS = 12
BIRDEYE_REQUEST_INTERVAL_SECONDS = 1.1

HttpGetter = Callable[[str, dict[str, str], float], Any]


@dataclass
class SmartWalletFinding:
    """Evidence-bounded smart-wallet fields exposed by /scan."""

    smart_wallets_detected: str = "UNKNOWN"
    top_traders_detected: str = "UNKNOWN"
    candidate_smart_wallet_count: str = "UNKNOWN"
    smart_money_score: str = "UNKNOWN"
    qualified_wallet_count: str = "UNKNOWN"
    independent_wallet_count: str = "UNKNOWN"
    best_smart_wallet_evidence: str = "UNKNOWN"
    wallet_history_coverage: str = "UNKNOWN"
    smart_money_evidence: str = (
        "UNKNOWN — current Solana RPC/DEX Screener sources do not provide "
        "reliable indexed wallet entry, return, or cluster history."
    )
    tracked_meme_coin_entries: str = "UNKNOWN"
    profitable_entries: str = "UNKNOWN"
    win_rate: str = "UNKNOWN"
    median_return: str = "UNKNOWN"
    average_return: str = "UNKNOWN"
    winners_2x: str = "UNKNOWN"
    winners_5x: str = "UNKNOWN"
    winners_10x: str = "UNKNOWN"
    maximum_drawdown: str = "UNKNOWN"
    typical_entry_timing: str = "UNKNOWN"
    holding_period: str = "UNKNOWN"
    recent_performance: str = "UNKNOWN"
    wallet_summary_tokens: str = "UNKNOWN"
    wallet_summary_win_rate: str = "UNKNOWN"
    wallet_summary_return: str = "UNKNOWN"
    wallet_purchase_signal: str = "UNKNOWN"
    cluster_evidence: str = "UNKNOWN"
    purchase_signals: list[dict[str, str]] = field(default_factory=list)


class SmartWalletProvider:
    """Interface for indexed, read-only smart-wallet data providers."""

    async def analyze(self, pair: dict[str, Any]) -> SmartWalletFinding:
        raise NotImplementedError


class UnavailableSmartWalletProvider(SmartWalletProvider):
    """Safe provider used when no indexed wallet-history source is configured."""

    async def analyze(self, pair: dict[str, Any]) -> SmartWalletFinding:
        chain = str(pair.get("chainId") or "unknown")
        return SmartWalletFinding(
            smart_money_evidence=(
                "UNKNOWN — no permitted indexed smart-wallet data source is "
                f"configured for the {chain} chain. Public RPC can expose "
                "individual transactions but not reliable wallet-wide performance."
            ),
            cluster_evidence=(
                "UNKNOWN — funding and transaction relationships require an "
                "indexed graph source; no wallet ownership is inferred."
            ),
        )


class BirdeyeApiError(RuntimeError):
    """Raised when an indexed Birdeye response is unusable."""


def _number(value: Any, default: float | None = None) -> float | None:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return default
    return result if math.isfinite(result) else default


def _integer(value: Any) -> int | None:
    number = _number(value)
    return int(number) if number is not None else None


def _first(mapping: dict[str, Any], *names: str) -> Any:
    for name in names:
        if name in mapping and mapping[name] is not None:
            return mapping[name]
    return None


def _percent(value: Any) -> float | None:
    """Normalize Birdeye's ratio-or-percent fields to percentage points."""
    number = _number(value)
    if number is None:
        return None
    return number * 100 if abs(number) <= 1 else number


def _format_percent(value: float | None) -> str:
    return "UNKNOWN" if value is None else f"{value:+.2f}%"


def _format_count(value: int | None) -> str:
    return "UNKNOWN" if value is None else str(max(0, value))


def _format_timestamp(value: Any) -> str:
    seconds = _timestamp(value)
    if seconds is None:
        return "UNKNOWN"
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (OverflowError, OSError, ValueError):
        return "UNKNOWN"


def _timestamp(value: Any) -> float | None:
    seconds = _number(value)
    if seconds is not None:
        return seconds / 1000 if seconds > 10_000_000_000 else seconds
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    return None


def _format_duration(seconds: float | None) -> str:
    if seconds is None or seconds < 0:
        return "UNKNOWN"
    if seconds < 3600:
        return f"{max(1, round(seconds / 60))}m"
    if seconds < 86_400:
        return f"{seconds / 3600:.1f}h"
    return f"{seconds / 86_400:.1f}d"


def _format_usd(value: Any) -> str:
    number = _number(value)
    if number is None:
        return "UNKNOWN"
    absolute = abs(number)
    if absolute >= 1_000_000:
        return f"${number / 1_000_000:.2f}M"
    if absolute >= 1_000:
        return f"${number / 1_000:.2f}K"
    return f"${number:.2f}"


def _items(response: Any) -> list[dict[str, Any]]:
    if not isinstance(response, dict):
        return []
    data = response.get("data")
    if isinstance(data, dict):
        raw_items = data.get("items")
        if isinstance(raw_items, list):
            return [item for item in raw_items if isinstance(item, dict)]
    return []


def _summary(response: Any) -> dict[str, Any]:
    if not isinstance(response, dict) or not isinstance(response.get("data"), dict):
        return {}
    summary = response["data"].get("summary")
    return summary if isinstance(summary, dict) else {}
def _wallet_score(win_rate: float, average_return: float, observations: int) -> int:
    """Bounded evidence score, not a return prediction.

    The score weights win rate (55%), return (35%), and observation depth
    (10%).  It is only called after the minimum observation gate passes.
    """
    win_component = max(0, min(100, win_rate))
    return_component = max(0, min(100, 50 + average_return))
    depth_component = min(100, observations / MIN_HISTORICAL_OBSERVATIONS * 100)
    return round(win_component * 0.55 + return_component * 0.35 + depth_component * 0.10)


def _unknown_for_pair(pair: dict[str, Any], reason: str) -> SmartWalletFinding:
    chain = str(pair.get("chainId") or "unknown")
    return SmartWalletFinding(
        smart_money_evidence=f"UNKNOWN — {reason} ({chain}); no signal is inferred.",
        cluster_evidence=(
            "UNKNOWN — indexed funding relationships were unavailable; no wallet "
            "ownership or relationship is inferred."
        ),
    )


class BirdeyeSmartWalletProvider(SmartWalletProvider):
    """Read-only Birdeye adapter for Solana token traders and wallet PnL."""

    def __init__(
        self,
        api_key: str,
        *,
        api_base: str = BIRDEYE_API_BASE,
        http_get: HttpGetter | None = None,
        min_observations: int = MIN_HISTORICAL_OBSERVATIONS,
        request_interval: float = BIRDEYE_REQUEST_INTERVAL_SECONDS,
    ) -> None:
        self.api_key = api_key
        self.api_base = api_base.rstrip("/")
        self.http_get = http_get or self._http_get
        self.min_observations = max(1, min_observations)
        self.request_interval = max(0, request_interval)
        self._request_lock = asyncio.Lock()
        self._last_request_at = 0.0

    @staticmethod
    def _http_get(url: str, headers: dict[str, str], timeout: float) -> Any:
        request = Request(url, headers=headers)
        with urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))

    async def _request(self, path: str, params: dict[str, Any]) -> Any:
        query = urlencode({key: value for key, value in params.items() if value is not None})
        url = f"{self.api_base}{path}?{query}"
        headers = {
            "Accept": "application/json",
            "User-Agent": "MemeFinder1000X/1.0",
            "X-API-KEY": self.api_key,
            "x-chain": "solana",
        }
        response: Any = None
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                async with self._request_lock:
                    delay = self.request_interval - (
                        time.monotonic() - self._last_request_at
                    )
                    if delay > 0:
                        await asyncio.sleep(delay)
                    response = await asyncio.to_thread(
                        self.http_get, url, headers, HTTP_TIMEOUT_SECONDS
                    )
                    self._last_request_at = time.monotonic()
                last_error = None
                break
            except Exception as error:
                last_error = error
                if getattr(error, "code", None) != 429 or attempt == 2:
                    break
                await asyncio.sleep(2**attempt)
        if last_error is not None:
            raise BirdeyeApiError(
                f"request failed for {path}: {type(last_error).__name__}"
            ) from last_error
        if not isinstance(response, dict) or response.get("success") is False:
            message = response.get("message", "invalid response") if isinstance(response, dict) else "invalid response"
            raise BirdeyeApiError(f"Birdeye returned an unusable response: {message}")
        return response

    async def _profile_wallet(self, wallet: str) -> dict[str, Any] | None:
        try:
            summary_response = await self._request(
                BIRDEYE_WALLET_SUMMARY_PATH,
                {"wallet": wallet, "duration": "90d", "position_scope": "cumulative"},
            )
            summary = _summary(summary_response)
            return {"summary": summary}
        except BirdeyeApiError:
            logger.warning("Birdeye wallet history unavailable for one wallet")
            return None

    async def analyze(self, pair: dict[str, Any]) -> SmartWalletFinding:
        chain = str(pair.get("chainId") or "").lower()
        address = str((pair.get("baseToken") or {}).get("address") or "")
        if chain != "solana":
            return _unknown_for_pair(pair, "Birdeye wallet intelligence currently supports Solana only")
        if not address:
            return _unknown_for_pair(pair, "the pair has no token address")

        try:
            traders_response = await self._request(
                BIRDEYE_TOP_TRADERS_PATH,
                {
                    "address": address,
                    "time_frame": "90d",
                    "sort_by": "total_pnl",
                    "sort_type": "desc",
                    "limit": MAX_TOP_TRADERS,
                    "get_holders_networth": "true",
                    "wallet_tags": "smart_trader",
                },
            )
        except BirdeyeApiError as error:
            logger.warning("Birdeye top traders unavailable: %s", error)
            return _unknown_for_pair(pair, "Birdeye indexed trader history is unavailable")

        traders = _items(traders_response)
        if not traders:
            return _unknown_for_pair(pair, "Birdeye returned no indexed trader history")

        unique_traders: dict[str, dict[str, Any]] = {}
        for trader in traders:
            wallet = str(_first(trader, "owner", "wallet", "address") or "")
            if wallet and wallet not in unique_traders:
                unique_traders[wallet] = trader
        profiles = await asyncio.gather(
            *(self._profile_wallet(wallet) for wallet in list(unique_traders)[:MAX_WALLETS_TO_PROFILE])
        )
        profile_limit = min(len(unique_traders), MAX_WALLETS_TO_PROFILE)
        profiled_count = sum(profile is not None for profile in profiles)

        qualified: list[dict[str, Any]] = []
        entry_ages: list[float] = []
        funding_by_wallet: dict[str, str] = {}
        pair_created = _number(pair.get("pairCreatedAt"))
        pair_created_seconds = pair_created / 1000 if pair_created and pair_created > 10_000_000_000 else pair_created

        for (wallet, trader), profile in zip(list(unique_traders.items())[:MAX_WALLETS_TO_PROFILE], profiles):
            if not profile:
                continue
            summary = profile["summary"]
            counts = summary.get("counts") if isinstance(summary.get("counts"), dict) else {}
            observations_count = _integer(_first(summary, "unique_tokens", "uniqueTokens"))
            wins = _integer(_first(counts, "total_win", "totalWin"))
            losses = _integer(_first(counts, "total_loss", "totalLoss"))
            if observations_count is None or observations_count < self.min_observations:
                continue
            if wins is None or losses is None or wins + losses <= 0:
                continue
            if wins + losses < MIN_DECIDED_TRADES:
                continue
            win_rate = wins / (wins + losses) * 100
            pnl = summary.get("pnl") if isinstance(summary.get("pnl"), dict) else {}
            historical_return = _percent(
                _first(pnl, "realized_profit_percent", "realizedProfitPercent")
            )
            if historical_return is None:
                continue
            average_return = historical_return
            score = _wallet_score(win_rate, average_return, observations_count)
            if score < MIN_SMART_WALLET_SCORE:
                continue
            qualified.append(
                {
                    "wallet": wallet,
                    "trader": trader,
                    "summary": summary,
                    "observations_count": observations_count,
                    "wins": wins,
                    "losses": losses,
                    "win_rate": win_rate,
                    "average_return": average_return,
                    "score": score,
                }
            )
            first_trade = _number(_first(trader, "firstTradeUnixTime", "first_trade_unix_time"))
            if first_trade is not None and pair_created_seconds:
                age = first_trade - pair_created_seconds
                if age >= 0:
                    entry_ages.append(age)
            funding = trader.get("funding") if isinstance(trader.get("funding"), dict) else {}
            funder = str(_first(funding, "funder", "address") or "")
            if funder:
                funding_by_wallet[wallet] = funder

        if not qualified:
            return SmartWalletFinding(
                smart_wallets_detected="0",
                top_traders_detected=str(len(unique_traders)),
                candidate_smart_wallet_count=str(profiled_count),
                qualified_wallet_count="0",
                smart_money_score="UNKNOWN",
                best_smart_wallet_evidence=(
                    "INSUFFICIENT HISTORY — no profiled wallet met all gates: "
                    f"at least {self.min_observations} distinct token observations, "
                    f"{MIN_DECIDED_TRADES} decided outcomes, complete realized P&L, "
                    f"and score ≥{MIN_SMART_WALLET_SCORE}."
                ),
                wallet_history_coverage=(
                    f"{profiled_count}/{profile_limit} selected top-trader wallets "
                    "returned usable Birdeye wallet-history responses"
                ),
                smart_money_evidence=(
                    f"Birdeye returned {len(unique_traders)} top trader(s). "
                    "Top-trader status is not treated as smart-money qualification; "
                    "no Smart Wallet Score is emitted without sufficient history."
                ),
                wallet_purchase_signal=(
                    "UNKNOWN — no qualified smart wallet exists for comparison "
                    "with current-token activity"
                ),
                cluster_evidence=(
                    "UNKNOWN — wallet clustering is evaluated only for qualified "
                    "wallets with sufficient funding evidence."
                ),
            )

        total_wallet_token_observations = sum(
            item["observations_count"] for item in qualified
        )
        total_wins = sum(item["wins"] for item in qualified)
        total_decided = sum(item["wins"] + item["losses"] for item in qualified)
        wallet_scores = [item["score"] for item in qualified]
        wallet_returns = [item["average_return"] for item in qualified]

        purchase_signals: list[dict[str, str]] = []
        for item in qualified:
            trader = item["trader"]
            first_trade = _first(trader, "firstTradeUnixTime", "first_trade_unix_time")
            buy_value = _first(trader, "volumeBuyUSD", "volume_buy_usd")
            buy_count = _integer(_first(trader, "tradeBuy", "trade_buy"))
            if (
                buy_count is None
                or buy_count <= 0
                or _number(buy_value) is None
                or _number(buy_value) <= 0
                or first_trade is None
            ):
                continue
            entry_age = None
            if pair_created_seconds:
                raw_age = _number(first_trade)
                if raw_age is not None and raw_age >= pair_created_seconds:
                    entry_age = raw_age - pair_created_seconds
            purchase_signals.append(
                {
                    "wallet": item["wallet"],
                    "token": str((pair.get("baseToken") or {}).get("symbol") or address),
                    "value": _format_usd(buy_value),
                    "time": _format_timestamp(first_trade),
                    "token_age": _format_duration(entry_age),
                    "score": f"{item['score']}/100",
                    "activity_label": "Birdeye 90d current-token aggregate buy volume",
                    "evidence": (
                        f"Birdeye first-trade timestamp; 90d wallet summary covers "
                        f"{item['observations_count']} wallet-wide tokens, "
                        f"{item['win_rate']:.1f}% realized-outcome win rate, and "
                        f"{_format_percent(item['average_return'])} aggregate realized PnL return"
                    ),
                }
            )

        funders = list(funding_by_wallet.values())
        funder_groups: dict[str, int] = {}
        for funder in funders:
            funder_groups[funder] = funder_groups.get(funder, 0) + 1
        shared_funders = {funder: count for funder, count in funder_groups.items() if count > 1}
        if len(funding_by_wallet) == len(qualified):
            independent_count = len(funder_groups)
            if shared_funders:
                cluster_text = (
                    "Possible cluster — "
                    + ", ".join(f"{count} qualified wallets share an indexed funder" for count in shared_funders.values())
                    + "; counted as one independent signal where applicable. Ownership is not asserted."
                )
            else:
                cluster_text = (
                    f"No shared indexed funder observed across {len(qualified)} qualified wallets; "
                    "this does not prove independent ownership."
                )
        else:
            independent_count = None
            cluster_text = (
                "UNKNOWN — funding evidence was incomplete for some qualified wallets; "
                "no wallet ownership or relationship is inferred."
            )

        typical_timing = (
            _format_duration(median(entry_ages)) + " after token creation"
            if entry_ages
            else "UNKNOWN"
        )
        recent = (
            f"{total_wins}/{total_decided} realized wins "
            f"({total_wins / total_decided * 100:.1f}%) over Birdeye's 90d summary window"
        )
        best_wallet = max(qualified, key=lambda item: item["score"])
        best_evidence = (
            f"Score {best_wallet['score']}/100 from "
            f"{best_wallet['observations_count']} distinct token observations, "
            f"{best_wallet['wins']}/{best_wallet['wins'] + best_wallet['losses']} "
            f"decided wins, {best_wallet['win_rate']:.1f}% win rate, and "
            f"{_format_percent(best_wallet['average_return'])} aggregate realized "
            "P&L return. This is historical evidence, not a forecast."
        )
        return SmartWalletFinding(
            smart_wallets_detected=str(len(qualified)),
            top_traders_detected=str(len(unique_traders)),
            candidate_smart_wallet_count=str(profiled_count),
            smart_money_score=f"{sum(wallet_scores) / len(wallet_scores):.0f}/100",
            qualified_wallet_count=str(len(qualified)),
            independent_wallet_count=_format_count(independent_count),
            best_smart_wallet_evidence=best_evidence,
            wallet_history_coverage=(
                f"{profiled_count}/{profile_limit} selected top-trader wallets "
                "returned usable Birdeye wallet-history responses"
            ),
            smart_money_evidence=(
                "Birdeye indexed 90d current-token top-trader data and wallet-wide PnL summaries; "
                f"wallets are scored only after at least {self.min_observations} distinct wallet-wide token observations. "
                "Entry-level and meme-only history are unavailable on the configured plan and remain UNKNOWN. "
                "This is informational evidence, not a return prediction."
            ),
            typical_entry_timing=typical_timing,
            recent_performance=recent,
            wallet_summary_tokens=str(total_wallet_token_observations),
            wallet_summary_win_rate=_format_percent(total_wins / total_decided * 100),
            wallet_summary_return=_format_percent(
                sum(wallet_returns) / len(wallet_returns)
            ),
            wallet_purchase_signal=(
                f"{len(purchase_signals)} qualified wallet activity signal(s) observed for this token"
                if purchase_signals
                else "UNKNOWN — current-token top-trader buy fields were incomplete"
            ),
            cluster_evidence=cluster_text,
            purchase_signals=purchase_signals,
        )


class SmartWalletIntelligence:
    """Routes pairs through chain-specific smart-wallet providers."""

    def __init__(self, provider: SmartWalletProvider | Any | None = None) -> None:
        # Main also passes its shared BirdeyeProvider here. That client enriches
        # risk/developer evidence but does not implement this module's analyze()
        # interface, so keep the dedicated evidence-bounded adapter for wallets.
        if provider is not None and callable(getattr(provider, "analyze", None)):
            self._provider = provider
        else:
            api_key = os.getenv("BIRDEYE_API_KEY", "").strip()
            self._provider = (
                BirdeyeSmartWalletProvider(api_key)
                if api_key
                else UnavailableSmartWalletProvider()
            )

    async def analyze_many(
        self, pairs: list[dict[str, Any]]
    ) -> dict[tuple[str, str], SmartWalletFinding]:
        """Return evidence-bounded results for every scanned pair."""

        async def analyze_pair(
            pair: dict[str, Any],
        ) -> tuple[tuple[str, str], SmartWalletFinding]:
            base_token = pair.get("baseToken") or {}
            key = (
                str(pair.get("chainId") or ""),
                str(base_token.get("address") or ""),
            )
            try:
                finding = await self._provider.analyze(pair)
            except Exception:
                logger.exception("Smart-wallet provider failed for one pair")
                finding = _unknown_for_pair(pair, "smart-wallet provider error")
            return key, finding

        return dict(await asyncio.gather(*(analyze_pair(pair) for pair in pairs)))
