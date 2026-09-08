"""MemeFinder 1000X Telegram bot."""

import asyncio
import json
import logging
import os
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from developer_intelligence import DeveloperIntelligence
from birdeye_provider import BirdeyeProvider, BirdeyeRiskEvidence
from smart_wallet_intelligence import SmartWalletIntelligence
from security_intelligence import SecurityIntelligence
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes


WELCOME_MESSAGE = (
    "🚀 MemeFinder 1000X is online! Meme coin scanner coming soon."
)
DEXSCREENER_API = "https://api.dexscreener.com"
LATEST_PROFILES_PATH = "/token-profiles/latest/v1"
TOKEN_BATCH_PATH = "/tokens/v1/{chain_id}/{addresses}"
HTTP_TIMEOUT_SECONDS = 12
MAX_RETRIES = 3
MAX_TOKEN_ADDRESSES_PER_REQUEST = 30
MAX_TELEGRAM_MESSAGE_LENGTH = 4096
REQUEST_INTERVAL_SECONDS = 1.05
SUPPORTED_CHAINS = {
    "arbitrum", "base", "bsc", "ethereum", "optimism", "polygon",
    "solana", "sui", "avalanche", "linea", "fantom", "cronos", "ton",
}
MEME_KEYWORDS = (
    "meme", "doge", "shib", "pepe", "inu", "cat", "frog", "moon",
    "wojak", "bonk", "floki",
)

logger = logging.getLogger(__name__)
_last_dex_request_at = 0.0
_request_lock = asyncio.Lock()
_birdeye_provider = BirdeyeProvider()
_developer_intelligence = DeveloperIntelligence(_birdeye_provider)
_smart_wallet_intelligence = SmartWalletIntelligence(_birdeye_provider)
_security_intelligence = SecurityIntelligence()


class DexScreenerError(Exception):
    """Raised when DEX Screener cannot provide usable scan data."""


def _number(value: Any, default: float = 0.0) -> float:
    try:
        result = float(value)
        return result if result == result else default
    except (TypeError, ValueError):
        return default


def _format_number(value: Any, prefix: str = "") -> str:
    number = _number(value)
    if number == 0:
        return "n/a"
    absolute = abs(number)
    if absolute >= 1_000_000_000:
        return f"{prefix}{number / 1_000_000_000:.2f}B"
    if absolute >= 1_000_000:
        return f"{prefix}{number / 1_000_000:.2f}M"
    if absolute >= 1_000:
        return f"{prefix}{number / 1_000:.2f}K"
    return f"{prefix}{number:.2f}"


def _format_price(value: Any) -> str:
    number = _number(value)
    if number == 0:
        return "n/a"
    if abs(number) >= 1:
        return f"${number:,.4f}"
    return f"${number:.8f}".rstrip("0").rstrip(".")


def _format_age(pair_created_at: Any) -> str:
    created_ms = _number(pair_created_at)
    if created_ms <= 0:
        return "n/a"
    age_seconds = max(0, time.time() - created_ms / 1000)
    if age_seconds < 3600:
        return f"{max(1, int(age_seconds // 60))}m"
    if age_seconds < 86_400:
        return f"{int(age_seconds // 3600)}h"
    return f"{int(age_seconds // 86_400)}d"


async def _wait_for_dex_request() -> None:
    global _last_dex_request_at
    async with _request_lock:
        wait_seconds = REQUEST_INTERVAL_SECONDS - (time.monotonic() - _last_dex_request_at)
        if wait_seconds > 0:
            await asyncio.sleep(wait_seconds)
        _last_dex_request_at = time.monotonic()


async def _get_dex_json(path: str) -> Any:
    url = f"{DEXSCREENER_API}{path}"
    last_error: Exception | None = None
    for attempt in range(MAX_RETRIES):
        await _wait_for_dex_request()
        request = Request(url, headers={"Accept": "application/json", "User-Agent": "MemeFinder1000X/1.0"})
        try:
            response = await asyncio.to_thread(urlopen, request, timeout=HTTP_TIMEOUT_SECONDS)
            with response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            last_error = error
            if error.code not in (429, 500, 502, 503, 504):
                raise DexScreenerError(f"DEX Screener returned HTTP {error.code}") from error
            retry_after = error.headers.get("Retry-After")
            delay = _number(retry_after, 2**attempt) if retry_after else 2**attempt
            await asyncio.sleep(min(8, max(1, delay)))
        except (URLError, TimeoutError, json.JSONDecodeError, OSError) as error:
            last_error = error
            if attempt < MAX_RETRIES - 1:
                await asyncio.sleep(2**attempt)
    raise DexScreenerError("DEX Screener did not respond after several attempts") from last_error


def _is_meme_candidate(profile: dict[str, Any]) -> bool:
    text_parts = [str(profile.get(key, "")) for key in ("description", "url", "tokenAddress")]
    for link in profile.get("links") or []:
        if isinstance(link, dict):
            text_parts.extend(str(link.get(key, "")) for key in ("label", "url"))
    text = " ".join(text_parts).lower()
    return any(keyword in text for keyword in MEME_KEYWORDS)


def _nested_number(data: Any, key: str) -> float:
    return _number(data.get(key)) if isinstance(data, dict) else 0.0


def _relative_score(value: float, low: float, high: float) -> float:
    if value <= 0:
        return 0.0
    if value <= low:
        return value / low * 50
    if value <= high:
        return 50 + (value - low) / (high - low) * 50
    return 100.0


def _analyze_pair(pair: dict[str, Any]) -> dict[str, Any]:
    liquidity = _nested_number(pair.get("liquidity"), "usd")
    market_cap = _number(pair.get("marketCap"))
    volume = _nested_number(pair.get("volume"), "h24")
    volume_h1 = _nested_number(pair.get("volume"), "h1")
    price_change = _nested_number(pair.get("priceChange"), "h24")
    txns = pair.get("txns") or {}
    txns_24h = txns.get("h24") if isinstance(txns, dict) else {}
    buys = _nested_number(txns_24h, "buys")
    sells = _nested_number(txns_24h, "sells")
    total_txns = buys + sells
    pair_age_hours = 0.0
    if _number(pair.get("pairCreatedAt")) > 0:
        pair_age_hours = max(0.1, (time.time() * 1000 - _number(pair.get("pairCreatedAt"))) / 3_600_000)
    volume_to_liquidity = volume / liquidity if liquidity else 0.0
    volume_to_market_cap = volume / market_cap if market_cap else 0.0
    market_cap_to_liquidity = market_cap / liquidity if liquidity else 0.0
    volume_acceleration = volume_h1 / (volume / 24) if volume_h1 and volume > 0 else 0.0
    buy_share = buys / total_txns if total_txns else 0.0
    unknown: list[str] = []
    required_fields = (
        ("priceUsd", "price"), ("marketCap", "market cap"), ("liquidity.usd", "liquidity"),
        ("volume.h24", "24h volume"), ("priceChange.h24", "24h price change"),
        ("txns.h24", "24h buys/sells"), ("pairCreatedAt", "token age"), ("url", "DEX Screener URL"),
    )
    for path, label in required_fields:
        if path == "liquidity.usd": present = liquidity > 0
        elif path == "volume.h24": present = volume > 0
        elif path == "priceChange.h24": present = isinstance(pair.get("priceChange"), dict) and "h24" in pair["priceChange"]
        elif path == "txns.h24": present = isinstance(txns_24h, dict) and ("buys" in txns_24h or "sells" in txns_24h)
        elif path == "pairCreatedAt": present = pair_age_hours > 0
        else: present = bool(pair.get(path))
        if not present: unknown.append(label)
    unknown.extend(["holder growth", "holder concentration", "developer/contract risk", "liquidity lock", "mint/freeze/authority status"])
    unavailable = {"holder growth", "holder concentration", "developer/contract risk", "liquidity lock", "mint/freeze/authority status"}
    completeness = round(100 * (len(required_fields) - len([item for item in unknown if item not in unavailable])) / len(required_fields))
    anomalies: list[str] = []
    risk_flags: list[str] = []
    if price_change <= -90: anomalies.append("down >90%"); risk_flags.append("extreme drawdown")
    if price_change >= 200: anomalies.append("extreme price increase"); risk_flags.append("extreme momentum")
    if liquidity and liquidity < 5_000: anomalies.append("very low liquidity"); risk_flags.append("very low liquidity")
    if volume_to_liquidity > 50: anomalies.append("extreme volume/liquidity"); risk_flags.append("volume/liquidity anomaly")
    if volume_to_market_cap > 5: anomalies.append("extreme volume/market cap"); risk_flags.append("volume/market-cap anomaly")
    if "market cap" in unknown or "liquidity" in unknown: risk_flags.append("missing critical risk data")
    if str(pair.get("chainId", "")).lower() not in SUPPORTED_CHAINS: risk_flags.append("unsupported/unusual chain")
    if "price" in unknown or "24h buys/sells" in unknown: risk_flags.append("incomplete activity data")
    liquidity_score = _relative_score(liquidity, 10_000, 100_000)
    ratio_score = 100 if 5 <= market_cap_to_liquidity <= 50 else max(0.0, 100 - abs(market_cap_to_liquidity - 25) * 3) if market_cap_to_liquidity else 0.0
    relative_volume_score = _relative_score(volume_to_liquidity, 0.2, 5)
    volume_cap_score = _relative_score(volume_to_market_cap, 0.02, 1)
    acceleration_score = _relative_score(volume_acceleration, 1, 4)
    balance_score = abs(buy_share - 0.5) * 200 if total_txns else 0.0
    transaction_score = min(100.0, total_txns / 10)
    age_score = max(0.0, 100 - max(0, pair_age_hours - 24) * 2) if pair_age_hours else 0.0
    momentum_score = max(0.0, min(100.0, 50 + price_change)) if -50 < price_change < 100 else 0.0
    opportunity = (liquidity_score * .18 + ratio_score * .12 + relative_volume_score * .13 + volume_cap_score * .10 + acceleration_score * .10 + balance_score * .08 + transaction_score * .10 + age_score * .07 + momentum_score * .07 + completeness * .05)
    opportunity -= min(45, len(anomalies) * 15)
    opportunity = round(max(0.0, min(100.0, opportunity)))
    if completeness < 55: verdict = "INSUFFICIENT DATA"
    elif any(anomaly in anomalies for anomaly in ("down >90%", "extreme volume/liquidity", "extreme volume/market cap", "very low liquidity")): verdict = "EXTREME RISK"
    elif len(risk_flags) >= 3 or "unsupported/unusual chain" in risk_flags: verdict = "HIGH RISK"
    elif price_change >= 50 or volume_acceleration >= 3: verdict = "HIGH MOMENTUM"
    elif opportunity >= 65: verdict = "INTERESTING"
    else: verdict = "WATCH"
    pair["_analysis"] = {"opportunity_score": opportunity, "data_quality_score": completeness, "unknown": unknown, "anomalies": anomalies, "risk_flags": risk_flags, "verdict": verdict, "volume_to_liquidity": volume_to_liquidity, "volume_acceleration": volume_acceleration, "market_cap_to_liquidity": market_cap_to_liquidity}
    return pair


def _score_pair(pair: dict[str, Any]) -> float:
    return _number((pair.get("_analysis") or {}).get("opportunity_score"))


def _apply_birdeye_risk_evidence(pair: dict[str, Any], evidence: BirdeyeRiskEvidence) -> None:
    analysis = pair.get("_analysis") or {}
    risk_flags = analysis.setdefault("risk_flags", [])
    unknown = analysis.setdefault("unknown", [])
    for flag in evidence.risk_flags:
        if flag not in risk_flags: risk_flags.append(flag)
    for item in evidence.unknown:
        if item not in unknown: unknown.append(item)
    analysis["birdeye_evidence"] = evidence.evidence
    analysis["birdeye_holder_count"] = evidence.holder_count
    analysis["birdeye_top10_holder_percent"] = evidence.top10_holder_percent
    if evidence.holder_count is not None: unknown[:] = [item for item in unknown if item != "holder growth"]
    if evidence.top10_holder_percent is not None: unknown[:] = [item for item in unknown if item != "holder concentration"]


def _apply_developer_risk_evidence(pair: dict[str, Any], developer: dict[str, Any]) -> None:
    analysis = pair.get("_analysis") or {}
    risk_flags = analysis.setdefault("risk_flags", [])
    for flag in developer.get("risk_flags") or []:
        if flag not in risk_flags: risk_flags.append(flag)


def _clip(value: Any, limit: int, default: str = "UNKNOWN") -> str:
    text = str(value) if value is not None else default
    if len(text) <= limit: return text
    return text[: max(0, limit - 1)] + "…"


def _security_percent(value: Any) -> str:
    if value is None: return "UNKNOWN"
    return f"{_number(value):.1f}%"


def _render_scan_results(pairs: list[dict[str, Any]], include_header: bool = True) -> str:
    if not pairs: return "No newly active meme coin pairs are available right now.\nTry /scan again shortly."
    lines = (["🔎 MEMEFINDER 1000X", "Read-only analysis. No trades are executed.", ""] if include_header else [])
    for pair in pairs:
        base_token = pair.get("baseToken") or {}
        txns_24h = (pair.get("txns") or {}).get("h24") or {}
        change_24h = _number((pair.get("priceChange") or {}).get("h24"))
        analysis = pair.get("_analysis") or {}
        developer = pair.get("_developer") or {}
        smart_wallet = pair.get("_smart_wallet") or {}
        security = pair.get("_security") or {}
        risk_flags = analysis.get("risk_flags") or []
        anomalies = analysis.get("anomalies") or []
        birdeye_holder_count = analysis.get("birdeye_holder_count")
        birdeye_top10 = analysis.get("birdeye_top10_holder_percent")
        verdict = _clip(analysis.get("verdict"), 40, "INSUFFICIENT DATA")
        risk_display = "🔴 EXTREME" if verdict == "EXTREME RISK" else "🔴 HIGH" if verdict == "HIGH RISK" else "🟠 ELEVATED" if risk_flags else "🟡 WATCH"
        liquidity = (pair.get("liquidity") or {}).get("usd")
        volume_anomaly = any("volume" in str(item).lower() for item in anomalies)
        top10_icon = "🔴" if birdeye_top10 is not None and birdeye_top10 >= 50 else "🟢" if birdeye_top10 is not None else ""
        developer_address = str(developer.get("developer") or "UNKNOWN")
        if developer_address.lower() != "unknown" and len(developer_address) > 12: developer_address = f"{developer_address[:4]}...{developer_address[-4:]}"
        developer_label = _clip(developer.get("developer_label"), 30, "Probable Developer")
        developer_evidence = _clip(developer.get("evidence"), 180)
        history_coverage = _clip(developer.get("history_coverage"), 150)
        history_available = str(developer.get("previous_launches") or "UNKNOWN").upper() != "UNKNOWN"
        if history_available:
            developer_lines = [
                f"Launches: {developer.get('previous_launches', 'UNKNOWN')} | Successful: {developer.get('successful_launches', 'UNKNOWN')} | Failed/inactive: {developer.get('failed_launches', 'UNKNOWN')}",
                f"Suspected rug patterns: {developer.get('suspected_rug_launches', 'UNKNOWN')}",
                f"Best previous: {_clip(developer.get('best_previous_launch'), 120)}",
                f"Developer Score: {_clip(developer.get('developer_score'), 80)} | Risk: {_clip(developer.get('risk'), 30)}",
            ]
            optional_history = (("Historical market cap", "highest_historical_market_cap", 60), ("Historical liquidity", "historical_liquidity", 80), ("Liquidity activity", "liquidity_activity", 120), ("Developer selling", "selling_behavior", 120), ("Activity timing", "major_activity_timing", 120), ("Recent launches", "recent_launch_activity", 120))
            for label, key, limit in optional_history:
                value = str(developer.get(key) or "UNKNOWN")
                if value.upper() != "UNKNOWN": developer_lines.append(f"{label}: {_clip(value, limit)}")
            developer_lines.extend([f"Coverage: {history_coverage}", f"Evidence: {developer_evidence}"])
        else:
            developer_lines = ["History: UNKNOWN — no attributable prior launches in available evidence", "Developer Score: UNKNOWN | Risk: UNKNOWN", f"Coverage: {history_coverage}", f"Evidence: {developer_evidence}"]
        concise_risks = list(dict.fromkeys(_clip(item, 140) for item in risk_flags))
        security_risks = security.get("warnings") or []
        for warning in security_risks:
            warning_text = _clip(warning, 140)
            if warning_text not in concise_risks: concise_risks.append(warning_text)
        if not concise_risks: concise_risks.append("No major risk flag observed in available data")
        security_score = security.get("security_score")
        security_score_text = f"{security_score}/100" if security_score is not None else "UNKNOWN"
        security_risk = _clip(security.get("risk"), 20, "INCONCLUSIVE")
        security_confidence = _clip(security.get("confidence"), 12, "LOW")
        lines.extend([
            f"🐸 {_clip(base_token.get('symbol'), 32)} · {_clip(pair.get('chainId'), 20).upper()}", "",
            f"Opportunity: {analysis.get('opportunity_score', 'UNKNOWN')}/100", f"Risk: {risk_display}", "",
            f"Price: {_format_price(pair.get('priceUsd')).replace('n/a', 'UNKNOWN')}", f"Market Cap: {_format_number(pair.get('marketCap'), '$').replace('n/a', 'UNKNOWN')}", f"Liquidity: {_format_number(liquidity, '$').replace('n/a', 'UNKNOWN')}", f"Volume: {_format_number((pair.get('volume') or {}).get('h24'), '$').replace('n/a', 'UNKNOWN')}", f"Age: {_format_age(pair.get('pairCreatedAt')).replace('n/a', 'UNKNOWN')}", "",
            "📊 MARKET", f"24h: {change_24h:+.2f}% | Age: {_format_age(pair.get('pairCreatedAt')).replace('n/a', 'UNKNOWN')}", f"Buys: {int(_number(txns_24h.get('buys')))}", f"Sells: {int(_number(txns_24h.get('sells')))}", f"Volume anomaly: {'🔴' if volume_anomaly else '🟢'}", "",
            "👥 HOLDERS", f"Holders: {birdeye_holder_count if birdeye_holder_count is not None else 'UNKNOWN'}", f"Top 10: {f'{birdeye_top10:.1f}%' if birdeye_top10 is not None else 'UNKNOWN'} {top10_icon}".rstrip(), "",
            "👨‍💻 DEVELOPER", f"{developer_label}: {developer_address}",
        ])
        lines.extend(developer_lines)
        if str(pair.get("chainId") or "").lower() == "solana":
            lines.extend(["", "🔐 SECURITY", f"Score: {security_score_text}", f"Risk: {security_risk} | Confidence: {security_confidence}", f"Mint authority: {security.get('mint_authority', 'UNKNOWN')}", f"Freeze authority: {security.get('freeze_authority', 'UNKNOWN')}", f"Honeypot: {security.get('honeypot', 'UNKNOWN')}", f"LP status: {security.get('lp_status', 'UNKNOWN')}", f"LP lock/burn: {security.get('lp_lock_burn', 'UNKNOWN')}", f"Top 10: {_security_percent(security.get('top10_percent'))}", f"Dev: {_security_percent(security.get('dev_percent'))}", f"Insiders: {_security_percent(security.get('insider_percent'))}", f"Snipers: {_security_percent(security.get('sniper_percent'))}", f"Bundlers: {_security_percent(security.get('bundler_percent'))}"])
        lines.extend(["", "🐋 SMART MONEY", f"Top traders: {_clip(smart_wallet.get('top_traders_detected'), 30)}", f"Qualified wallets: {_clip(smart_wallet.get('qualified_wallet_count'), 30)}", f"Smart Money Score: {_clip(smart_wallet.get('smart_money_score'), 50)}", "", "🚨 RISK"])
        lines.extend(f"• {risk}" for risk in concise_risks[:4])
        lines.extend(["", f"VERDICT: {verdict}", f"DEX: {_clip(pair.get('url'), 300)}", ""])
    return "\n".join(lines).strip()


def _render_scan_messages(pairs: list[dict[str, Any]]) -> list[str]:
    if not pairs: return [_render_scan_results([])]
    header = "🔎 MEMEFINDER 1000X\nRead-only analysis. No trades are executed."
    cards: list[str] = []
    for pair in pairs:
        card = _render_scan_results([pair], include_header=False)
        if len(card) > MAX_TELEGRAM_MESSAGE_LENGTH:
            base = pair.get("baseToken") or {}
            analysis = pair.get("_analysis") or {}
            card = "\n".join([f"🐸 {_clip(base.get('symbol'), 32)} · {_clip(pair.get('chainId'), 20).upper()}", "Result available, but detailed fields exceeded Telegram limits.", f"VERDICT: {_clip(analysis.get('verdict'), 40, 'INSUFFICIENT DATA')}", f"DEX: {_clip(pair.get('url'), 300)}"])
        cards.append(card[:MAX_TELEGRAM_MESSAGE_LENGTH])
    messages: list[str] = []
    current = header
    for card in cards:
        candidate = f"{current}\n\n{card}" if current else card
        if len(candidate) <= MAX_TELEGRAM_MESSAGE_LENGTH: current = candidate; continue
        if current: messages.append(current)
        current = card
    if current: messages.append(current)
    return messages


async def scan(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message is None: return
    await update.message.reply_text("Scanning DEX Screener for newly active meme coins…")
    try:
        pairs = await _scan_newly_active_coins()
        findings = await _developer_intelligence.analyze_many(pairs)
        for pair in pairs:
            base_token = pair.get("baseToken") or {}
            key = (str(pair.get("chainId") or ""), str(base_token.get("address") or ""))
            finding = findings.get(key)
            pair["_developer"] = finding.__dict__ if finding else {}
        smart_findings = await _smart_wallet_intelligence.analyze_many(pairs)
        for index, pair in enumerate(pairs):
            base_token = pair.get("baseToken") or {}
            key = (str(pair.get("chainId") or ""), str(base_token.get("address") or ""))
            finding = smart_findings.get(key)
            pair["_smart_wallet"] = finding.__dict__ if finding else {}
            if index < 3 and key[0].lower() == "solana" and key[1]:
                snapshot = await _birdeye_provider.analyze_token(key[1])
                _apply_birdeye_risk_evidence(pair, _birdeye_provider.risk_evidence(snapshot))
            _apply_developer_risk_evidence(pair, pair.get("_developer") or {})
        for pair in pairs:
            base_token = pair.get("baseToken") or {}
            chain = str(pair.get("chainId") or "").lower()
            address = str(base_token.get("address") or "")
            if chain != "solana" or not address: continue
            try:
                security = await _security_intelligence.analyze(_birdeye_provider, address)
                pair["_security"] = security.__dict__
            except Exception:
                logger.exception("Security analysis failed for token")
                pair["_security"] = {"risk": "INCONCLUSIVE", "confidence": "LOW"}
        messages = _render_scan_messages(pairs)
    except DexScreenerError as error:
        logger.warning("DEX Screener scan failed: %s", error)
        messages = ["DEX Screener is temporarily unavailable or rate-limited. Please try /scan again in a moment."]
    except Exception:
        logger.exception("Unexpected scan error")
        messages = ["The scan could not be completed right now. Please try /scan again."]
    for message in messages: await update.message.reply_text(message)


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message is not None: await update.message.reply_text(WELCOME_MESSAGE)


def main() -> None:
    """Start the bot using Telegram webhook mode on Railway."""
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    if not token:
        raise RuntimeError("TELEGRAM_BOT_TOKEN is not set. Add it as an environment variable before starting the bot.")
    logging.basicConfig(format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    application = Application.builder().token(token).build()
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("scan", scan))
    webhook_url = os.getenv("TELEGRAM_WEBHOOK_URL")
    if not webhook_url:
        raise RuntimeError("TELEGRAM_WEBHOOK_URL is not set. Configure the public Railway URL before starting the bot.")
    port = int(os.getenv("PORT", "8080"))
    application.run_webhook(listen="0.0.0.0", port=port, webhook_url=webhook_url, drop_pending_updates=True)


if __name__ == "__main__":
    main()
