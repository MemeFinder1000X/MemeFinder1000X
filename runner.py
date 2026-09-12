"""Runtime entrypoint that restores scan discovery and improves scan quality."""

from urllib.parse import quote
import re

import bot
from scan_quality import improve_pair, improve_rendered_text
import birdeye_key_diagnostic  # noqa: F401  # logs only a one-way key fingerprint
import top10_fix  # noqa: F401  # patches Birdeye concentration extraction only
from scan_presentation_fix import normalize_developer_display, annotate_opportunity_label


async def _scan_newly_active_coins() -> list[dict]:
    """Get recent DEX Screener profiles and enrich them with current pair metrics."""
    profiles_data = await bot._get_dex_json(bot.LATEST_PROFILES_PATH)
    profiles = profiles_data if isinstance(profiles_data, list) else []
    profiles = [
        profile
        for profile in profiles
        if isinstance(profile, dict)
        and profile.get("chainId")
        and profile.get("tokenAddress")
    ]
    meme_profiles = [profile for profile in profiles if bot._is_meme_candidate(profile)]
    candidates = meme_profiles or profiles

    grouped: dict[str, list[str]] = {}
    for profile in candidates:
        grouped.setdefault(str(profile["chainId"]), []).append(str(profile["tokenAddress"]))

    pairs: list[dict] = []
    for chain_id, addresses in grouped.items():
        for offset in range(0, len(addresses), bot.MAX_TOKEN_ADDRESSES_PER_REQUEST):
            batch = addresses[offset : offset + bot.MAX_TOKEN_ADDRESSES_PER_REQUEST]
            path = bot.TOKEN_BATCH_PATH.format(
                chain_id=quote(chain_id, safe=""),
                addresses=quote(",".join(batch), safe=","),
            )
            response = await bot._get_dex_json(path)
            if isinstance(response, list):
                pairs.extend(pair for pair in response if isinstance(pair, dict))

    best_by_token: dict[tuple[str, str], dict] = {}
    for pair in pairs:
        base_token = pair.get("baseToken") or {}
        key = (str(pair.get("chainId", "")), str(base_token.get("address", "")))
        token_text = f"{base_token.get('name', '')} {base_token.get('symbol', '')}".lower()
        has_meme_signal = any(keyword in token_text for keyword in bot.MEME_KEYWORDS)
        if key[0].lower() not in bot.SUPPORTED_CHAINS or not has_meme_signal:
            continue
        analyzed = bot._analyze_pair(pair)
        if key[0] and key[1] and (
            key not in best_by_token
            or bot._score_pair(analyzed) > bot._score_pair(best_by_token[key])
        ):
            best_by_token[key] = analyzed

    return sorted(best_by_token.values(), key=bot._score_pair, reverse=True)[:10]


bot._scan_newly_active_coins = _scan_newly_active_coins


def _number(value: object) -> float | None:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    return result if result == result else None


def _normalize_tag_risk_flags(pair: dict) -> None:
    """Keep developer/insider warnings consistent with reported security cohorts."""
    analysis = pair.get("_analysis") or {}
    flags = analysis.get("risk_flags")
    if not isinstance(flags, list):
        return
    security = pair.get("_security") or {}
    dev_percent = _number(security.get("dev_percent"))
    insider_percent = _number(security.get("insider_percent"))
    normalized: list[object] = []
    for flag in flags:
        text = str(flag)
        if text.lower() == "developer/insider tag observed in top traders":
            if insider_percent is not None and insider_percent > 0 and dev_percent is not None and dev_percent > 0:
                text = "developer/insider tag observed in top traders"
            elif insider_percent is not None and insider_percent > 0:
                text = "insider tag observed in top traders"
            elif dev_percent is not None and dev_percent > 0:
                text = "developer tag observed in top traders"
            else:
                continue
        if text not in normalized:
            normalized.append(text)
    analysis["risk_flags"] = normalized


def _normalize_low_holder_top10(text: str, holder_count: object) -> str:
    """Call the concentration Top-N when fewer than ten holders exist."""
    count = _number(holder_count)
    if count is None or count < 1 or count >= 10:
        return text
    holder_n = int(count)
    return re.sub(r"Top 10:", f"Top {holder_n}:", text)


_original_render_scan_results = bot._render_scan_results


def _quality_render_scan_results(pairs: list[dict], include_header: bool = True) -> str:
    for pair in pairs:
        if pair.get("_security") is not None:
            _normalize_tag_risk_flags(pair)
            improve_pair(pair)
        normalize_developer_display(pair)
    rendered = improve_rendered_text(_original_render_scan_results(pairs, include_header=include_header))
    if pairs and len(pairs) == 1:
        holder_count = ((pairs[0].get("_analysis") or {}).get("birdeye_holder_count"))
        rendered = _normalize_low_holder_top10(rendered, holder_count)
        rendered = annotate_opportunity_label(rendered, pairs[0])
    return rendered


bot._render_scan_results = _quality_render_scan_results

if __name__ == "__main__":
    bot.main()
