"""Runtime entrypoint that restores scan discovery and improves scan quality."""

from urllib.parse import quote

import bot
from scan_quality import improve_pair, improve_rendered_text
import birdeye_key_diagnostic  # noqa: F401  # logs only a one-way key fingerprint


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

# The production bot computes security after market/developer/smart-money
# enrichment. Wrap the renderer so the final Telegram cards use the completed
# security evidence and apply the conservative opportunity adjustment.
_original_render_scan_results = bot._render_scan_results


def _quality_render_scan_results(pairs: list[dict], include_header: bool = True) -> str:
    for pair in pairs:
        if pair.get("_security") is not None:
            improve_pair(pair)
    return improve_rendered_text(_original_render_scan_results(pairs, include_header=include_header))


bot._render_scan_results = _quality_render_scan_results

if __name__ == "__main__":
    bot.main()
