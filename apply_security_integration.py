"""Idempotently wire security intelligence into bot.py before launch.

This is a temporary compatibility layer for the existing bot module. It only
adds read-only enrichment and rendering; it never executes trades.
"""

from pathlib import Path


ROOT = Path(__file__).resolve().parent
BOT = ROOT / "bot.py"


def replace_once(text: str, old: str, new: str) -> str:
    if new in text:
        return text
    if old not in text:
        raise RuntimeError(f"Expected integration anchor not found: {old[:100]!r}")
    return text.replace(old, new, 1)


def main() -> None:
    text = BOT.read_text(encoding="utf-8")

    text = replace_once(
        text,
        "from smart_wallet_intelligence import SmartWalletIntelligence\n",
        "from smart_wallet_intelligence import SmartWalletIntelligence\nfrom security_intelligence import SecurityIntelligence\n",
    )
    text = replace_once(
        text,
        "_smart_wallet_intelligence = SmartWalletIntelligence(_birdeye_provider)\n",
        "_smart_wallet_intelligence = SmartWalletIntelligence(_birdeye_provider)\n_security_intelligence = SecurityIntelligence()\n",
    )

    scan_anchor = '''            _apply_developer_risk_evidence(pair, pair.get("_developer") or {})\n        messages = _render_scan_messages(pairs)\n'''
    scan_replacement = '''            _apply_developer_risk_evidence(pair, pair.get("_developer") or {})\n\n        # Security enrichment is deliberately separate from Opportunity Score.\n        # Every displayed Solana token is analyzed; failures remain inconclusive.\n        for pair in pairs:\n            base_token = pair.get("baseToken") or {}\n            chain = str(pair.get("chainId") or "").lower()\n            address = str(base_token.get("address") or "")\n            if chain == "solana" and address:\n                try:\n                    security = await _security_intelligence.analyze(\n                        _birdeye_provider, address\n                    )\n                    pair["_security"] = security.__dict__\n                except Exception:\n                    logger.exception("Security analysis failed for token")\n                    pair["_security"] = {\n                        "risk": "INCONCLUSIVE",\n                        "confidence": "LOW",\n                    }\n        messages = _render_scan_messages(pairs)\n'''
    text = replace_once(text, scan_anchor, scan_replacement)

    render_anchor = "        lines.extend(developer_lines)\n"
    render_replacement = '''        security = pair.get("_security") or {}\n        security_score = security.get("security_score")\n        score_text = f"{security_score}/100" if security_score is not None else "UNKNOWN"\n        security_risk = _clip(security.get("risk"), 20, "INCONCLUSIVE")\n        security_confidence = _clip(security.get("confidence"), 12, "LOW")\n        lines.extend(developer_lines)\n        lines.extend(\n            [\n                "",\n                "🔐 SECURITY",\n                f"Score: {score_text}",\n                f"Risk: {security_risk} | Confidence: {security_confidence}",\n                f"Mint authority: {security.get('mint_authority', 'UNKNOWN')}",\n                f"Freeze authority: {security.get('freeze_authority', 'UNKNOWN')}",\n                f"Honeypot: {security.get('honeypot', 'UNKNOWN')}",\n                f"LP status: {security.get('lp_status', 'UNKNOWN')}",\n                f"LP lock/burn: {security.get('lp_lock_burn', 'UNKNOWN')}",\n                f"Top 10: {_security_percent(security.get('top10_percent'))}",\n                f"Dev: {_security_percent(security.get('dev_percent'))}",\n                f"Insiders: {_security_percent(security.get('insider_percent'))}",\n                f"Snipers: {_security_percent(security.get('sniper_percent'))}",\n                f"Bundlers: {_security_percent(security.get('bundler_percent'))}",\n            ]\n        )\n'''
    text = replace_once(text, render_anchor, render_replacement)

    helper_anchor = '''def _clip(value: Any, limit: int, fallback: str = "UNKNOWN") -> str:\n'''
    helper = '''def _security_percent(value: Any) -> str:\n    """Render a security cohort percentage without implying missing data is safe."""\n    if value is None:\n        return "UNKNOWN"\n    try:\n        return f"{float(value):.1f}%"\n    except (TypeError, ValueError):\n        return "UNKNOWN"\n\n\n'''
    text = replace_once(text, helper_anchor, helper + helper_anchor)

    BOT.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
