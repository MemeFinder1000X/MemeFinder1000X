"""Idempotently wire security intelligence into bot.py before launch.

Kept separate so the existing scanner logic is not rewritten or duplicated.
The patch only adds read-only enrichment and a SECURITY section to each card.
"""

from pathlib import Path


ROOT = Path(__file__).resolve().parent
BOT = ROOT / "bot.py"


def replace_once(text: str, old: str, new: str) -> str:
    if new in text:
        return text
    if old not in text:
        raise RuntimeError(f"Expected integration anchor not found: {old[:80]!r}")
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

    old_scan_anchor = '''            _apply_developer_risk_evidence(pair, pair.get("_developer") or {})\n        messages = _render_scan_messages(pairs)\n'''
    new_scan_anchor = '''            _apply_developer_risk_evidence(pair, pair.get("_developer") or {})\n\n        # Security enrichment runs for every displayed Solana token. It is\n        # deliberately isolated from opportunity scoring and never executes trades.\n        for pair in pairs:\n            base_token = pair.get("baseToken") or {}\n            chain = str(pair.get("chainId") or "").lower()\n            address = str(base_token.get("address") or "")\n            if chain == "solana" and address:\n                try:\n                    security = await _security_intelligence.analyze(\n                        _birdeye_provider, address\n                    )\n                    pair["_security"] = security.__dict__\n                except Exception:\n                    logger.exception("Security analysis failed for token")\n                    pair["_security"] = {"risk": "INCONCLUSIVE", "confidence": "LOW"}\n\n        messages = _render_scan_messages(pairs)\n'''
    text = replace_once(text, old_scan_anchor, new_scan_anchor)

    holder_anchor = '''                f"Top 10: {f'{birdeye_top10:.1f}%' if birdeye_top10 is not None else 'UNKNOWN'} {top10_icon}".rstrip(),\n                "",\n                "👨‍💻 DEVELOPER",\n'''
    holder_replacement = '''                f"Top 10: {f'{birdeye_top10:.1f}%' if birdeye_top10 is not None else 'UNKNOWN'} {top10_icon}".rstrip(),\n            ]\n        )\n\n        security = pair.get("_security") or {}\n        security_score = security.get("security_score")\n        security_risk = _clip(security.get("risk"), 20, "INCONCLUSIVE")\n        security_confidence = _clip(security.get("confidence"), 12, "LOW")\n        score_text = f"{security_score}/100" if security_score is not None else "UNKNOWN"\n        lines.extend(\n            [\n                "",\n                "🔐 SECURITY",\n                f"Score: {score_text}",\n                f"Risk: {security_risk} | Confidence: {security_confidence}",\n                f"Mint authority: {security.get('mint_authority', 'UNKNOWN')}",\n                f"Freeze authority: {security.get('freeze_authority', 'UNKNOWN')}",\n                f"Honeypot: {security.get('honeypot', 'UNKNOWN')}",\n                f"LP status: {security.get('lp_status', 'UNKNOWN')}",\n                f"LP lock/burn: {security.get('lp_lock_burn', 'UNKNOWN')}",\n                "",\n                "👨‍💻 DEVELOPER",\n            ]\n        )\n'''
    text = replace_once(text, holder_anchor, holder_replacement)

    # The replacement above closes the existing lines.extend block, so remove
    # the now-duplicated continuation opener if the original syntax leaves one.
    text = text.replace(
        '''        )\n        lines.extend(developer_lines)\n''',
        '''        lines.extend(developer_lines)\n''',
        1,
    )

    BOT.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
