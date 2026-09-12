"""Security-aware presentation and scoring adjustments for /scan.

This module is read-only: it never trades, signs transactions, or changes
provider data. It only makes the existing evidence harder to misinterpret.
"""

from __future__ import annotations

from typing import Any


def _number(value: Any, default: float | None = None) -> float | None:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return default
    return result if result == result else default


def improve_pair(pair: dict[str, Any]) -> None:
    """Apply conservative security penalties and evidence-aware verdicts."""
    analysis = pair.get("_analysis") or {}
    security = pair.get("_security") or {}
    smart = pair.get("_smart_wallet") or {}
    risk_flags = analysis.setdefault("risk_flags", [])

    bundler = _number(security.get("bundler_percent"))
    sniper = _number(security.get("sniper_percent"))
    top10 = _number(security.get("top10_percent"))
    smart_score = smart.get("smart_money_score")
    qualified = _number(smart.get("qualified_wallet_count"))

    score = _number(analysis.get("opportunity_score"), 0) or 0
    penalty = 0
    if bundler is not None:
        if bundler >= 60:
            penalty += 15
        elif bundler >= 40:
            penalty += 10
    if sniper is not None:
        if sniper >= 30:
            penalty += 10
        elif sniper >= 15:
            penalty += 5
    if top10 is not None and top10 >= 70:
        penalty += 10
    elif top10 is not None and top10 >= 50:
        penalty += 5

    if qualified == 0 and str(smart_score).upper() == "UNKNOWN":
        penalty += 5

    adjusted = max(0, min(100, round(score - penalty)))
    analysis["raw_opportunity_score"] = round(score)
    analysis["opportunity_score"] = adjusted
    analysis["security_adjusted"] = penalty > 0
    analysis["opportunity_adjustment"] = penalty

    if bundler is not None and bundler >= 60:
        flag = f"High bundler cohort concentration: {bundler:.1f}%"
        if flag not in risk_flags:
            risk_flags.append(flag)
    if sniper is not None and sniper >= 30:
        flag = f"High sniper cohort concentration: {sniper:.1f}%"
        if flag not in risk_flags:
            risk_flags.append(flag)

    security_warnings = [str(item).lower() for item in (security.get("warnings") or [])]
    token_security_unavailable = (
        any("token-security" in item and ("unavailable" in item or "401" in item or "403" in item) for item in security_warnings)
        or str(security.get("mint_authority", "UNKNOWN")).upper() == "UNKNOWN"
    )

    verdict = str(analysis.get("verdict") or "INSUFFICIENT DATA")
    if token_security_unavailable and verdict == "HIGH MOMENTUM":
        analysis["verdict"] = "HIGH MOMENTUM — SECURITY UNVERIFIED"
    elif bundler is not None and bundler >= 60 and verdict in {"HIGH MOMENTUM", "INTERESTING"}:
        analysis["verdict"] = "HIGH MOMENTUM — BUNDLER RISK"


def improve_rendered_text(text: str) -> str:
    """Make Solana-specific security limitations explicit in Telegram output."""
    text = text.replace("Honeypot: UNKNOWN", "Honeypot: N/A (Solana)")
    text = text.replace(
        "• Token-security endpoint unavailable",
        "• Token-security endpoint unavailable — authority/LP checks unverified",
    )
    text = text.replace(
        "• Critical security data unavailable",
        "• Token-security endpoint unavailable — authority/LP checks unverified",
    )
    return text
