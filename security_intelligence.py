"""Conservative, read-only Solana token security analysis.

This module combines documented Birdeye evidence without pretending that an
API snapshot can guarantee that a token is safe. Missing evidence lowers
confidence; it is never converted into a positive security claim.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SecurityFinding:
    """Evidence-weighted security finding for one token."""

    security_score: int | None = None
    risk: str = "INCONCLUSIVE"
    confidence: str = "LOW"
    mint_authority: str = "UNKNOWN"
    freeze_authority: str = "UNKNOWN"
    honeypot: str = "UNKNOWN"
    lp_status: str = "UNKNOWN"
    lp_lock_burn: str = "UNKNOWN"
    top10_percent: float | None = None
    dev_percent: float | None = None
    insider_percent: float | None = None
    sniper_percent: float | None = None
    bundler_percent: float | None = None
    developer_wallet: str = "UNKNOWN"
    developer_selling: str = "UNKNOWN"
    suspicious_activity: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    unknown: list[str] = field(default_factory=list)


def _first(data: Any, *keys: str) -> Any:
    if not isinstance(data, dict):
        return None
    for key in keys:
        if key in data and data[key] is not None:
            return data[key]
    return None


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


def _authority_state(value: Any) -> str:
    if value is None:
        return "UNKNOWN"
    text = str(value).strip().lower()
    if text in {"", "none", "null", "false", "0", "disabled", "revoked"}:
        return "DISABLED"
    if text in {"true", "enabled", "active"}:
        return "ACTIVE"
    return "ACTIVE" if text else "UNKNOWN"


def _security_field(data: dict[str, Any], *keys: str) -> Any:
    value = _first(data, *keys)
    if value is not None:
        return value
    nested = data.get("security")
    return _first(nested, *keys)


class SecurityIntelligence:
    """Build a conservative security report from Birdeye read-only data."""

    async def analyze(self, provider: Any, token_address: str) -> SecurityFinding:
        finding = SecurityFinding()
        try:
            snapshot = await provider.analyze_token(token_address)
        except Exception as exc:  # provider already keeps remote errors safe
            finding.unknown.append("Birdeye security enrichment unavailable")
            finding.warnings.append("Security data could not be retrieved")
            finding.confidence = "LOW"
            return finding

        security = snapshot.data.get("token_security")
        if isinstance(security, dict):
            mint = _security_field(security, "mintAuthority", "mint_authority", "mintAuthorityAddress")
            freeze = _security_field(security, "freezeAuthority", "freeze_authority", "freezeAuthorityAddress")
            finding.mint_authority = _authority_state(mint)
            finding.freeze_authority = _authority_state(freeze)
            honeypot = _security_field(security, "honeypot", "isHoneypot", "honeypotRisk")
            if honeypot is not None:
                finding.honeypot = "YES" if str(honeypot).lower() in {"true", "1", "yes", "high", "danger"} else "NO"
            else:
                finding.unknown.append("honeypot assessment")
            finding.evidence.append("Birdeye token-security response available")
        else:
            finding.unknown.extend(["mint authority", "freeze authority", "honeypot assessment"])

        holders = snapshot.data.get("token_holders")
        if isinstance(holders, dict):
            finding.top10_percent = _percent(_first(holders, "top10_holder_percent", "top10HolderPercent"))

        profile = snapshot.data.get("holder_profile")
        if isinstance(profile, dict):
            summary = profile.get("holder_summary") if isinstance(profile.get("holder_summary"), dict) else profile
            finding.top10_percent = _percent(_first(summary, "top10_holder", "top10_holder_percent", "top10HolderPercent")) or finding.top10_percent
            tags = profile.get("tags") if isinstance(profile.get("tags"), dict) else {}
            for tag, attr in (("dev", "dev_percent"), ("insider", "insider_percent"), ("sniper", "sniper_percent"), ("bundler", "bundler_percent")):
                value = _percent(_first(tags, tag, f"{tag}_percent", f"{tag}Percent"))
                if value is not None:
                    setattr(finding, attr, value)
            finding.evidence.append("Birdeye holder-profile data available")
        else:
            finding.unknown.extend(["developer-holder concentration", "insider concentration", "sniper concentration", "bundler concentration"])

        creation = snapshot.data.get("token_creation_info")
        if isinstance(creation, dict):
            creator = _first(creation, "creator", "creatorAddress", "owner", "deployer")
            if creator:
                finding.developer_wallet = str(creator)
                finding.evidence.append("Developer/creator address observed in creation data")

        liquidity = snapshot.data.get("liquidity_history")
        if isinstance(liquidity, (dict, list)):
            finding.lp_status = "HEALTHY" if liquidity else "UNKNOWN"
            finding.evidence.append("Birdeye liquidity-history endpoint returned")
        else:
            finding.unknown.append("historical liquidity / LP status")

        # A liquidity balance is not proof of a lock or burn.
        finding.lp_lock_burn = "UNKNOWN"
        finding.unknown.append("LP lock/burn proof")

        score = 70
        known = 0
        if finding.mint_authority != "UNKNOWN":
            known += 1
            if finding.mint_authority == "ACTIVE":
                score -= 20
                finding.warnings.append("Mint authority is active")
        if finding.freeze_authority != "UNKNOWN":
            known += 1
            if finding.freeze_authority == "ACTIVE":
                score -= 20
                finding.warnings.append("Freeze authority is active")
        if finding.honeypot != "UNKNOWN":
            known += 1
            if finding.honeypot == "YES":
                score -= 45
                finding.warnings.append("Honeypot risk reported by provider")
        if finding.top10_percent is not None:
            known += 1
            if finding.top10_percent >= 70:
                score -= 25
                finding.warnings.append(f"Top-10 holders control {finding.top10_percent:.1f}%")
            elif finding.top10_percent >= 50:
                score -= 15
                finding.warnings.append(f"Top-10 holders control {finding.top10_percent:.1f}%")
        for label, value in (("developer", finding.dev_percent), ("insider", finding.insider_percent), ("sniper", finding.sniper_percent), ("bundler", finding.bundler_percent)):
            if value is not None:
                known += 1
                if value >= 15:
                    score -= 10
                    finding.warnings.append(f"High {label} cohort concentration: {value:.1f}%")

        if known == 0:
            finding.security_score = None
            finding.risk = "INCONCLUSIVE"
            finding.confidence = "LOW"
        else:
            finding.security_score = max(0, min(100, score))
            finding.risk = "LOW" if finding.security_score >= 75 else "MODERATE" if finding.security_score >= 55 else "HIGH"
            if known >= 5:
                finding.confidence = "HIGH"
            elif known >= 3:
                finding.confidence = "MEDIUM"
            else:
                finding.confidence = "LOW"
        return finding
