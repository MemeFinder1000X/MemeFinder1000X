"""Conservative, read-only Solana token security analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SecurityFinding:
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
        if data.get(key) is not None:
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
    # Solana's system program is the null/disabled authority in Birdeye's
    # security glossary as well as an explicit null value.
    if text == "11111111111111111111111111111111":
        return "DISABLED"
    return "ACTIVE"


def _security_field(data: dict[str, Any], *keys: str) -> Any:
    value = _first(data, *keys)
    if value is not None:
        return value
    nested = data.get("security")
    return _first(nested, *keys)


def _tag_percent(data: Any, tag: str) -> float | None:
    if isinstance(data, dict):
        direct = _percent(
            _first(data, tag, f"{tag}_percent", f"{tag}Percent", "percent_of_supply")
        )
        if direct is not None:
            return direct
        item = data.get(tag)
        if isinstance(item, dict):
            return _percent(
                _first(item, "percent_of_supply", "percent", "percentage", "supply_percent", "supplyPercent")
            )
    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            name = str(_first(item, "tag", "name", "label") or "").lower()
            if name == tag.lower():
                return _percent(
                    _first(item, "percent_of_supply", "percent", "percentage", "supply_percent", "supplyPercent")
                )
    return None


def _unwrap_data(value: Any) -> Any:
    if isinstance(value, dict) and isinstance(value.get("data"), (dict, list)):
        return value["data"]
    return value


class SecurityIntelligence:
    """Build an evidence-weighted security report without safety guarantees."""

    async def analyze(self, provider: Any, token_address: str) -> SecurityFinding:
        finding = SecurityFinding()
        try:
            snapshot = await provider.analyze_token(token_address)
        except Exception:
            finding.unknown.append("Birdeye security enrichment unavailable")
            finding.warnings.append("Security data could not be retrieved")
            return finding

        profile = None
        distribution = None
        try:
            profile = await provider._get(
                "/token/v1/holder-profile",
                {
                    "token_address": token_address,
                    "interval": "1h",
                    "include_zero_balance": "false",
                },
            )
        except Exception:
            finding.unknown.append("holder profile")
        try:
            distribution = await provider._get(
                "/holder/v1/distribution",
                {
                    "token_address": token_address,
                    "address_type": "wallet",
                    "mode": "top",
                    "top_n": 10,
                    "include_list": "false",
                },
            )
        except Exception:
            finding.unknown.append("holder distribution")

        security = _unwrap_data(snapshot.data.get("token_security"))
        if isinstance(security, dict):
            # Birdeye's current security glossary exposes ownerAddress/renounced
            # and freezeAuthority/freezeable rather than a generic mintAuthority.
            owner = _security_field(security, "ownerAddress", "owner_address")
            renounced = _security_field(security, "renounced")
            mintable = _security_field(security, "mintable")
            if owner is not None:
                finding.mint_authority = _authority_state(owner)
            elif renounced is not None or mintable is not None:
                finding.mint_authority = (
                    "DISABLED"
                    if renounced is True or mintable is False
                    else "ACTIVE"
                    if renounced is False or mintable is True
                    else "UNKNOWN"
                )
            else:
                finding.unknown.append("mint authority")

            freeze = _security_field(security, "freezeAuthority", "freeze_authority")
            freezeable = _security_field(security, "freezeable")
            if freeze is not None:
                finding.freeze_authority = _authority_state(freeze)
            elif freezeable is not None:
                finding.freeze_authority = "ACTIVE" if bool(freezeable) else "DISABLED"
            else:
                finding.unknown.append("freeze authority")

            honeypot = _security_field(security, "honeypot", "isHoneypot", "honeypotRisk")
            if honeypot is not None:
                text = str(honeypot).strip().lower()
                finding.honeypot = "YES" if text in {"true", "1", "yes", "high", "danger"} else "NO"
            else:
                finding.unknown.append("honeypot assessment")
            finding.evidence.append("Birdeye token-security response available")
        else:
            finding.unknown.extend(["mint authority", "freeze authority", "honeypot assessment"])

        holders = _unwrap_data(snapshot.data.get("token_holders"))
        if isinstance(holders, dict):
            finding.top10_percent = _percent(
                _first(holders, "top10_holder_percent", "top10HolderPercent")
            )

        profile = _unwrap_data(profile)
        if isinstance(profile, dict):
            summary = profile.get("holder_summary") if isinstance(profile.get("holder_summary"), dict) else profile
            finding.top10_percent = (
                _percent(_first(summary, "top10_holder", "top10_holder_percent", "top10HolderPercent"))
                or finding.top10_percent
            )
            tags = profile.get("tags", {})
            finding.dev_percent = _tag_percent(tags, "dev")
            finding.insider_percent = _tag_percent(tags, "insider")
            finding.sniper_percent = _tag_percent(tags, "sniper")
            finding.bundler_percent = _tag_percent(tags, "bundler")
            dev_tag = tags.get("dev") if isinstance(tags, dict) else None
            if isinstance(dev_tag, dict):
                finding.developer_wallet = str(
                    _first(dev_tag, "address", "wallet", "wallet_address") or finding.developer_wallet
                )
            finding.evidence.append("Birdeye holder-profile data available")

        distribution = _unwrap_data(distribution)
        if isinstance(distribution, dict):
            summary = distribution.get("summary") if isinstance(distribution.get("summary"), dict) else distribution
            distribution_top10 = _percent(
                _first(summary, "percent_of_supply", "top10_percent", "top10HolderPercent", "top10_holder_percent")
            )
            # Only accept distribution summary as top-10 when the request was
            # actually made in top-10 mode; the request above is fixed to that mode.
            if finding.top10_percent is None:
                finding.top10_percent = distribution_top10
            finding.evidence.append("Birdeye holder-distribution data available")

        creation = _unwrap_data(snapshot.data.get("token_creation_info"))
        if isinstance(creation, dict):
            creator = _first(creation, "creator", "creatorAddress", "owner", "deployer", "creator_address")
            if creator and finding.developer_wallet == "UNKNOWN":
                finding.developer_wallet = str(creator)
            if creator:
                finding.evidence.append("Developer/creator address observed in creation data")

        liquidity = _unwrap_data(snapshot.data.get("liquidity_history"))
        if isinstance(liquidity, (dict, list)):
            # Endpoint availability is evidence that liquidity history could be
            # inspected, not proof that liquidity is locked or safe.
            finding.lp_status = "OBSERVED"
            finding.evidence.append("Birdeye liquidity-history endpoint returned")
        else:
            finding.unknown.append("historical liquidity / LP status")

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
        for label, value in (
            ("developer", finding.dev_percent),
            ("insider", finding.insider_percent),
            ("sniper", finding.sniper_percent),
            ("bundler", finding.bundler_percent),
        ):
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
            finding.risk = (
                "LOW" if finding.security_score >= 75
                else "MODERATE" if finding.security_score >= 55
                else "HIGH"
            )
            finding.confidence = "HIGH" if known >= 5 else "MEDIUM" if known >= 3 else "LOW"
        return finding
