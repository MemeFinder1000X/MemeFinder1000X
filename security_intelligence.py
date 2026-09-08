"""Conservative, read-only Solana token security analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


def _first(data: Any, *keys: str) -> Any:
    if not isinstance(data, dict):
        return None
    for key in keys:
        if key in data and data[key] is not None:
            return data[key]
    return None


def _percent(value: Any) -> float | None:
    if isinstance(value, dict):
        value = _first(value, "percent_of_supply", "percentOfSupply", "percent", "percentage", "supply_percent", "supplyPercent")
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
        return "DISABLED"
    if isinstance(value, bool):
        return "ACTIVE" if value else "DISABLED"
    text = str(value).strip().lower()
    if text in {"", "none", "null", "false", "0", "disabled", "revoked"}:
        return "DISABLED"
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
        item = data.get(tag)
        if isinstance(item, dict):
            return _percent(item)
        direct = _percent(_first(data, tag, f"{tag}_percent", f"{tag}Percent"))
        if direct is not None:
            return direct
    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            name = str(_first(item, "tag", "name", "label") or "").lower()
            if name == tag.lower():
                return _percent(item)
    return None


def _unwrap_data(value: Any) -> Any:
    """Unwrap repeated provider data envelopes without altering ordinary payloads."""
    current = value
    for _ in range(4):
        if isinstance(current, dict) and isinstance(current.get("data"), (dict, list)):
            current = current["data"]
        else:
            break
    return current


def _top10_from_profile(profile: dict[str, Any]) -> float | None:
    """Read documented and legacy top-10 holder concentration shapes."""
    candidates = [
        profile.get("top10_holder"),
        profile.get("top10Holder"),
        profile.get("top10_holder_percent"),
        profile.get("top10HolderPercent"),
    ]
    summary = profile.get("holder_summary")
    if isinstance(summary, dict):
        candidates.extend([
            summary.get("top10_holder"),
            summary.get("top10Holder"),
            summary.get("top10_holder_percent"),
            summary.get("top10HolderPercent"),
        ])
    for candidate in candidates:
        parsed = _percent(candidate)
        if parsed is not None:
            return parsed
    return None


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


class SecurityIntelligence:
    """Build an evidence-weighted security report without safety guarantees."""

    async def analyze(self, provider: Any, token_address: str) -> SecurityFinding:
        finding = SecurityFinding()
        try:
            security_raw = await provider.security_snapshot(token_address)
        except Exception as error:
            finding.unknown.append("Birdeye token security")
            finding.warnings.append("Token-security endpoint unavailable")
            finding.evidence.append(f"Birdeye token-security request failed: {error}")
            security_raw = None

        security = _unwrap_data(security_raw)
        if isinstance(security, dict):
            owner = _security_field(security, "ownerAddress", "owner_address")
            if "ownerAddress" in security or "owner_address" in security:
                finding.mint_authority = _authority_state(owner)
            else:
                renounced = _security_field(security, "renounced")
                mintable = _security_field(security, "mintable")
                if renounced is not None or mintable is not None:
                    finding.mint_authority = (
                        "DISABLED" if renounced is True or mintable is False
                        else "ACTIVE" if renounced is False or mintable is True
                        else "UNKNOWN"
                    )
                else:
                    finding.unknown.append("mint authority")

            freeze = _security_field(security, "freezeAuthority", "freeze_authority")
            freezeable = _security_field(security, "freezeable")
            if "freezeAuthority" in security or "freeze_authority" in security:
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

            top10 = _percent(_security_field(security, "top10HolderPercent", "top10_holder_percent", "top10Holder"))
            if top10 is not None:
                finding.top10_percent = top10

            creator_percent = _percent(_security_field(security, "creatorPercentage", "creator_percent"))
            if creator_percent is not None:
                finding.dev_percent = creator_percent

            creator = _security_field(security, "creatorAddress", "creator_address")
            if creator:
                finding.developer_wallet = str(creator)

            lock_info = _security_field(security, "lockInfo", "lock_info")
            if lock_info is not None:
                finding.lp_status = "LOCK INFO AVAILABLE"
                finding.lp_lock_burn = "PROVIDER REPORTED"
                finding.evidence.append("Birdeye token-security lockInfo available")

            finding.evidence.append("Birdeye token-security response available")
        else:
            finding.unknown.extend(["mint authority", "freeze authority", "honeypot assessment"])

        try:
            profile = _unwrap_data(await provider.holder_profile(token_address))
        except Exception as error:
            profile = None
            finding.unknown.append("holder profile")
            finding.evidence.append(f"Birdeye holder-profile request failed: {error}")

        if isinstance(profile, dict):
            profile_top10 = _top10_from_profile(profile)
            if profile_top10 is not None:
                finding.top10_percent = profile_top10
            tags = profile.get("tags", {})
            finding.dev_percent = finding.dev_percent if finding.dev_percent is not None else _tag_percent(tags, "dev")
            finding.insider_percent = _tag_percent(tags, "insider")
            finding.sniper_percent = _tag_percent(tags, "sniper")
            finding.bundler_percent = _tag_percent(tags, "bundler")
            dev_tag = tags.get("dev") if isinstance(tags, dict) else None
            if isinstance(dev_tag, dict):
                finding.developer_wallet = str(_first(dev_tag, "address", "wallet", "wallet_address") or finding.developer_wallet)
            finding.evidence.append("Birdeye holder-profile data available")

        if finding.top10_percent is None and hasattr(provider, "holder_distribution"):
            try:
                distribution = _unwrap_data(await provider.holder_distribution(token_address))
                if isinstance(distribution, dict):
                    summary = distribution.get("summary") if isinstance(distribution.get("summary"), dict) else distribution
                    finding.top10_percent = _percent(_first(summary, "percent_of_supply", "percentOfSupply", "top10_holder_percent", "top10HolderPercent"))
                    if finding.top10_percent is not None:
                        finding.evidence.append("Birdeye holder-distribution top-10 concentration available")
            except Exception as error:
                finding.unknown.append("holder distribution")
                finding.evidence.append(f"Birdeye holder-distribution request failed: {error}")

        if finding.lp_lock_burn == "UNKNOWN":
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
            if finding.top10_percent >= 90:
                score -= 45
                finding.warnings.append(f"Top-10 holders control {finding.top10_percent:.1f}%")
            elif finding.top10_percent >= 70:
                score -= 30
                finding.warnings.append(f"Top-10 holders control {finding.top10_percent:.1f}%")
            elif finding.top10_percent >= 50:
                score -= 20
                finding.warnings.append(f"Top-10 holders control {finding.top10_percent:.1f}%")
            elif finding.top10_percent >= 30:
                score -= 10
                finding.warnings.append(f"Top-10 holders control {finding.top10_percent:.1f}%")
        for label, value in (("developer", finding.dev_percent), ("insider", finding.insider_percent), ("sniper", finding.sniper_percent), ("bundler", finding.bundler_percent)):
            if value is not None:
                known += 1
                if value >= 15:
                    score -= 10
                    finding.warnings.append(f"High {label} cohort concentration: {value:.1f}%")

        critical_unknowns = sum(
            value == "UNKNOWN"
            for value in (finding.mint_authority, finding.freeze_authority, finding.lp_status, finding.lp_lock_burn)
        )
        if critical_unknowns >= 3:
            score -= 10
            finding.warnings.append("Multiple critical security checks remain unverified")
        elif critical_unknowns >= 2:
            score -= 5

        # Concentration this extreme is not compatible with a moderate/low risk label.
        # Keep the result conservative when provider evidence is incomplete.
        if finding.top10_percent is not None and finding.top10_percent >= 90:
            score = min(score, 25)
        elif finding.top10_percent is not None and finding.top10_percent >= 70:
            score = min(score, 40)

        if known == 0:
            finding.security_score = None
            finding.risk = "INCONCLUSIVE"
            finding.confidence = "LOW"
        else:
            finding.security_score = max(0, min(100, score))
            finding.risk = "LOW" if finding.security_score >= 75 else "MODERATE" if finding.security_score >= 55 else "HIGH"
            finding.confidence = "HIGH" if known >= 5 else "MEDIUM" if known >= 3 else "LOW"
        return finding
