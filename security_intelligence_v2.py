"""Read-only Solana security intelligence with on-chain authority verification."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any
from solana_rpc import get_mint_authorities


def pct(v: Any) -> float | None:
    if isinstance(v, dict):
        v = next((v.get(k) for k in ("percent_of_supply","percentOfSupply","percent","percentage") if v.get(k) is not None), None)
    try: n = float(v)
    except (TypeError, ValueError): return None
    if n < 0: return None
    if n <= 1: n *= 100
    return n if n <= 100 else None


def first(d: Any, *keys: str) -> Any:
    if not isinstance(d, dict): return None
    for k in keys:
        if d.get(k) is not None: return d[k]
    return None


def unwrap(v: Any) -> Any:
    for _ in range(4):
        if isinstance(v, dict) and isinstance(v.get("data"), (dict,list)): v = v["data"]
        else: break
    return v


def authority(v: Any) -> str:
    if v is None or isinstance(v, bool) and not v: return "DISABLED"
    s = str(v).strip().lower()
    return "DISABLED" if s in {"","none","null","false","0","disabled","revoked","11111111111111111111111111111111"} else "ACTIVE"


def top10(profile: dict[str,Any]) -> float | None:
    vals = [profile.get(k) for k in ("top10_holder","top10Holder","top10_holder_percent","top10HolderPercent")]
    summary = profile.get("holder_summary")
    if isinstance(summary,dict): vals += [summary.get(k) for k in ("top10_holder","top10Holder","top10_holder_percent","top10HolderPercent")]
    return next((p for v in vals if (p:=pct(v)) is not None), None)


def tagpct(tags: Any, name: str) -> float | None:
    if isinstance(tags,dict): return pct(tags.get(name) or tags.get(f"{name}_percent") or tags.get(f"{name}Percent"))
    if isinstance(tags,list):
        for item in tags:
            if isinstance(item,dict) and str(first(item,"tag","name","label") or "").lower()==name: return pct(item)
    return None

@dataclass
class SecurityFinding:
    security_score: int|None = None
    risk: str = "INCONCLUSIVE"
    confidence: str = "LOW"
    mint_authority: str = "UNKNOWN"
    freeze_authority: str = "UNKNOWN"
    honeypot: str = "UNKNOWN"
    lp_status: str = "UNKNOWN"
    lp_lock_burn: str = "UNKNOWN"
    top10_percent: float|None = None
    dev_percent: float|None = None
    insider_percent: float|None = None
    sniper_percent: float|None = None
    bundler_percent: float|None = None
    developer_wallet: str = "UNKNOWN"
    developer_selling: str = "UNKNOWN"
    suspicious_activity: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    unknown: list[str] = field(default_factory=list)

class SecurityIntelligence:
    async def analyze(self, provider: Any, token_address: str, top10_hint: Any=None) -> SecurityFinding:
        f=SecurityFinding()
        try: sec=unwrap(await provider.security_snapshot(token_address))
        except Exception as e: sec=None; f.warnings.append("Token-security endpoint unavailable"); f.evidence.append(f"Birdeye token-security request failed: {e}")
        if isinstance(sec,dict):
            owner=first(sec,"ownerAddress","owner_address")
            if "ownerAddress" in sec or "owner_address" in sec: f.mint_authority=authority(owner)
            else:
                renounced,mintable=first(sec,"renounced"),first(sec,"mintable")
                if renounced is not None or mintable is not None: f.mint_authority="DISABLED" if renounced is True or mintable is False else "ACTIVE" if renounced is False or mintable is True else "UNKNOWN"
            freeze=first(sec,"freezeAuthority","freeze_authority")
            if "freezeAuthority" in sec or "freeze_authority" in sec: f.freeze_authority=authority(freeze)
            elif first(sec,"freezeable") is not None: f.freeze_authority="ACTIVE" if bool(first(sec,"freezeable")) else "DISABLED"
            hp=first(sec,"honeypot","isHoneypot","honeypotRisk")
            if hp is not None: f.honeypot="YES" if str(hp).lower() in {"true","1","yes","high","danger"} else "NO"
            f.top10_percent=pct(first(sec,"top10HolderPercent","top10_holder_percent","top10Holder"))
            f.dev_percent=pct(first(sec,"creatorPercentage","creator_percent"))
            creator=first(sec,"creatorAddress","creator_address")
            if creator: f.developer_wallet=str(creator)
            if first(sec,"lockInfo","lock_info") is not None: f.lp_status,f.lp_lock_burn="LOCK INFO AVAILABLE","PROVIDER REPORTED"
            f.evidence.append("Birdeye token-security response available")
        try: profile=unwrap(await provider.holder_profile(token_address))
        except Exception as e: profile=None; f.evidence.append(f"Birdeye holder-profile request failed: {e}")
        if isinstance(profile,dict):
            p=top10(profile)
            if p is not None: f.top10_percent=p
            tags=profile.get("tags",{})
            f.dev_percent=f.dev_percent if f.dev_percent is not None else tagpct(tags,"dev")
            f.insider_percent,f.sniper_percent,f.bundler_percent=tagpct(tags,"insider"),tagpct(tags,"sniper"),tagpct(tags,"bundler")
            dt=tags.get("dev") if isinstance(tags,dict) else None
            if isinstance(dt,dict): f.developer_wallet=str(first(dt,"address","wallet","wallet_address") or f.developer_wallet)
            f.evidence.append("Birdeye holder-profile data available")
        if f.top10_percent is None and hasattr(provider,"holder_distribution"):
            try:
                d=unwrap(await provider.holder_distribution(token_address)); s=d.get("summary") if isinstance(d,dict) and isinstance(d.get("summary"),dict) else d
                if isinstance(s,dict): f.top10_percent=pct(first(s,"percent_of_supply","percentOfSupply","top10_holder_percent","top10HolderPercent"))
            except Exception as e: f.evidence.append(f"Birdeye holder-distribution request failed: {e}")
        hinted=pct(top10_hint)
        if hinted is not None and (f.top10_percent is None or hinted>f.top10_percent): f.top10_percent=hinted; f.evidence.append("Top-10 concentration propagated from Birdeye holder analysis")

        if f.mint_authority=="UNKNOWN" or f.freeze_authority=="UNKNOWN":
            try:
                onchain=await __import__("asyncio").to_thread(get_mint_authorities,token_address)
                if f.mint_authority=="UNKNOWN": f.mint_authority=onchain.get("mint_authority","UNKNOWN")
                if f.freeze_authority=="UNKNOWN": f.freeze_authority=onchain.get("freeze_authority","UNKNOWN")
                if "Token-security endpoint unavailable" in f.warnings:
                    f.warnings.remove("Token-security endpoint unavailable")
                    f.warnings.append("Birdeye token-security unavailable; LP checks remain unverified.")
                    f.warnings.append("Mint/freeze authorities verified on-chain.")
                f.evidence.append("Solana RPC SPL Mint authority state verified on-chain")
            except Exception as e: f.evidence.append(f"Solana RPC authority verification unavailable: {e}")
        if f.lp_lock_burn=="UNKNOWN": f.unknown.append("LP lock/burn proof")
        score,known=70,0
        for state,penalty,label in ((f.mint_authority,20,"Mint"),(f.freeze_authority,20,"Freeze")):
            if state!="UNKNOWN": known+=1
            if state=="ACTIVE": score-=penalty; f.warnings.append(f"{label} authority is active")
        if f.honeypot!="UNKNOWN": known+=1; score-=45 if f.honeypot=="YES" else 0
        if f.top10_percent is not None:
            known+=1; v=f.top10_percent; score-=45 if v>=90 else 30 if v>=70 else 20 if v>=50 else 10 if v>=30 else 0
            if v>=30: f.warnings.append(f"Top-10 holders control {v:.1f}%")
        for label,v in (("developer",f.dev_percent),("insider",f.insider_percent),("sniper",f.sniper_percent),("bundler",f.bundler_percent)):
            if v is not None: known+=1; score-=10 if v>=15 else 0
            if v is not None and v>=15: f.warnings.append(f"High {label} cohort concentration: {v:.1f}%")
        unknowns=sum(x=="UNKNOWN" for x in (f.mint_authority,f.freeze_authority,f.lp_status,f.lp_lock_burn))
        if unknowns>=3: score-=10; f.warnings.append("Multiple critical security checks remain unverified")
        elif unknowns>=2: score-=5
        if f.top10_percent is not None and f.top10_percent>=90: score=min(score,25)
        elif f.top10_percent is not None and f.top10_percent>=70: score=min(score,40)
        if known==0: return f
        f.security_score=max(0,min(100,score)); f.risk="LOW" if score>=75 else "MODERATE" if score>=55 else "HIGH"; f.confidence="HIGH" if known>=5 else "MEDIUM" if known>=3 else "LOW"
        return f
