"""Read-only presentation cleanup for MemeFinder scan cards."""
from __future__ import annotations

import re
from typing import Any


def _number(value: Any) -> float | None:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    return result if result == result else None


def normalize_developer_display(pair: dict[str, Any]) -> None:
    """Replace verbose/truncated developer diagnostics with concise evidence."""
    developer = pair.get("_developer")
    if not isinstance(developer, dict):
        return
    coverage = str(developer.get("history_coverage") or "UNKNOWN")
    evidence = str(developer.get("evidence") or "UNKNOWN")
    confidence = str(developer.get("identity_confidence") or "UNKNOWN").upper()

    match = re.search(r"Birdeye returned (\d+) wallet-token P&L observation\(s\)", coverage, re.I)
    if match and "no explicit mint initialization" in coverage.lower():
        count = match.group(1)
        sig_match = re.search(r"latest (\d+) inspected signatures", coverage, re.I)
        sigs = sig_match.group(1) if sig_match else "12"
        developer["history_coverage"] = (
            f"{count} wallet-token observations; no explicit mint initialization "
            f"in latest {sigs} RPC signatures. Prior launch history unverified."
        )
    elif len(coverage) > 150:
        developer["history_coverage"] = coverage[:147] + "…"

    if "PROBABLE FIRST-TRANSACTION SIGNER" in confidence:
        developer["evidence"] = (
            "Probable first-transaction signer from Solana RPC; creator identity "
            "and prior launch history are unverified."
        )
    elif "EXPLICIT CREATOR/DEPLOYER" in confidence and len(evidence) > 180:
        developer["evidence"] = evidence[:177] + "…"


def annotate_opportunity_label(text: str, pair: dict[str, Any]) -> str:
    """Explain when the displayed opportunity score was reduced by security evidence."""
    analysis = pair.get("_analysis") or {}
    raw = _number(analysis.get("raw_opportunity_score"))
    adjusted = _number(analysis.get("opportunity_score"))
    penalty = _number(analysis.get("opportunity_adjustment"))
    if raw is None or adjusted is None or penalty is None or penalty <= 0 or raw == adjusted:
        return text
    return re.sub(
        r"Opportunity: ([0-9]+(?:\.[0-9]+)?)/100",
        f"Opportunity: {int(adjusted)}/100 (security-adjusted from {int(raw)})",
        text,
        count=1,
    )
