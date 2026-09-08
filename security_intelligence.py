"""Compatibility entrypoint for MemeFinder security intelligence."""
from __future__ import annotations

import logging
from typing import Any

from security_intelligence_v2 import SecurityFinding, SecurityIntelligence

logger = logging.getLogger(__name__)


def _diagnostic_key_paths(value: Any, prefix: str = "", depth: int = 0) -> list[str]:
    """Return only liquidity/LP-related key paths; never log response values."""
    if depth > 5:
        return []
    matches: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            path = f"{prefix}.{key_text}" if prefix else key_text
            lowered = key_text.lower()
            if any(term in lowered for term in ("liquidity", "lp", "lock", "burn")):
                matches.append(path)
            matches.extend(_diagnostic_key_paths(child, path, depth + 1))
    elif isinstance(value, list):
        for index, child in enumerate(value[:20]):
            matches.extend(_diagnostic_key_paths(child, f"{prefix}[{index}]", depth + 1))
    return matches


def _install_security_diagnostic() -> None:
    """Wrap the provider security call so production logs reveal payload shape only."""
    try:
        from birdeye_provider import BirdeyeProvider
    except Exception:
        return
    if getattr(BirdeyeProvider, "_mf_security_diagnostic_installed", False):
        return
    original = BirdeyeProvider.security_snapshot

    async def diagnostic_security_snapshot(self: Any, token_address: str) -> Any:
        try:
            data = await original(self, token_address)
        except Exception as exc:
            logger.warning("Birdeye security diagnostic: token-security request failed: %s", exc)
            raise
        paths = sorted(set(_diagnostic_key_paths(data)))
        if paths:
            logger.warning("Birdeye security diagnostic: LP/liquidity-related keys returned: %s", ", ".join(paths[:80]))
        else:
            logger.warning("Birdeye security diagnostic: NO LP/liquidity-related keys returned by token-security")
        return data

    BirdeyeProvider.security_snapshot = diagnostic_security_snapshot
    BirdeyeProvider._mf_security_diagnostic_installed = True


_install_security_diagnostic()

__all__ = ["SecurityFinding", "SecurityIntelligence"]
