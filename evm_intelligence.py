"""Read-only EVM holder concentration intelligence using public JSON-RPC.

This module intentionally avoids trading, private keys, or paid indexing APIs.
It is conservative: only recent tokens with a bounded Transfer-log window are
analyzed. If the snapshot cannot be completed safely, it returns UNKNOWN.
"""
from __future__ import annotations

import asyncio
import json
import time
from typing import Any
from urllib.request import Request, urlopen


EVM_RPC = {
    "ethereum": "https://eth.llamarpc.com",
    "arbitrum": "https://arb1.arbitrum.io/rpc",
    "base": "https://mainnet.base.org",
    "optimism": "https://mainnet.optimism.io",
    "polygon": "https://polygon-rpc.com",
    "bsc": "https://bsc-dataseed.binance.org",
    "avalanche": "https://api.avax.network/ext/bc/C/rpc",
    "linea": "https://rpc.linea.build",
    "fantom": "https://rpc.ankr.com/fantom",
    "cronos": "https://evm.cronos.org",
}

# keccak256("Transfer(address,address,uint256)")
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a9df523b3ef"
ZERO_ADDRESS = "0x" + "0" * 40
MAX_AGE_SECONDS = 6 * 60 * 60
MAX_HOLDERS = 2000
MAX_LOGS = 5000
LOG_CHUNK = 2000
BALANCE_BATCH = 100

BLOCK_TIME = {
    "ethereum": 12.0,
    "arbitrum": 0.25,
    "base": 2.0,
    "optimism": 2.0,
    "polygon": 2.0,
    "bsc": 1.5,
    "avalanche": 2.0,
    "linea": 6.0,
    "fantom": 1.0,
    "cronos": 5.0,
}


def _rpc_call_sync(url: str, payload: Any) -> Any:
    request = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Accept": "application/json", "Content-Type": "application/json", "User-Agent": "MemeFinder1000X/1.0"},
        method="POST",
    )
    with urlopen(request, timeout=12) as response:
        return json.loads(response.read().decode("utf-8"))


async def _rpc(url: str, payload: Any) -> Any:
    return await asyncio.to_thread(_rpc_call_sync, url, payload)


def _hex_int(value: Any) -> int | None:
    try:
        return int(str(value), 16)
    except (TypeError, ValueError):
        return None


def _address_from_topic(topic: str) -> str:
    return "0x" + str(topic)[-40:].lower()


def _age_seconds(pair: dict[str, Any]) -> float | None:
    created_ms = pair.get("pairCreatedAt")
    try:
        created = float(created_ms) / 1000
    except (TypeError, ValueError):
        return None
    if created <= 0:
        return None
    return max(0.0, time.time() - created)


async def _logs(url: str, token: str, start: int, end: int) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for chunk_start in range(start, end + 1, LOG_CHUNK):
        chunk_end = min(end, chunk_start + LOG_CHUNK - 1)
        result = await _rpc(
            url,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "eth_getLogs",
                "params": [{
                    "address": token,
                    "fromBlock": hex(chunk_start),
                    "toBlock": hex(chunk_end),
                    "topics": [TRANSFER_TOPIC],
                }],
            },
        )
        if not isinstance(result, dict) or result.get("error"):
            raise RuntimeError("EVM Transfer-log query failed")
        batch = result.get("result") or []
        if not isinstance(batch, list):
            raise RuntimeError("EVM Transfer-log response was malformed")
        events.extend(item for item in batch if isinstance(item, dict))
        if len(events) > MAX_LOGS:
            raise RuntimeError("EVM Transfer-log window is too large")
    return events


async def _balances(url: str, token: str, addresses: list[str]) -> dict[str, int]:
    balances: dict[str, int] = {}
    for offset in range(0, len(addresses), BALANCE_BATCH):
        batch = addresses[offset : offset + BALANCE_BATCH]
        payload = []
        for index, address in enumerate(batch):
            data = "0x70a08231" + address[2:].rjust(64, "0")
            payload.append({
                "jsonrpc": "2.0",
                "id": index + 1,
                "method": "eth_call",
                "params": [{"to": token, "data": data}, "latest"],
            })
        result = await _rpc(url, payload)
        if not isinstance(result, list):
            raise RuntimeError("EVM balance batch response was malformed")
        for item, address in zip(result, batch):
            if not isinstance(item, dict) or item.get("error"):
                continue
            value = _hex_int(item.get("result"))
            if value is not None and value > 0:
                balances[address] = value
    return balances


async def enrich_evm_pair(pair: dict[str, Any]) -> dict[str, Any]:
    """Return conservative holder intelligence for a recent EVM token."""
    chain = str(pair.get("chainId") or "").lower()
    token = str((pair.get("baseToken") or {}).get("address") or "").strip()
    if chain not in EVM_RPC or not token.startswith("0x") or len(token) != 42:
        return {"status": "UNKNOWN", "holder_count": None, "top10_percent": None, "reason": "unsupported EVM token"}

    age = _age_seconds(pair)
    if age is None or age > MAX_AGE_SECONDS:
        return {"status": "UNKNOWN", "holder_count": None, "top10_percent": None, "reason": "outside recent EVM snapshot window"}

    url = EVM_RPC[chain]
    try:
        latest_result = await _rpc(url, {"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []})
        latest = _hex_int(latest_result.get("result")) if isinstance(latest_result, dict) else None
        if latest is None:
            raise RuntimeError("latest EVM block unavailable")
        estimated_blocks = max(1, int(age / BLOCK_TIME.get(chain, 2.0)) + 100)
        start = max(0, latest - estimated_blocks)
        events = await _logs(url, token, start, latest)

        holders: set[str] = set()
        for event in events:
            topics = event.get("topics") or []
            if len(topics) < 3:
                continue
            sender = _address_from_topic(topics[1])
            receiver = _address_from_topic(topics[2])
            if sender != ZERO_ADDRESS:
                holders.add(sender)
            if receiver != ZERO_ADDRESS:
                holders.add(receiver)
            if len(holders) > MAX_HOLDERS:
                return {"status": "UNKNOWN", "holder_count": None, "top10_percent": None, "reason": "holder set too large for safe RPC snapshot"}

        if not holders:
            return {"status": "UNKNOWN", "holder_count": None, "top10_percent": None, "reason": "no ERC20 Transfer holders found"}

        balances = await _balances(url, token, sorted(holders))
        live = sorted(((address, balance) for address, balance in balances.items() if balance > 0), key=lambda item: item[1], reverse=True)
        if not live:
            return {"status": "UNKNOWN", "holder_count": None, "top10_percent": None, "reason": "no live ERC20 balances returned"}

        total_supply_result = await _rpc(
            url,
            {"jsonrpc": "2.0", "id": 1, "method": "eth_call", "params":[{"to": token, "data": "0x18160ddd"}, "latest"]},
        )
        total_supply = _hex_int(total_supply_result.get("result")) if isinstance(total_supply_result, dict) else None
        if not total_supply or total_supply <= 0:
            return {"status": "PARTIAL", "holder_count": len(live), "top10_percent": None, "reason": "totalSupply unavailable"}

        top10 = sum(balance for _, balance in live[:10]) / total_supply * 100
        return {
            "status": "VERIFIED",
            "holder_count": len(live),
            "top10_percent": round(min(100.0, top10), 2),
            "holder_source": "EVM public RPC Transfer + balanceOf snapshot",
            "scanned_transfer_events": len(events),
        }
    except Exception as exc:
        return {"status": "UNKNOWN", "holder_count": None, "top10_percent": None, "reason": str(exc)[:160]}
