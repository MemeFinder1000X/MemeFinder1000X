"""Minimal read-only Solana RPC helpers for token authority verification."""
from __future__ import annotations
import base64, json, os, time
from typing import Any
from urllib.request import Request, urlopen

DEFAULT_RPC_URL = "https://api.mainnet-beta.solana.com"
RPC_TIMEOUT_SECONDS, CACHE_SECONDS = 8, 300
_cache: dict[str, tuple[float, dict[str,str]]] = {}


def _rpc_url() -> str: return os.getenv("SOLANA_RPC_URL", DEFAULT_RPC_URL).rstrip("/")


def _rpc(method: str, params: list[Any]) -> Any:
    body=json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":params}).encode()
    req=Request(_rpc_url(),data=body,headers={"Accept":"application/json","Content-Type":"application/json","User-Agent":"MemeFinder1000X/1.0"},method="POST")
    with urlopen(req,timeout=RPC_TIMEOUT_SECONDS) as response: payload=json.loads(response.read().decode())
    if payload.get("error"): raise RuntimeError(str(payload["error"]))
    return payload.get("result")


def _authority(option:int, raw:bytes)->str:
    if option==0: return "DISABLED"
    if option==1 and len(raw)==32: return "ACTIVE"
    return "UNKNOWN"


def get_mint_authorities(token_address:str)->dict[str,str]:
    """Read SPL Token Mint authority state from on-chain account bytes."""
    if not isinstance(token_address,str) or not 32 <= len(token_address) <= 44:
        raise ValueError("not a plausible Solana token address")
    cached=_cache.get(token_address)
    if cached and time.monotonic()-cached[0]<CACHE_SECONDS: return dict(cached[1])
    result=_rpc("getAccountInfo",[token_address,{"encoding":"base64","commitment":"confirmed"}])
    value=result.get("value") if isinstance(result,dict) else None
    if not isinstance(value,dict): raise RuntimeError("Solana RPC returned no mint account")
    data=value.get("data")
    if not isinstance(data,list) or not data or not isinstance(data[0],str): raise RuntimeError("Solana RPC returned unsupported mint encoding")
    raw=base64.b64decode(data[0])
    if len(raw)<82: raise RuntimeError("Solana RPC returned an invalid SPL mint account")
    finding={"mint_authority":_authority(int.from_bytes(raw[0:4],"little"),raw[4:36]),"freeze_authority":_authority(int.from_bytes(raw[46:50],"little"),raw[50:82])}
    _cache[token_address]=(time.monotonic(),finding)
    return dict(finding)
