"""Read-only developer intelligence providers for MemeFinder.

The provider boundary is intentionally small so indexed sources such as
Solscan, Birdeye, GMGN, or FOMO can be added without changing the scanner.
No provider in this module signs transactions or requires a private key.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from birdeye_provider import BirdeyeProvider, BirdeyeSnapshot

logger = logging.getLogger(__name__)

SOLANA_RPC_URL = "https://api.mainnet-beta.solana.com"
RPC_TIMEOUT_SECONDS = 10
RPC_MAX_RETRIES = 2
RPC_REQUEST_INTERVAL_SECONDS = 0.4
SOLSCAN_API = "https://pro-api.solscan.io"
SOLSCAN_API_KEY_ENV = "SOLSCAN_API_KEY"
SOLSCAN_TIMEOUT_SECONDS = 12
SOLSCAN_MAX_RETRIES = 3
SOLSCAN_REQUEST_INTERVAL_SECONDS = 0.4
SOLSCAN_HISTORY_PAGE_SIZE = 40
SOLSCAN_MAX_HISTORY_PAGES = 10
SOLSCAN_HISTORY_TIMEOUT_SECONDS = 15
SOLANA_TOKEN_PROGRAM_ID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss823yt"
SOLANA_TOKEN_2022_PROGRAM_ID = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
SOLANA_MINT_PROGRAM_IDS = (
    SOLANA_TOKEN_PROGRAM_ID,
    SOLANA_TOKEN_2022_PROGRAM_ID,
)
MAX_CREATOR_LOOKUPS_PER_SCAN = 3
MAX_WALLET_HISTORY_SIGNATURES = 12
MIN_HISTORICAL_LAUNCHES = 5
MIN_HISTORICAL_DECISIONS = 5
HIGH_DEVELOPER_SCORE = 75


@dataclass
class DeveloperFinding:
    """Evidence-bounded developer information shown by /scan."""

    developer: str = "UNKNOWN"
    developer_label: str = "Probable Developer"
    identity_confidence: str = "UNKNOWN"
    previous_launches: str = "UNKNOWN"
    successful_launches: str = "UNKNOWN"
    failed_launches: str = "UNKNOWN"
    suspected_rug_launches: str = "UNKNOWN"
    best_previous_launch: str = "UNKNOWN"
    highest_historical_market_cap: str = "UNKNOWN"
    historical_liquidity: str = "UNKNOWN"
    liquidity_activity: str = "UNKNOWN"
    selling_behavior: str = "UNKNOWN"
    major_activity_timing: str = "UNKNOWN"
    recent_launch_activity: str = "UNKNOWN"
    developer_score: str = "UNKNOWN"
    reputation: str = "UNKNOWN"
    risk: str = "UNKNOWN"
    evidence: str = "UNKNOWN — no indexed developer-history source is configured."
    history_coverage: str = "UNKNOWN"
    evidence_sources: list[str] = field(default_factory=list)


class DeveloperProvider:
    """Interface for chain-specific, read-only developer intelligence."""

    async def analyze(self, pair: dict[str, Any]) -> DeveloperFinding:
        raise NotImplementedError


class UnknownDeveloperProvider(DeveloperProvider):
    """Safe fallback when a chain/provider cannot supply the required data."""

    async def analyze(self, pair: dict[str, Any]) -> DeveloperFinding:
        chain = str(pair.get("chainId") or "unknown")
        return DeveloperFinding(
            evidence=(
                f"Unknown — no read-only creator/history source is configured for "
                f"the {chain} chain."
            )
        )


class SolscanError(Exception):
    """Raised when the documented Solscan provider cannot return usable data."""


class SolscanPermissionError(SolscanError):
    """Raised when the Solscan key is missing permission for an endpoint."""


class SolanaRpcDeveloperProvider(DeveloperProvider):
    """Conservative creator hint from Solana's public JSON-RPC methods.

    This does not claim that the first signer is the token creator. It only
    reports a probable signer when the mint's transaction history and parsed
    transaction are both available. A separate bounded probe can observe SPL
    mint initialization instructions, but it does not claim complete history.
    """

    def __init__(self) -> None:
        self._last_request_at = 0.0
        self._request_lock = asyncio.Lock()

    async def _rpc(self, method: str, params: list[Any]) -> Any:
        payload = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        ).encode("utf-8")
        last_error: Exception | None = None
        for attempt in range(RPC_MAX_RETRIES):
            async with self._request_lock:
                wait = RPC_REQUEST_INTERVAL_SECONDS - (
                    time.monotonic() - self._last_request_at
                )
                if wait > 0:
                    await asyncio.sleep(wait)
                self._last_request_at = time.monotonic()
            request = Request(
                SOLANA_RPC_URL,
                data=payload,
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "User-Agent": "MemeFinder1000X/1.0",
                },
                method="POST",
            )
            try:
                response = await asyncio.to_thread(
                    urlopen, request, timeout=RPC_TIMEOUT_SECONDS
                )
                with response:
                    decoded = json.loads(response.read().decode("utf-8"))
                if decoded.get("error"):
                    raise RuntimeError(str(decoded["error"]))
                return decoded.get("result")
            except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError, RuntimeError) as error:
                last_error = error
                if attempt < RPC_MAX_RETRIES - 1:
                    await asyncio.sleep(2**attempt)
        raise RuntimeError("Solana RPC unavailable") from last_error

    async def analyze(self, pair: dict[str, Any]) -> DeveloperFinding:
        mint = str((pair.get("baseToken") or {}).get("address") or "")
        if not mint:
            return DeveloperFinding(evidence="Unknown — token mint address is missing.")

        try:
            signatures = await self._rpc(
                "getSignaturesForAddress",
                [mint, {"limit": 1000, "commitment": "finalized"}],
            )
            if not isinstance(signatures, list) or not signatures:
                return DeveloperFinding(
                    evidence=(
                        "Unknown — Solana RPC returned no mint transaction history; "
                        "creator and launch history could not be established."
                    )
                )

            # The RPC returns newest first. This is the oldest transaction in
            # the returned page, not necessarily the token's true first ever tx.
            oldest = signatures[-1]
            signature = oldest.get("signature") if isinstance(oldest, dict) else None
            if not signature:
                return DeveloperFinding(
                    evidence="Unknown — the oldest available RPC signature was malformed."
                )
            transaction = await self._rpc(
                "getTransaction",
                [signature, {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0}],
            )
            signer = self._first_signer(transaction)
            if not signer:
                return DeveloperFinding(
                    evidence=(
                        "Unknown — Solana RPC returned the earliest available "
                        "transaction but no unambiguous signer."
                    )
                )
            return DeveloperFinding(
                developer_label="Probable Developer",
                identity_confidence="PROBABLE FIRST-TRANSACTION SIGNER",
                developer=signer,
                evidence=(
                    "Probable first-transaction signer from Solana RPC. "
                    "This is not proof of creator identity; the returned RPC page "
                    "may not include the true mint creation transaction. "
                    "Previous-launch history requires an indexed wallet data source."
                ),
            )
        except Exception as error:
            logger.info("Solana developer lookup unavailable for %s: %s", mint, error)
            return DeveloperFinding(
                evidence=(
                    "Unknown — Solana RPC creator lookup was unavailable; "
                    "indexed launch-history data is not configured."
                )
            )

    async def find_wallet_launches(self, wallet: str) -> list[dict[str, str]]:
        """Find only explicit SPL mint initializations signed by this wallet.

        Public RPC is not an indexed launch database. This bounded probe returns
        observed launches only, and never treats a transfer or token trade as a
        launch.
        """
        if not wallet:
            return []
        signatures = await self._rpc(
            "getSignaturesForAddress",
            [wallet, {"limit": MAX_WALLET_HISTORY_SIGNATURES, "commitment": "finalized"}],
        )
        if not isinstance(signatures, list):
            return []

        launches: dict[str, dict[str, str]] = {}
        transaction_failures = 0
        for item in signatures:
            if not isinstance(item, dict) or not item.get("signature"):
                continue
            try:
                transaction = await self._rpc(
                    "getTransaction",
                    [
                        item["signature"],
                        {
                            "encoding": "jsonParsed",
                            "maxSupportedTransactionVersion": 0,
                        },
                    ],
                )
            except Exception:
                transaction_failures += 1
                continue
            for launch in self._mint_initializations(transaction, wallet):
                launch.setdefault("signature", str(item["signature"]))
                if item.get("blockTime") is not None:
                    launch.setdefault("block_time", str(item["blockTime"]))
                launches[launch["address"]] = launch
        if transaction_failures and transaction_failures == len(signatures):
            raise RuntimeError("Solana RPC wallet-history transactions unavailable")
        return list(launches.values())

    @staticmethod
    def _mint_initializations(transaction: Any, wallet: str) -> list[dict[str, str]]:
        """Extract SPL initializeMint instructions with explicit wallet evidence."""
        try:
            message = transaction["transaction"]["message"]
        except (KeyError, TypeError):
            return []
        account_keys = message.get("accountKeys") if isinstance(message, dict) else []
        wallet_signed = any(
            isinstance(account, dict)
            and account.get("pubkey") == wallet
            and account.get("signer") is True
            for account in account_keys or []
        )
        instructions = list(
            (message.get("instructions") or []) if isinstance(message, dict) else []
        )
        meta = transaction.get("meta") if isinstance(transaction, dict) else None
        if isinstance(meta, dict):
            for group in meta.get("innerInstructions") or []:
                if isinstance(group, dict) and isinstance(group.get("instructions"), list):
                    instructions.extend(group["instructions"])
        found: list[dict[str, str]] = []
        for instruction in instructions or []:
            if not isinstance(instruction, dict):
                continue
            if instruction.get("programId") not in SOLANA_MINT_PROGRAM_IDS:
                continue
            parsed = instruction.get("parsed")
            if not isinstance(parsed, dict):
                continue
            if parsed.get("type") not in {"initializeMint", "initializeMint2"}:
                continue
            info = parsed.get("info")
            if not isinstance(info, dict):
                continue
            mint = info.get("mint")
            mint_authority = info.get("mintAuthority")
            if (
                not isinstance(mint, str)
                or not mint
                or not wallet_signed
                or mint_authority != wallet
            ):
                continue
            found.append({"address": mint})
        return found

    @staticmethod
    def _first_signer(transaction: Any) -> str | None:
        """Extract only an explicitly signer-marked account from parsed RPC data."""
        try:
            keys = transaction["transaction"]["message"]["accountKeys"]
        except (KeyError, TypeError):
            return None
        for account in keys:
            if isinstance(account, dict) and account.get("signer") is True:
                pubkey = account.get("pubkey")
                if isinstance(pubkey, str) and pubkey:
                    return pubkey
        return None


class SolscanDeveloperProvider(SolanaRpcDeveloperProvider):
    """Complete creator-to-mint history from Solscan's documented Pro API.

    Solscan's ``/v2.0/account/transactions/enhanced`` endpoint is a read-only,
    indexed account-history API. It returns raw Solana transaction objects and
    supports cursor pagination plus signer/program filters. A launch is counted
    only when that response contains both the wallet as an explicit signer and
    an SPL ``initializeMint``/``initializeMint2`` instruction.

    The provider is opt-in through ``SOLSCAN_API_KEY``. The key is never
    included in evidence or logs. When the key is absent, callers may choose
    the older bounded RPC observation; when the key is present but forbidden,
    callers must preserve UNKNOWN rather than silently substituting incomplete
    history.
    """

    HISTORY_ENDPOINT = "/v2.0/account/transactions/enhanced"
    DOCUMENTATION_URL = (
        "https://pro-api.solscan.io/pro-api-docs/v2.0/reference/"
        "v2-account-transactions-enhanced"
    )

    def __init__(
        self,
        api_key: str | None = None,
        max_history_pages: int = SOLSCAN_MAX_HISTORY_PAGES,
    ) -> None:
        self._api_key_override = api_key
        self.max_history_pages = max(1, max_history_pages)
        self._last_request_at = 0.0
        self._request_lock = asyncio.Lock()
        self.last_history_complete = "UNKNOWN"

    @property
    def configured(self) -> bool:
        return bool(self._api_key_override or os.getenv(SOLSCAN_API_KEY_ENV))

    def _api_key(self) -> str:
        key = self._api_key_override or os.getenv(SOLSCAN_API_KEY_ENV)
        if not key:
            raise SolscanError(f"{SOLSCAN_API_KEY_ENV} is not configured")
        return key

    async def _request(
        self, path: str, params: dict[str, Any] | None = None
    ) -> Any:
        query = f"?{urlencode(params, doseq=True)}" if params else ""
        request = Request(
            f"{SOLSCAN_API}{path}{query}",
            headers={
                "Accept": "application/json",
                "User-Agent": "MemeFinder1000X/1.0",
                # Solscan Pro documents the API key as a request header.
                "token": self._api_key(),
            },
            method="GET",
        )
        last_error: Exception | None = None
        for attempt in range(SOLSCAN_MAX_RETRIES):
            async with self._request_lock:
                wait = SOLSCAN_REQUEST_INTERVAL_SECONDS - (
                    time.monotonic() - self._last_request_at
                )
                if wait > 0:
                    await asyncio.sleep(wait)
                self._last_request_at = time.monotonic()
            try:
                response = await asyncio.to_thread(
                    urlopen, request, timeout=SOLSCAN_TIMEOUT_SECONDS
                )
                with response:
                    payload = json.loads(response.read().decode("utf-8"))
                if not isinstance(payload, dict) or payload.get("success") is False:
                    raise SolscanError("Solscan returned an unsuccessful response")
                return payload.get("data")
            except HTTPError as error:
                if error.code in (401, 403):
                    raise SolscanPermissionError(
                        f"Solscan permission denied for {path}"
                    ) from error
                last_error = error
                if error.code not in (408, 425, 429, 500, 502, 503, 504):
                    raise SolscanError(
                        f"Solscan returned HTTP {error.code}"
                    ) from error
                retry_after = error.headers.get("Retry-After")
                try:
                    delay = float(retry_after) if retry_after else 2**attempt
                except ValueError:
                    delay = 2**attempt
                if attempt < SOLSCAN_MAX_RETRIES - 1:
                    await asyncio.sleep(min(12, max(1, delay)))
            except SolscanPermissionError:
                raise
            except (
                URLError,
                TimeoutError,
                OSError,
                json.JSONDecodeError,
                SolscanError,
            ) as error:
                last_error = error
                if attempt < SOLSCAN_MAX_RETRIES - 1:
                    await asyncio.sleep(2**attempt)
        raise SolscanError(
            "Solscan did not respond after several attempts"
        ) from last_error

    async def find_wallet_launches(self, wallet: str) -> list[dict[str, str]]:
        """Page through indexed wallet transactions and extract explicit launches."""
        if not wallet:
            self.last_history_complete = "UNKNOWN"
            return []
        self._api_key()
        self.last_history_complete = "UNKNOWN"
        cursor: str | None = None
        seen_cursors: set[str] = set()
        launches: dict[str, dict[str, str]] = {}

        for _page in range(self.max_history_pages):
            params: dict[str, Any] = {
                "address": wallet,
                "signer[]": wallet,
                "program[]": list(SOLANA_MINT_PROGRAM_IDS),
                "limit": SOLSCAN_HISTORY_PAGE_SIZE,
                "encoding": "jsonParsed",
            }
            if cursor:
                params["cursor"] = cursor
            page = await self._request(self.HISTORY_ENDPOINT, params)
            transactions, next_cursor = self._transaction_page(page)
            for transaction in transactions:
                if not isinstance(transaction, dict):
                    continue
                for launch in self._mint_initializations(transaction, wallet):
                    address = launch.get("address")
                    if not address:
                        continue
                    enriched = {
                        **launch,
                        "source": (
                            "Solscan Pro API v2 account transactions enhanced"
                        ),
                        "source_url": self.DOCUMENTATION_URL,
                    }
                    signature = transaction.get("signature") or transaction.get(
                        "tx_hash"
                    )
                    block_time = transaction.get("blockTime")
                    if block_time is None:
                        block_time = transaction.get("block_time")
                    if signature:
                        enriched["signature"] = str(signature)
                    if block_time is not None:
                        enriched["block_time"] = str(block_time)
                    launches[address] = enriched

            if not next_cursor:
                self.last_history_complete = "TRUE"
                break
            if next_cursor in seen_cursors:
                self.last_history_complete = "FALSE"
                break
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        else:
            # Do not call a bounded page window complete history.
            self.last_history_complete = "FALSE"
        return list(launches.values())

    @staticmethod
    def _transaction_page(page: Any) -> tuple[list[Any], str | None]:
        """Read the enhanced endpoint's documented {transactions, cursor} page."""
        if not isinstance(page, dict):
            return [], None
        transactions = page.get("transactions")
        if not isinstance(transactions, list):
            transactions = page.get("data")
        if not isinstance(transactions, list):
            transactions = []
        cursor = page.get("cursor")
        if cursor is not None and not isinstance(cursor, str):
            raise SolscanError("Solscan returned a malformed pagination cursor")
        return transactions, cursor if cursor else None


class DeveloperIntelligence:
    """Routes each pair to the narrowest available chain provider."""

    def __init__(
        self,
        birdeye: BirdeyeProvider | None = None,
        solscan: SolscanDeveloperProvider | None = None,
    ) -> None:
        self._unknown = UnknownDeveloperProvider()
        self._solana = SolanaRpcDeveloperProvider()
        self._birdeye = birdeye
        self._solscan = solscan or SolscanDeveloperProvider()

    async def analyze_many(
        self, pairs: list[dict[str, Any]]
    ) -> dict[tuple[str, str], DeveloperFinding]:
        """Enrich a bounded top-candidate set without blocking the event loop."""
        selected = pairs[:MAX_CREATOR_LOOKUPS_PER_SCAN]

        async def analyze_pair(pair: dict[str, Any]) -> tuple[tuple[str, str], DeveloperFinding]:
            base = pair.get("baseToken") or {}
            key = (str(pair.get("chainId") or ""), str(base.get("address") or ""))
            provider: DeveloperProvider = (
                self._solana
                if key[0].lower() == "solana"
                else self._unknown
            )
            if key[0].lower() == "solana" and self._birdeye is not None:
                return key, await self._analyze_with_birdeye(pair, provider)
            return key, await provider.analyze(pair)

        results = await asyncio.gather(*(analyze_pair(pair) for pair in selected))
        return dict(results)

    async def _analyze_with_birdeye(
        self, pair: dict[str, Any], fallback: DeveloperProvider
    ) -> DeveloperFinding:
        """Prefer explicit creation data, then enrich a cautious RPC fallback."""
        mint = str((pair.get("baseToken") or {}).get("address") or "")
        try:
            snapshot = await self._birdeye.analyze_token(mint)
            creator = self._creator_from_creation(snapshot)
            sources = ", ".join(snapshot.available_endpoints) or "none"
            if creator:
                finding = DeveloperFinding(
                    developer=creator,
                    developer_label="Developer",
                    identity_confidence="EXPLICIT CREATOR/DEPLOYER",
                    evidence=(
                        "Birdeye token creation data returned an explicit creator/"
                        f"deployer address. Source endpoints: {sources}. "
                        "This is evidence of the reported address, not identity "
                        "or ownership."
                    ),
                )
            else:
                finding = await fallback.analyze(pair)
                if finding.developer != "UNKNOWN":
                    finding.evidence = (
                        "Birdeye did not return an explicit creator/deployer field. "
                        + finding.evidence
                        + f" Birdeye endpoints available: {sources}."
                    )
                else:
                    finding.evidence = (
                        "Unknown — Birdeye returned no explicit creator/deployer "
                        f"address and RPC fallback was inconclusive. Endpoints "
                        f"available: {sources}."
                    )
            if finding.developer == "UNKNOWN":
                return finding
            return await self._enrich_history(pair, finding)
        except Exception as error:
            logger.info("Birdeye developer enrichment unavailable: %s", error)
            finding = await fallback.analyze(pair)
            if finding.developer == "UNKNOWN":
                return finding
            return await self._enrich_history(pair, finding)

    async def _enrich_history(
        self, pair: dict[str, Any], finding: DeveloperFinding
    ) -> DeveloperFinding:
        """Attach only measurable wallet history to an identified address."""
        wallet = finding.developer
        current_mint = str((pair.get("baseToken") or {}).get("address") or "")
        detail_rows: list[dict[str, Any]] = []
        detail_status = "Birdeye wallet P&L details unavailable"
        if self._birdeye is not None:
            try:
                details = await self._birdeye.wallet_pnl_details(wallet)
                detail_rows = self._detail_rows(details)
                detail_status = (
                    f"Birdeye returned {len(detail_rows)} wallet-token P&L observation(s)"
                )
            except Exception as error:
                logger.info("Birdeye developer history unavailable: %s", error)

        launches: list[dict[str, str]] = []
        launch_source = "no explicit launch evidence"
        indexed_history_complete: bool | None = None
        explicit_launches = self._launches_from_detail_rows(detail_rows, wallet)
        if getattr(self._solscan, "configured", False):
            try:
                launches = await asyncio.wait_for(
                    self._solscan.find_wallet_launches(wallet),
                    timeout=SOLSCAN_HISTORY_TIMEOUT_SECONDS,
                )
                indexed_history_complete = (
                    str(getattr(self._solscan, "last_history_complete", "UNKNOWN"))
                    == "TRUE"
                )
                launch_source = (
                    "Solscan Pro API v2 account/transactions/enhanced; "
                    "explicit signer + SPL mint-initialization evidence"
                )
                if not indexed_history_complete:
                    launch_source += " (indexed page window incomplete)"
            except SolscanPermissionError:
                launch_source = (
                    "Solscan Pro API permission denied; indexed launch history "
                    "is UNKNOWN"
                )
            except TimeoutError:
                launch_source = (
                    "Solscan indexed launch-history lookup timed out; indexed "
                    "launch history is UNKNOWN"
                )
            except SolscanError:
                launch_source = "Solscan indexed launch-history source unavailable"
        elif explicit_launches:
            launches = explicit_launches
            indexed_history_complete = False
            launch_source = (
                "Birdeye explicit creator/deployer fields; limited 90-day/100-row "
                "wallet observation window is not complete launch history"
            )
        elif isinstance(self._solana, SolanaRpcDeveloperProvider):
            try:
                launches = await self._solana.find_wallet_launches(wallet)
                indexed_history_complete = False
                if launches:
                    launch_source = (
                        "bounded Solana RPC mint-initialization evidence; "
                        "observed count may be incomplete"
                    )
                else:
                    launch_source = (
                        "Solana RPC found no explicit mint initialization in the "
                        f"latest {MAX_WALLET_HISTORY_SIGNATURES} inspected signatures"
                    )
            except Exception:
                launch_source = "Solana RPC launch probe unavailable"

        previous = [
            launch for launch in launches
            if str(launch.get("address") or "") != current_mint
        ]
        row_by_address = {
            str(row.get("address") or row.get("tokenAddress") or ""): row
            for row in detail_rows
            if str(row.get("address") or row.get("tokenAddress") or "")
        }
        scored_rows = [
            (launch, row_by_address.get(str(launch.get("address") or "")))
            for launch in previous
        ]
        returns: list[float] = []
        success_count = 0
        failed_count = 0
        suspicious_count = 0
        lifecycle_observations = 0
        rug_observations = 0
        best: tuple[float, dict[str, Any]] | None = None
        peak_market_caps: list[float] = []
        peak_liquidities: list[float] = []
        total_sells = 0
        total_sold_usd = 0.0
        liquidity_additions = 0.0
        liquidity_removals = 0.0
        activity_delays: list[float] = []
        launch_times: list[float] = []
        for launch, row in scored_rows:
            launch_time = self._first_number(launch, "block_time", "launch_time")
            if launch_time is not None:
                launch_times.append(launch_time)
            if not row:
                continue
            return_percent = self._row_return_percent(row)
            if return_percent is not None:
                returns.append(return_percent)
                if return_percent >= 50:
                    success_count += 1
                if best is None or return_percent > best[0]:
                    best = (return_percent, {**launch, **row})
            lifecycle_status = self._row_lifecycle_status(row)
            if lifecycle_status is not None:
                lifecycle_observations += 1
                if lifecycle_status:
                    failed_count += 1
            rug_status = self._row_rug_status(row)
            if rug_status is not None:
                rug_observations += 1
                if rug_status:
                    suspicious_count += 1
            market_cap = self._first_number(
                row,
                "peak_market_cap",
                "peakMarketCap",
                "ath_market_cap",
                "athMarketCap",
                "highest_market_cap",
            )
            if market_cap is not None:
                peak_market_caps.append(market_cap)
            liquidity = self._first_number(
                row,
                "peak_liquidity_usd",
                "peakLiquidityUsd",
                "liquidity_usd",
                "liquidityUsd",
            )
            if liquidity is not None:
                peak_liquidities.append(liquidity)
            total_sells += int(
                self._first_number(row, "total_sell", "totalSell") or 0
            )
            total_sold_usd += self._first_number(
                row, "total_sold", "totalSold", "sold_usd", "soldUsd"
            ) or 0
            liquidity_additions += self._first_number(
                row, "liquidity_added", "liquidityAdded"
            ) or 0
            liquidity_removals += self._first_number(
                row, "liquidity_removed", "liquidityRemoval"
            ) or 0
            major_activity = self._first_number(
                row, "major_activity_unix_time", "majorActivityUnixTime"
            )
            if launch_time is not None and major_activity is not None:
                activity_delays.append(max(0, major_activity - launch_time))

        finding.history_coverage = (
            f"{detail_status}; {launch_source}. "
            f"{len(returns)}/{len(previous)} observed prior launch(es) have "
            f"measurable P&L, {lifecycle_observations}/{len(previous)} have "
            f"lifecycle evidence, and {rug_observations}/{len(previous)} have "
            "rug-pattern evidence."
        )
        if detail_rows:
            finding.evidence_sources.append(
                "Birdeye POST /wallet/v2/pnl/details (90d cumulative)"
            )
        if launches:
            finding.evidence_sources.append(launch_source)
        if indexed_history_complete is False:
            finding.evidence = (
                f"{finding.evidence} History coverage: {finding.history_coverage} "
                "Aggregate launch totals and performance metrics are withheld because "
                "the indexed creator-history page window was incomplete."
            )
            return finding
        if not previous:
            finding.evidence = (
                f"{finding.evidence} {finding.history_coverage}"
            )
            return finding

        finding.previous_launches = str(len(previous))
        if len(returns) == len(previous):
            finding.successful_launches = str(success_count)
        if lifecycle_observations == len(previous):
            finding.failed_launches = str(failed_count)
        if rug_observations == len(previous):
            finding.suspected_rug_launches = str(suspicious_count)
        if peak_market_caps:
            finding.highest_historical_market_cap = (
                f"${max(peak_market_caps):,.0f}"
            )
        if peak_liquidities:
            finding.historical_liquidity = f"${max(peak_liquidities):,.0f} peak"
        if liquidity_additions or liquidity_removals:
            finding.liquidity_activity = (
                f"${liquidity_additions:,.0f} added / "
                f"${liquidity_removals:,.0f} removed in sourced records"
            )
        if total_sells or total_sold_usd:
            finding.selling_behavior = (
                f"{total_sells} sell(s), ${total_sold_usd:,.0f} sold across "
                "confirmed prior launches"
            )
        if activity_delays:
            finding.major_activity_timing = (
                f"Median {sorted(activity_delays)[len(activity_delays) // 2] / 3600:.1f}h "
                "from launch to sourced major activity"
            )
        if launch_times:
            latest = datetime.fromtimestamp(
                max(launch_times), tz=timezone.utc
            ).strftime("%Y-%m-%d")
            finding.recent_launch_activity = (
                f"Most recent observed prior launch: {latest} UTC"
            )
        if best:
            symbol = str(best[1].get("symbol") or best[1].get("address") or "UNKNOWN")
            finding.best_previous_launch = (
                f"{symbol} ({best[0]:+.1f}% tracked P&L)"
            )
        else:
            finding.best_previous_launch = "UNKNOWN — no measurable prior-launch P&L"

        if len(previous) >= MIN_HISTORICAL_LAUNCHES and len(returns) >= MIN_HISTORICAL_DECISIONS:
            positive = sum(value > 0 for value in returns)
            win_rate = positive / len(returns) * 100
            average_return = sum(returns) / len(returns)
            return_component = max(0, min(100, 50 + average_return / 2))
            depth_component = min(100, len(returns) / len(previous) * 100)
            finding.developer_score = str(
                round(win_rate * 0.55 + return_component * 0.35 + depth_component * 0.10)
            )
            if rug_observations == len(previous) and suspicious_count > 0:
                finding.risk = "HIGH"
            elif (
                lifecycle_observations == len(previous)
                and failed_count > success_count
            ):
                finding.risk = "MEDIUM"
            elif (
                lifecycle_observations == len(previous)
                and rug_observations == len(previous)
                and int(finding.developer_score) >= HIGH_DEVELOPER_SCORE
            ):
                finding.risk = "LOW"
            elif (
                lifecycle_observations == len(previous)
                and rug_observations == len(previous)
            ):
                finding.risk = "MEDIUM"
            else:
                finding.risk = "UNKNOWN"
            finding.reputation = finding.developer_score
        else:
            finding.developer_score = (
                f"UNKNOWN — requires {MIN_HISTORICAL_LAUNCHES} prior launches and "
                f"{MIN_HISTORICAL_DECISIONS} measurable outcomes"
            )
            finding.risk = "UNKNOWN"

        finding.evidence = (
            f"{finding.evidence} History coverage: {finding.history_coverage} "
            "Successful means tracked P&L ≥+50%; failed/inactive requires an "
            "explicit inactive/closed status. A price decline alone is not a "
            "rug-pattern classification."
        )
        return finding

    @staticmethod
    def _detail_rows(details: Any) -> list[dict[str, Any]]:
        if not isinstance(details, dict):
            return []
        data = details.get("data") if isinstance(details.get("data"), dict) else details
        rows = data.get("tokens") if isinstance(data, dict) else None
        if not isinstance(rows, list) and isinstance(data, dict):
            rows = data.get("items")
        if isinstance(rows, dict):
            rows = [
                {"address": address, **value}
                for address, value in rows.items()
                if isinstance(value, dict)
            ]
        return [row for row in rows or [] if isinstance(row, dict)]

    @staticmethod
    def _launches_from_detail_rows(
        rows: list[dict[str, Any]], wallet: str
    ) -> list[dict[str, str]]:
        launches: dict[str, dict[str, str]] = {}
        for row in rows:
            address = row.get("address") or row.get("tokenAddress")
            if not isinstance(address, str) or not address:
                continue
            creator = (
                row.get("creator")
                or row.get("creatorAddress")
                or row.get("deployer")
                or row.get("deployerAddress")
            )
            is_creator = row.get("isCreator") is True or row.get("isDeployer") is True
            if creator == wallet or is_creator:
                launches[address] = {"address": address}
        return list(launches.values())

    @staticmethod
    def _row_return_percent(row: dict[str, Any]) -> float | None:
        pnl = row.get("pnl") if isinstance(row.get("pnl"), dict) else row
        for key in (
            "total_percent",
            "totalPercent",
            "realized_profit_percent",
            "realizedProfitPercent",
        ):
            value = pnl.get(key) if isinstance(pnl, dict) else None
            try:
                number = float(value)
            except (TypeError, ValueError):
                continue
            if abs(number) <= 1:
                number *= 100
            return number
        return None

    @staticmethod
    def _row_lifecycle_status(row: dict[str, Any]) -> bool | None:
        status = str(
            row.get("status")
            or row.get("activity")
            or row.get("lifecycle")
            or ""
        ).lower()
        if status in {"inactive", "failed", "dead", "closed"}:
            return True
        if status in {"active", "trading", "live", "open", "successful"}:
            return False
        return None

    @staticmethod
    def _row_rug_status(row: dict[str, Any]) -> bool | None:
        """Require explicit source evidence; never infer from a negative return."""
        boolean_keys = (
            "significant_liquidity_removal",
            "significantLiquidityRemoval",
            "unusual_developer_selling",
            "unusualDeveloperSelling",
            "coordinated_dumping",
            "coordinatedDumping",
            "suspected_rug_pattern",
            "suspectedRugPattern",
        )
        observed = False
        for key in boolean_keys:
            if key not in row:
                continue
            observed = True
            value = row.get(key)
            if value is True:
                return True
        removed_percent = DeveloperIntelligence._first_number(
            row, "liquidity_removed_percent", "liquidityRemovedPercent"
        )
        if removed_percent is not None:
            return removed_percent >= 50
        if row.get("rug_evidence_available") is True:
            observed = True
        return False if observed else None

    @staticmethod
    def _first_number(row: dict[str, Any], *keys: str) -> float | None:
        """Read known numeric fields from documented nested response sections."""
        sections = [
            row,
            row.get("market") if isinstance(row.get("market"), dict) else {},
            row.get("marketData") if isinstance(row.get("marketData"), dict) else {},
            row.get("liquidity") if isinstance(row.get("liquidity"), dict) else {},
            row.get("counts") if isinstance(row.get("counts"), dict) else {},
            row.get("cashflow_usd")
            if isinstance(row.get("cashflow_usd"), dict)
            else {},
            row.get("cashflowUsd")
            if isinstance(row.get("cashflowUsd"), dict)
            else {},
        ]
        for section in sections:
            for key in keys:
                value = section.get(key)
                try:
                    return float(value)
                except (TypeError, ValueError):
                    continue
        return None

    @staticmethod
    def _creator_from_creation(snapshot: BirdeyeSnapshot) -> str | None:
        """Read only explicit creator/deployer keys from creation response data."""
        creation = snapshot.data.get("token_creation_info")
        return DeveloperIntelligence._find_address(
            creation,
            {"creator", "creatorAddress", "creator_address", "deployer", "deployerAddress"},
        )

    @staticmethod
    def _find_address(value: Any, keys: set[str]) -> str | None:
        if isinstance(value, dict):
            for key, item in value.items():
                if key in keys:
                    if isinstance(item, dict):
                        item = item.get("address") or item.get("pubkey")
                    if isinstance(item, str) and 32 <= len(item) <= 64:
                        return item
                found = DeveloperIntelligence._find_address(item, keys)
                if found:
                    return found
        elif isinstance(value, list):
            for item in value:
                found = DeveloperIntelligence._find_address(item, keys)
                if found:
                    return found
        return None