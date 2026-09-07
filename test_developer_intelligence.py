"""Deterministic tests for read-only Developer Intelligence."""

from __future__ import annotations

import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from birdeye_provider import BirdeyeError, BirdeyeProvider
from developer_intelligence import (
    DeveloperFinding,
    DeveloperIntelligence,
    SOLANA_TOKEN_2022_PROGRAM_ID,
    SOLANA_TOKEN_PROGRAM_ID,
    SolanaRpcDeveloperProvider,
    SolscanDeveloperProvider,
    SolscanPermissionError,
)


WALLET = "DeveloperWallet111111111111111111111111111"
CURRENT_MINT = "CurrentMint11111111111111111111111111111"


class FakeBirdeye:
    def __init__(self, rows=None, error: Exception | None = None):
        self.rows = rows or []
        self.error = error

    async def wallet_pnl_details(self, wallet: str):
        if self.error:
            raise self.error
        return {"tokens": self.rows}


class FakeSolana(SolanaRpcDeveloperProvider):
    def __init__(self, launches=None):
        self.launches = launches or []

    async def find_wallet_launches(self, wallet: str):
        return self.launches


class FakeSolscan(SolscanDeveloperProvider):
    def __init__(
        self,
        launches=None,
        error: Exception | None = None,
        complete: str = "TRUE",
    ):
        super().__init__(api_key="test-only-key")
        self.launches = launches or []
        self.error = error
        self.complete = complete
        self.calls = 0

    async def find_wallet_launches(self, wallet: str):
        self.calls += 1
        if self.error:
            raise self.error
        self.last_history_complete = self.complete
        return self.launches


class SlowSolscan(FakeSolscan):
    async def find_wallet_launches(self, wallet: str):
        await asyncio.sleep(1)
        return self.launches


def history_rows(count: int) -> list[dict]:
    rows = []
    for index in range(count):
        rows.append(
            {
                "address": f"Mint{index}",
                "symbol": f"T{index}",
                "creator": WALLET,
                "pnl": {"total_percent": [180, 90, 60, -20, -50][index % 5]},
            }
        )
    return rows


class DeveloperHistoryTests(unittest.IsolatedAsyncioTestCase):
    async def test_sufficient_history_scores_only_explicit_launches(self):
        rows = history_rows(5)
        for row in rows:
            row["status"] = "active"
            row["suspected_rug_pattern"] = False
        rows[3]["status"] = "inactive"
        rows[4]["unusual_developer_selling"] = True
        rows[0]["peak_market_cap"] = 2_500_000
        rows[0]["peak_liquidity_usd"] = 300_000
        rows[0]["counts"] = {"total_sell": 4}
        rows[0]["cashflow_usd"] = {"total_sold": 125_000}
        intelligence = DeveloperIntelligence(
            FakeBirdeye(rows),
            FakeSolscan([{"address": row["address"]} for row in rows]),
        )
        finding = DeveloperFinding(
            developer=WALLET,
            developer_label="Developer",
            identity_confidence="EXPLICIT CREATOR/DEPLOYER",
            evidence="Explicit test evidence.",
        )

        result = await intelligence._enrich_history(
            {"baseToken": {"address": CURRENT_MINT}}, finding
        )

        self.assertEqual(result.previous_launches, "5")
        self.assertEqual(result.successful_launches, "3")
        self.assertEqual(result.failed_launches, "1")
        self.assertEqual(result.suspected_rug_launches, "1")
        self.assertNotIn("UNKNOWN", result.developer_score)
        self.assertEqual(result.risk, "HIGH")
        self.assertIn("tracked P&L", result.best_previous_launch)
        self.assertEqual(result.highest_historical_market_cap, "$2,500,000")
        self.assertEqual(result.historical_liquidity, "$300,000 peak")
        self.assertIn("4 sell(s)", result.selling_behavior)
        self.assertTrue(result.evidence_sources)

    async def test_two_observations_never_receive_score(self):
        rows = history_rows(2)
        intelligence = DeveloperIntelligence(
            FakeBirdeye(rows),
            FakeSolscan([{"address": row["address"]} for row in rows]),
        )
        finding = DeveloperFinding(developer=WALLET, evidence="Probable evidence.")

        result = await intelligence._enrich_history(
            {"baseToken": {"address": CURRENT_MINT}}, finding
        )

        self.assertEqual(result.previous_launches, "2")
        self.assertIn("UNKNOWN", result.developer_score)
        self.assertEqual(result.risk, "UNKNOWN")

    async def test_rpc_only_launches_do_not_claim_zero_outcomes(self):
        intelligence = DeveloperIntelligence(FakeBirdeye([]))
        intelligence._solana = FakeSolana(
            [{"address": "PriorMint1"}, {"address": "PriorMint2"}]
        )
        finding = DeveloperFinding(developer=WALLET, evidence="Probable evidence.")

        result = await intelligence._enrich_history(
            {"baseToken": {"address": CURRENT_MINT}}, finding
        )

        self.assertEqual(result.previous_launches, "UNKNOWN")
        self.assertEqual(result.successful_launches, "UNKNOWN")
        self.assertEqual(result.failed_launches, "UNKNOWN")
        self.assertEqual(result.suspected_rug_launches, "UNKNOWN")

    async def test_missing_lifecycle_and_rug_fields_stay_unknown(self):
        rows = history_rows(5)
        intelligence = DeveloperIntelligence(
            FakeBirdeye(rows),
            FakeSolscan([{"address": row["address"]} for row in rows]),
        )
        finding = DeveloperFinding(developer=WALLET, evidence="Explicit evidence.")

        result = await intelligence._enrich_history(
            {"baseToken": {"address": CURRENT_MINT}}, finding
        )

        self.assertEqual(result.successful_launches, "3")
        self.assertEqual(result.failed_launches, "UNKNOWN")
        self.assertEqual(result.suspected_rug_launches, "UNKNOWN")
        self.assertNotEqual(result.developer_score, "UNKNOWN")
        self.assertEqual(result.risk, "UNKNOWN")

    async def test_restricted_history_and_empty_rpc_preserve_unknown(self):
        intelligence = DeveloperIntelligence(
            FakeBirdeye(error=BirdeyeError("Birdeye returned HTTP 401"))
        )
        intelligence._solana = FakeSolana([])
        finding = DeveloperFinding(developer=WALLET, evidence="Probable evidence.")

        result = await intelligence._enrich_history(
            {"baseToken": {"address": CURRENT_MINT}}, finding
        )

        self.assertEqual(result.previous_launches, "UNKNOWN")
        self.assertEqual(result.developer_score, "UNKNOWN")
        self.assertIn("unavailable", result.history_coverage)
        self.assertIn("no explicit mint initialization", result.history_coverage)

    async def test_indexed_launches_join_wallet_metrics_and_populate_history(self):
        rows = history_rows(5)
        for index, row in enumerate(rows):
            row.pop("creator")
            row["status"] = "active" if index < 4 else "inactive"
            row["suspected_rug_pattern"] = False
            row["peak_market_cap"] = 1_000_000 + index
            row["peak_liquidity_usd"] = 100_000 + index
            row["counts"] = {"total_sell": index + 1}
            row["cashflow_usd"] = {"total_sold": (index + 1) * 1_000}
        launches = [
            {
                "address": f"Mint{index}",
                "block_time": str(1_700_000_000 + index * 86_400),
            }
            for index in range(5)
        ]
        intelligence = DeveloperIntelligence(
            FakeBirdeye(rows), FakeSolscan(launches)
        )
        intelligence._solana = AsyncMock()
        finding = DeveloperFinding(
            developer=WALLET,
            developer_label="Developer",
            identity_confidence="EXPLICIT CREATOR/DEPLOYER",
            evidence="Explicit current-token creator evidence.",
        )

        result = await intelligence._enrich_history(
            {"baseToken": {"address": CURRENT_MINT}}, finding
        )

        self.assertEqual(result.previous_launches, "5")
        self.assertEqual(result.successful_launches, "3")
        self.assertEqual(result.failed_launches, "1")
        self.assertEqual(result.highest_historical_market_cap, "$1,000,004")
        self.assertEqual(result.historical_liquidity, "$100,004 peak")
        self.assertIn("15 sell(s)", result.selling_behavior)
        self.assertIn("Most recent observed prior launch", result.recent_launch_activity)
        self.assertNotIn("UNKNOWN", result.developer_score)
        self.assertIn("Solscan Pro API v2", result.history_coverage)
        intelligence._solana.find_wallet_launches.assert_not_awaited()

    async def test_solscan_permission_failure_stays_unknown_without_rpc_substitute(self):
        intelligence = DeveloperIntelligence(
            FakeBirdeye([]),
            FakeSolscan(
                error=SolscanPermissionError("endpoint requires another plan")
            ),
        )
        intelligence._solana = AsyncMock()
        finding = DeveloperFinding(developer=WALLET, evidence="Explicit evidence.")

        result = await intelligence._enrich_history(
            {"baseToken": {"address": CURRENT_MINT}}, finding
        )

        self.assertEqual(result.previous_launches, "UNKNOWN")
        self.assertEqual(result.developer_score, "UNKNOWN")
        self.assertIn("permission denied", result.history_coverage)
        intelligence._solana.find_wallet_launches.assert_not_awaited()

    async def test_incomplete_indexed_history_withholds_score(self):
        rows = history_rows(5)
        launches = [{"address": f"Mint{index}"} for index in range(5)]
        intelligence = DeveloperIntelligence(
            FakeBirdeye(rows), FakeSolscan(launches, complete="FALSE")
        )
        finding = DeveloperFinding(developer=WALLET, evidence="Explicit evidence.")

        result = await intelligence._enrich_history(
            {"baseToken": {"address": CURRENT_MINT}}, finding
        )

        self.assertEqual(result.previous_launches, "UNKNOWN")
        self.assertEqual(result.successful_launches, "UNKNOWN")
        self.assertEqual(result.highest_historical_market_cap, "UNKNOWN")
        self.assertIn("UNKNOWN", result.developer_score)
        self.assertIn("Aggregate launch totals", result.evidence)
        self.assertEqual(intelligence._solscan.calls, 1)

    async def test_indexed_history_timeout_stays_unknown_and_scan_can_continue(self):
        intelligence = DeveloperIntelligence(FakeBirdeye([]), SlowSolscan([]))
        finding = DeveloperFinding(developer=WALLET, evidence="Explicit evidence.")

        with patch(
            "developer_intelligence.SOLSCAN_HISTORY_TIMEOUT_SECONDS", 0.001
        ):
            result = await intelligence._enrich_history(
                {"baseToken": {"address": CURRENT_MINT}}, finding
            )

        self.assertEqual(result.previous_launches, "UNKNOWN")
        self.assertEqual(result.developer_score, "UNKNOWN")
        self.assertIn("timed out", result.history_coverage)

    def test_rpc_requires_mint_initialization_and_wallet_evidence(self):
        transaction = {
            "transaction": {
                "message": {
                    "accountKeys": [{"pubkey": WALLET, "signer": True}],
                    "instructions": [
                        {
                            "program": "spl-token",
                            "programId": SOLANA_TOKEN_PROGRAM_ID,
                            "parsed": {
                                "type": "initializeMint2",
                                "info": {
                                    "mint": "PriorMint",
                                    "mintAuthority": WALLET,
                                },
                            },
                        },
                        {
                            "program": "spl-token",
                            "programId": SOLANA_TOKEN_PROGRAM_ID,
                            "parsed": {
                                "type": "transfer",
                                "info": {"mint": "NotALaunch"},
                            },
                        },
                    ],
                }
            }
        }

        launches = SolanaRpcDeveloperProvider._mint_initializations(transaction, WALLET)

        self.assertEqual(launches, [{"address": "PriorMint"}])

    def test_rpc_rejects_authority_only_without_wallet_signature(self):
        transaction = {
            "transaction": {
                "message": {
                    "accountKeys": [
                        {"pubkey": "DifferentSigner", "signer": True},
                        {"pubkey": WALLET, "signer": False},
                    ],
                    "instructions": [
                        {
                            "program": "spl-token",
                            "programId": SOLANA_TOKEN_2022_PROGRAM_ID,
                            "parsed": {
                                "type": "initializeMint",
                                "info": {
                                    "mint": "AuthorityOnlyMint",
                                    "mintAuthority": WALLET,
                                },
                            },
                        }
                    ],
                }
            }
        }

        launches = SolanaRpcDeveloperProvider._mint_initializations(transaction, WALLET)

        self.assertEqual(launches, [])

    def test_rpc_rejects_bare_account_key_as_signer_evidence(self):
        transaction = {
            "transaction": {
                "message": {
                    "accountKeys": [WALLET],
                    "instructions": [
                        {
                            "program": "spl-token",
                            "programId": SOLANA_TOKEN_PROGRAM_ID,
                            "parsed": {
                                "type": "initializeMint",
                                "info": {
                                    "mint": "BareKeyMint",
                                    "mintAuthority": WALLET,
                                },
                            },
                        }
                    ],
                }
            }
        }

        launches = SolanaRpcDeveloperProvider._mint_initializations(transaction, WALLET)

        self.assertEqual(launches, [])


class BirdeyeProviderTests(unittest.IsolatedAsyncioTestCase):
    async def test_wallet_details_uses_live_verified_read_only_post_and_cache(self):
        provider = BirdeyeProvider()
        provider._post = AsyncMock(return_value={"tokens": []})

        first = await provider.wallet_pnl_details(WALLET)
        second = await provider.wallet_pnl_details(WALLET)

        self.assertEqual(first, {"tokens": []})
        self.assertIs(first, second)
        provider._post.assert_awaited_once()
        path, body = provider._post.await_args.args
        self.assertEqual(path, "/wallet/v2/pnl/details")
        self.assertEqual(body["wallet"], WALLET)
        self.assertEqual(body["duration"], "90d")
        self.assertEqual(body["position_scope"], "cumulative")


class SolscanProviderTests(unittest.IsolatedAsyncioTestCase):
    async def test_pages_complete_indexed_history_and_keeps_explicit_evidence(self):
        provider = SolscanDeveloperProvider(api_key="test-only-key")
        valid_transaction = {
            "signature": "sig-1",
            "blockTime": 1_700_000_000,
            "transaction": {
                "message": {
                    "accountKeys": [{"pubkey": WALLET, "signer": True}],
                    "instructions": [
                        {
                            "program": "spl-token",
                            "programId": SOLANA_TOKEN_PROGRAM_ID,
                            "parsed": {
                                "type": "initializeMint2",
                                "info": {
                                    "mint": "IndexedMint1",
                                    "mintAuthority": WALLET,
                                },
                            },
                        }
                    ],
                }
            },
        }
        unsigned_transaction = {
            "signature": "sig-ignored",
            "transaction": {
                "message": {
                    "accountKeys": [{"pubkey": WALLET, "signer": False}],
                    "instructions": [
                        {
                            "program": "spl-token",
                            "programId": SOLANA_TOKEN_PROGRAM_ID,
                            "parsed": {
                                "type": "initializeMint",
                                "info": {
                                    "mint": "UnsignedMint",
                                    "mintAuthority": WALLET,
                                },
                            },
                        }
                    ],
                }
            },
        }
        second_transaction = {
            "tx_hash": "sig-2",
            "block_time": 1_700_086_400,
            "transaction": {
                "message": {
                    "accountKeys": [{"pubkey": WALLET, "signer": True}],
                    "instructions": [
                        {
                            "program": "spl-token",
                            "programId": SOLANA_TOKEN_PROGRAM_ID,
                            "parsed": {
                                "type": "initializeMint",
                                "info": {
                                    "mint": "IndexedMint2",
                                    "mintAuthority": WALLET,
                                },
                            },
                        }
                    ],
                }
            },
        }
        provider._request = AsyncMock(
            side_effect=[
                {
                    "transactions": [valid_transaction, unsigned_transaction],
                    "cursor": "next-page",
                },
                {"transactions": [second_transaction], "cursor": None},
            ]
        )

        launches = await provider.find_wallet_launches(WALLET)

        self.assertEqual(
            {launch["address"] for launch in launches},
            {"IndexedMint1", "IndexedMint2"},
        )
        self.assertEqual(provider.last_history_complete, "TRUE")
        self.assertTrue(all("source_url" in launch for launch in launches))
        self.assertEqual(provider._request.await_count, 2)
        second_params = provider._request.await_args_list[1].args[1]
        self.assertEqual(second_params["cursor"], "next-page")
        self.assertEqual(second_params["encoding"], "jsonParsed")
        self.assertEqual(
            second_params["program[]"],
            [SOLANA_TOKEN_PROGRAM_ID, SOLANA_TOKEN_2022_PROGRAM_ID],
        )

    def test_token_2022_only_mint_is_attributed_with_explicit_authority(self):
        transaction = {
            "transaction": {
                "message": {
                    "accountKeys": [{"pubkey": WALLET, "signer": True}],
                    "instructions": [
                        {
                            "program": "spl-token",
                            "programId": SOLANA_TOKEN_2022_PROGRAM_ID,
                            "parsed": {
                                "type": "initializeMint2",
                                "info": {
                                    "mint": "Token2022Mint",
                                    "mintAuthority": WALLET,
                                },
                            },
                        }
                    ],
                }
            }
        }

        launches = SolscanDeveloperProvider._mint_initializations(
            transaction, WALLET
        )

        self.assertEqual(launches, [{"address": "Token2022Mint"}])

    async def test_repeated_cursor_marks_observed_history_incomplete(self):
        provider = SolscanDeveloperProvider(
            api_key="test-only-key", max_history_pages=5
        )
        provider._request = AsyncMock(
            side_effect=[
                {"transactions": [], "cursor": "repeated"},
                {"transactions": [], "cursor": "repeated"},
            ]
        )

        launches = await provider.find_wallet_launches(WALLET)

        self.assertEqual(launches, [])
        self.assertEqual(provider.last_history_complete, "FALSE")
        self.assertEqual(provider._request.await_count, 2)

    def test_signer_with_different_mint_authority_is_not_attributed(self):
        transaction = {
            "transaction": {
                "message": {
                    "accountKeys": [{"pubkey": WALLET, "signer": True}],
                    "instructions": [
                        {
                            "program": "spl-token",
                            "programId": SOLANA_TOKEN_PROGRAM_ID,
                            "parsed": {
                                "type": "initializeMint2",
                                "info": {
                                    "mint": "OtherAuthorityMint",
                                    "mintAuthority": "DifferentAuthority",
                                },
                            },
                        }
                    ],
                }
            }
        }

        launches = SolscanDeveloperProvider._mint_initializations(
            transaction, WALLET
        )

        self.assertEqual(launches, [])

    def test_non_token_program_initialize_mint_is_not_attributed(self):
        transaction = {
            "transaction": {
                "message": {
                    "accountKeys": [{"pubkey": WALLET, "signer": True}],
                    "instructions": [
                        {
                            "program": "not-spl-token",
                            "programId": "NotTheTokenProgram",
                            "parsed": {
                                "type": "initializeMint2",
                                "info": {
                                    "mint": "FakeMint",
                                    "mintAuthority": WALLET,
                                },
                            },
                        }
                    ],
                }
            }
        }

        launches = SolscanDeveloperProvider._mint_initializations(
            transaction, WALLET
        )

        self.assertEqual(launches, [])


if __name__ == "__main__":
    unittest.main()