"""Telegram-size and concise fallback tests for scan rendering."""

from __future__ import annotations

import unittest

from bot import (
    MAX_TELEGRAM_MESSAGE_LENGTH,
    _apply_developer_risk_evidence,
    _render_scan_messages,
)


def pair(index: int, history_available: bool = False) -> dict:
    developer = {
        "developer": f"DeveloperWallet{index:02d}abcdefghijklmnop",
        "developer_label": "Probable Developer",
        "previous_launches": "5" if history_available else "UNKNOWN",
        "successful_launches": "3" if history_available else "UNKNOWN",
        "failed_launches": "1" if history_available else "UNKNOWN",
        "suspected_rug_launches": "0" if history_available else "UNKNOWN",
        "best_previous_launch": "TOKEN (+200.0% tracked P&L)"
        if history_available
        else "UNKNOWN",
        "developer_score": "72" if history_available else "UNKNOWN",
        "risk": "MEDIUM" if history_available else "UNKNOWN",
        "highest_historical_market_cap": "$2,500,000"
        if history_available
        else "UNKNOWN",
        "historical_liquidity": "$300,000 peak"
        if history_available
        else "UNKNOWN",
        "liquidity_activity": "$100,000 added / $20,000 removed"
        if history_available
        else "UNKNOWN",
        "selling_behavior": "4 sell(s), $125,000 sold"
        if history_available
        else "UNKNOWN",
        "major_activity_timing": "Median 2.0h from launch"
        if history_available
        else "UNKNOWN",
        "recent_launch_activity": "Most recent observed prior launch: 2026-08-01 UTC"
        if history_available
        else "UNKNOWN",
        "history_coverage": "Birdeye and bounded Solana evidence summary.",
        "evidence": "Source-attributed probable signer evidence.",
    }
    return {
        "chainId": "solana",
        "url": f"https://dexscreener.com/solana/pair{index}",
        "baseToken": {"symbol": f"T{index}"},
        "priceUsd": "0.001",
        "marketCap": 100_000,
        "liquidity": {"usd": 20_000},
        "volume": {"h24": 50_000},
        "priceChange": {"h24": 25},
        "txns": {"h24": {"buys": 120, "sells": 80}},
        "pairCreatedAt": 1,
        "_analysis": {
            "opportunity_score": 65,
            "risk_flags": ["test risk evidence"],
            "unknown": [],
            "anomalies": [],
            "verdict": "WATCH",
        },
        "_developer": developer,
        "_smart_wallet": {
            "top_traders_detected": 10,
            "qualified_wallet_count": 1,
            "smart_money_score": "70/100",
        },
    }


class ScanRenderingTests(unittest.TestCase):
    def test_developer_concern_changes_result_only_with_independent_risk(self):
        risky_pair = pair(1)
        risky_pair["_analysis"]["opportunity_score"] = 70
        risky_pair["_analysis"]["verdict"] = "INTERESTING"
        risky_pair["_analysis"]["risk_flags"] = ["low liquidity"]

        _apply_developer_risk_evidence(
            risky_pair, {"developer_score": "25", "risk": "HIGH"}
        )

        self.assertEqual(risky_pair["_analysis"]["verdict"], "HIGH RISK")
        self.assertLess(risky_pair["_analysis"]["opportunity_score"], 70)
        self.assertTrue(risky_pair["_analysis"]["developer_risk_corroborated"])

    def test_late_holder_risk_corroborates_developer_concern(self):
        enriched_pair = pair(3)
        enriched_pair["_analysis"]["opportunity_score"] = 70
        enriched_pair["_analysis"]["verdict"] = "INTERESTING"
        enriched_pair["_analysis"]["risk_flags"] = []
        enriched_pair["_analysis"]["risk_flags"].append(
            "high top-10 holder concentration (Birdeye)"
        )

        _apply_developer_risk_evidence(
            enriched_pair, {"developer_score": "25", "risk": "HIGH"}
        )

        self.assertEqual(enriched_pair["_analysis"]["verdict"], "HIGH RISK")
        self.assertTrue(enriched_pair["_analysis"]["developer_risk_corroborated"])

    def test_developer_history_alone_cannot_force_verdict(self):
        uncorroborated_pair = pair(2)
        uncorroborated_pair["_analysis"]["opportunity_score"] = 70
        uncorroborated_pair["_analysis"]["verdict"] = "INTERESTING"
        uncorroborated_pair["_analysis"]["risk_flags"] = []

        _apply_developer_risk_evidence(
            uncorroborated_pair, {"developer_score": "25", "risk": "HIGH"}
        )

        self.assertEqual(uncorroborated_pair["_analysis"]["verdict"], "INTERESTING")
        self.assertEqual(uncorroborated_pair["_analysis"]["opportunity_score"], 70)
        self.assertFalse(
            uncorroborated_pair["_analysis"]["developer_risk_corroborated"]
        )

    def test_two_five_and_ten_results_paginate_without_splitting_limit(self):
        for count in (2, 5, 10):
            with self.subTest(count=count):
                messages = _render_scan_messages(
                    [pair(index, history_available=index % 2 == 0) for index in range(count)]
                )
                self.assertTrue(messages)
                self.assertTrue(
                    all(len(message) <= MAX_TELEGRAM_MESSAGE_LENGTH for message in messages)
                )
                combined = "\n".join(messages)
                for index in range(count):
                    self.assertIn(f"🐸 T{index} · SOLANA", combined)

    def test_unknown_history_is_one_compact_summary(self):
        rendered = "\n".join(_render_scan_messages([pair(1)]))

        self.assertIn("History: UNKNOWN — no attributable prior launches", rendered)
        self.assertNotIn("Launches: UNKNOWN | Successful: UNKNOWN", rendered)
        self.assertNotIn("Suspected rug patterns: UNKNOWN", rendered)
        self.assertNotIn("Best previous: UNKNOWN", rendered)

    def test_available_historical_metrics_are_rendered_without_unknown_rows(self):
        rendered = "\n".join(_render_scan_messages([pair(2, history_available=True)]))

        self.assertIn("Historical market cap: $2,500,000", rendered)
        self.assertIn("Historical liquidity: $300,000 peak", rendered)
        self.assertIn("Liquidity activity: $100,000 added / $20,000 removed", rendered)
        self.assertIn("Developer selling: 4 sell(s), $125,000 sold", rendered)
        self.assertIn("Activity timing: Median 2.0h from launch", rendered)
        self.assertIn("Recent launches: Most recent observed prior launch", rendered)
        self.assertNotIn("Historical market cap: UNKNOWN", rendered)

    def test_oversized_external_fields_still_emit_sendable_result(self):
        oversized = pair(9)
        oversized["baseToken"]["symbol"] = "X" * 5_000
        oversized["url"] = "https://example.com/" + "u" * 5_000
        oversized["_developer"]["evidence"] = "e" * 5_000
        oversized["_developer"]["history_coverage"] = "c" * 5_000
        oversized["_analysis"]["risk_flags"] = ["r" * 5_000] * 10

        messages = _render_scan_messages([oversized])

        self.assertTrue(messages)
        self.assertTrue(
            all(len(message) <= MAX_TELEGRAM_MESSAGE_LENGTH for message in messages)
        )
        self.assertIn("🐸 X", "\n".join(messages))
        self.assertIn("VERDICT:", "\n".join(messages))


if __name__ == "__main__":
    unittest.main()