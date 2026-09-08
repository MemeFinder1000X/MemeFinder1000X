import asyncio
import unittest

from security_intelligence import SecurityIntelligence


class FakeProvider:
    def __init__(self, snapshot, profile=None, distribution=None, security_error=None):
        self.snapshot = snapshot
        self.profile = profile
        self.distribution = distribution
        self.security_error = security_error
        self.security_params = None
        self.profile_params = None
        self.distribution_params = None

    async def security_snapshot(self, token_address):
        self.security_params = {"token_address": token_address}
        if self.security_error is not None:
            raise self.security_error
        return self.snapshot.data.get("token_security")

    async def analyze_token(self, token_address):
        raise AssertionError("SecurityIntelligence should use security_snapshot")

    async def holder_profile(self, token_address):
        if self.profile is None:
            raise RuntimeError("unavailable")
        self.profile_params = {"token_address": token_address}
        return self.profile

    async def holder_distribution(self, token_address):
        if self.distribution is None:
            raise RuntimeError("unavailable")
        self.distribution_params = {"token_address": token_address}
        return self.distribution


class Snapshot:
    def __init__(self, data):
        self.data = data


class SecurityIntelligenceTests(unittest.TestCase):
    def run_async(self, coroutine):
        return asyncio.run(coroutine)

    def test_active_authorities_reduce_score(self):
        provider = FakeProvider(
            Snapshot({
                "token_security": {
                    "ownerAddress": "owner-wallet",
                    "freezeAuthority": "freeze-wallet",
                    "isHoneypot": False,
                },
            })
        )
        finding = self.run_async(SecurityIntelligence().analyze(provider, "token"))
        self.assertIsNotNone(finding.security_score)
        self.assertLess(finding.security_score, 70)
        self.assertIn("Mint authority is active", finding.warnings)
        self.assertIn("Freeze authority is active", finding.warnings)
        self.assertEqual(finding.lp_lock_burn, "UNKNOWN")
        self.assertEqual(provider.security_params["token_address"], "token")

    def test_disabled_authorities_are_parsed_from_birdeye_glossary(self):
        provider = FakeProvider(
            Snapshot({
                "token_security": {
                    "ownerAddress": None,
                    "renounced": True,
                    "freezeAuthority": "11111111111111111111111111111111",
                    "freezeable": False,
                    "isHoneypot": False,
                }
            })
        )
        finding = self.run_async(SecurityIntelligence().analyze(provider, "token"))
        self.assertEqual(finding.mint_authority, "DISABLED")
        self.assertEqual(finding.freeze_authority, "DISABLED")
        self.assertEqual(finding.honeypot, "NO")

    def test_holder_profile_tag_percentages_are_preserved(self):
        provider = FakeProvider(
            Snapshot({"token_security": {"isHoneypot": False}}),
            profile={
                "holder_summary": {"top10_holder": 0.61},
                "tags": {
                    "dev": {"percent_of_supply": 0.02},
                    "insider": {"percent_of_supply": 0.08},
                    "sniper": {"percent_of_supply": 0.04},
                    "bundler": {"percent_of_supply": 0.03},
                },
            },
        )
        finding = self.run_async(SecurityIntelligence().analyze(provider, "token"))
        self.assertEqual(finding.top10_percent, 61)
        self.assertEqual(finding.dev_percent, 2)
        self.assertEqual(finding.insider_percent, 8)
        self.assertEqual(finding.sniper_percent, 4)
        self.assertEqual(finding.bundler_percent, 3)
        self.assertEqual(provider.profile_params["token_address"], "token")

    def test_documented_top10_holder_shape_is_parsed(self):
        provider = FakeProvider(
            Snapshot({"token_security": {"isHoneypot": False}}),
            profile={
                "top10_holder": {"percent_of_supply": 0.73},
                "holder_summary": {"wallet_count": 169},
                "tags": {},
            },
        )
        finding = self.run_async(SecurityIntelligence().analyze(provider, "token"))
        self.assertAlmostEqual(finding.top10_percent, 73, places=6)
        self.assertIn("Top-10 holders control 73.0%", finding.warnings)
        self.assertLessEqual(finding.security_score, 40)

    def test_extreme_top10_is_capped_as_high_risk(self):
        provider = FakeProvider(
            Snapshot({"token_security": {"isHoneypot": False}}),
            profile={
                "data": {
                    "top10_holder": {"percent_of_supply": 1.0},
                    "tags": {},
                }
            },
        )
        finding = self.run_async(SecurityIntelligence().analyze(provider, "token"))
        self.assertEqual(finding.top10_percent, 100)
        self.assertLessEqual(finding.security_score, 25)
        self.assertEqual(finding.risk, "HIGH")

    def test_security_failure_does_not_block_holder_fallbacks(self):
        provider = FakeProvider(
            Snapshot({}),
            profile={
                "holder_summary": {"top10_holder": 0.42},
                "tags": {
                    "dev": {"percent_of_supply": 0.03},
                    "insider": {"percent_of_supply": 0.05},
                },
            },
            distribution={"summary": {"percent_of_supply": 0.42}},
            security_error=RuntimeError("HTTP 403"),
        )
        finding = self.run_async(SecurityIntelligence().analyze(provider, "token"))
        self.assertEqual(finding.top10_percent, 42)
        self.assertEqual(finding.dev_percent, 3)
        self.assertEqual(finding.insider_percent, 5)
        self.assertIn("Token-security endpoint unavailable", finding.warnings)
        self.assertTrue(any("HTTP 403" in item for item in finding.evidence))
        self.assertEqual(provider.profile_params["token_address"], "token")
        self.assertIsNone(provider.distribution_params)
        self.assertIsNotNone(finding.security_score)

    def test_distribution_is_used_when_profile_has_no_top10(self):
        provider = FakeProvider(
            Snapshot({"token_security": {"isHoneypot": False}}),
            profile={"tags": {}},
            distribution={"summary": {"percent_of_supply": 0.58}},
        )
        finding = self.run_async(SecurityIntelligence().analyze(provider, "token"))
        self.assertAlmostEqual(finding.top10_percent, 58, places=6)
        self.assertEqual(provider.distribution_params["token_address"], "token")

    def test_missing_security_data_is_inconclusive_not_safe(self):
        provider = FakeProvider(Snapshot({}))
        finding = self.run_async(SecurityIntelligence().analyze(provider, "token"))
        self.assertIsNone(finding.security_score)
        self.assertEqual(finding.risk, "INCONCLUSIVE")
        self.assertEqual(finding.confidence, "LOW")
        self.assertEqual(finding.lp_lock_burn, "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
