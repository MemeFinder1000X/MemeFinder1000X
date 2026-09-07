import asyncio
import unittest

from security_intelligence import SecurityIntelligence


class FakeProvider:
    def __init__(self, snapshot, profile=None):
        self.snapshot = snapshot
        self.profile = profile
        self.security_params = None
        self.profile_params = None

    async def security_snapshot(self, token_address):
        self.security_params = {"token_address": token_address}
        return self.snapshot.data.get("token_security")

    async def analyze_token(self, token_address):
        raise AssertionError("SecurityIntelligence should use security_snapshot")

    async def holder_profile(self, token_address):
        if self.profile is None:
            raise RuntimeError("unavailable")
        self.profile_params = {"token_address": token_address}
        return self.profile


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

    def test_missing_security_data_is_inconclusive_not_safe(self):
        provider = FakeProvider(Snapshot({}))
        finding = self.run_async(SecurityIntelligence().analyze(provider, "token"))
        self.assertIsNone(finding.security_score)
        self.assertEqual(finding.risk, "INCONCLUSIVE")
        self.assertEqual(finding.confidence, "LOW")
        self.assertEqual(finding.lp_lock_burn, "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
