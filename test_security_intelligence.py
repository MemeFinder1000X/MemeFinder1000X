import pytest

from security_intelligence import SecurityIntelligence


class FakeProvider:
    def __init__(self, snapshot, profile=None, distribution=None):
        self.snapshot = snapshot
        self.profile = profile
        self.distribution = distribution

    async def analyze_token(self, token_address):
        return self.snapshot

    async def _get(self, path, params):
        if path.endswith("holder-profile"):
            if self.profile is None:
                raise RuntimeError("unavailable")
            return self.profile
        if self.distribution is None:
            raise RuntimeError("unavailable")
        return self.distribution


class Snapshot:
    def __init__(self, data):
        self.data = data


@pytest.mark.asyncio
async def test_active_authorities_reduce_score():
    provider = FakeProvider(
        Snapshot({
            "token_security": {
                "mintAuthority": "active",
                "freezeAuthority": "active",
                "isHoneypot": False,
            },
            "token_holders": {"top10_holder_percent": 40},
            "liquidity_history": {"items": []},
        })
    )
    finding = await SecurityIntelligence().analyze(provider, "token")
    assert finding.security_score is not None
    assert finding.security_score < 70
    assert "Mint authority is active" in finding.warnings
    assert finding.lp_lock_burn == "UNKNOWN"


@pytest.mark.asyncio
async def test_holder_profile_tag_percentages_are_preserved():
    provider = FakeProvider(
        Snapshot({"token_security": {"isHoneypot": False}}),
        profile={
            "holder_summary": {"top10_holder": 0.61},
            "tags": {
                "dev": 0.02,
                "insider": 0.08,
                "sniper": 0.04,
                "bundler": 0.03,
            },
        },
        distribution={"top10_percent": 61},
    )
    finding = await SecurityIntelligence().analyze(provider, "token")
    assert finding.top10_percent == 61
    assert finding.dev_percent == 2
    assert finding.insider_percent == 8
    assert finding.sniper_percent == 4
    assert finding.bundler_percent == 3


@pytest.mark.asyncio
async def test_missing_security_data_is_inconclusive_not_safe():
    provider = FakeProvider(Snapshot({}))
    finding = await SecurityIntelligence().analyze(provider, "token")
    assert finding.security_score is None
    assert finding.risk == "INCONCLUSIVE"
    assert finding.confidence == "LOW"
    assert finding.lp_lock_burn == "UNKNOWN"
