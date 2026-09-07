# Security intelligence

The security layer is read-only and evidence-weighted.

- Mint/freeze authority, honeypot, holder concentration and tagged holder cohorts are treated as separate signals.
- Missing data is reported as UNKNOWN/INCONCLUSIVE rather than assumed safe.
- Liquidity presence is never treated as proof that LP is locked or burned.
- Security Score is separate from Opportunity Score.
- The startup integration is idempotent so existing bot logic is not duplicated.
