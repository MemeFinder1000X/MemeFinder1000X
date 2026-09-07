# MemeFinder 1000X — Deploy Ready

This is the cleaned, Python-only deployment package for the MemeFinder 1000X Telegram scanner.

## What it does

- Scans DEX Screener's latest token profiles.
- Filters for recognizable meme-token signals.
- Enriches tokens with pair metrics and transparent opportunity/risk scoring.
- Adds Birdeye holder/security evidence when a Birdeye API key is configured.
- Adds read-only smart-wallet intelligence when indexed wallet data is available.
- Adds conservative developer/launch-history intelligence.
- Never connects to a wallet, signs a transaction, or executes trades.

## Required environment variables

`TELEGRAM_BOT_TOKEN` — token from BotFather.

`BIRDEYE_API_KEY` — recommended for Solana holder/security and smart-wallet intelligence.

Optional:

`BIRDEYE_API_BASE_URL` — defaults to `https://public-api.birdeye.so`.

## Local test

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export TELEGRAM_BOT_TOKEN='...'
export BIRDEYE_API_KEY='...'
python bot.py
```

Then open Telegram and send `/start` followed by `/scan`.

## Docker

```bash
docker build -t memefinder1000x .
docker run --rm \
  -e TELEGRAM_BOT_TOKEN='...' \
  -e BIRDEYE_API_KEY='...' \
  memefinder1000x
```

## Koyeb deployment

For a continuously running Telegram long-polling bot, use an always-on paid instance rather than Koyeb's free Web Service. Koyeb currently lists an Eco Nano instance at about $1.61/month and a Free Instance that is intended for testing and scales to zero after inactivity.

Create a service from this repository/archive, use Docker, and set:

- Instance: `eco-nano` (or larger if needed)
- Command: leave the Dockerfile default
- Environment: `TELEGRAM_BOT_TOKEN`, `BIRDEYE_API_KEY`

## Important

Do not put real API keys or Telegram tokens into GitHub, ZIP files, source code, or screenshots. Use the hosting provider's secret/environment-variable settings.

The scoring is an opportunity/risk heuristic, not a guarantee of future returns. `UNKNOWN` means the available data was insufficient and is intentionally not guessed.
