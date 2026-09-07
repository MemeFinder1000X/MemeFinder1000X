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

## Railway deployment

MemeFinder 1000X is designed to run as a continuously running Telegram long-polling service.

1. Create a new Railway project and deploy this GitHub repository.
2. Railway will detect the root `Dockerfile` and build the service from it.
3. Add these variables in the Railway service's **Variables** section:
   - `TELEGRAM_BOT_TOKEN`
   - `BIRDEYE_API_KEY`
   - Optional: `BIRDEYE_API_BASE_URL`
4. Leave the Dockerfile start command unchanged. The container starts with `python bot.py`.
5. Use a normal persistent Railway service. Do not configure this bot as a cron job.
6. No HTTP healthcheck is required for Telegram long polling; the bot does not expose an HTTP health endpoint by default.

After deployment, check the Railway deployment logs for a clean startup, then send `/start` and `/scan` to the Telegram bot.

## Important

Do not put real API keys or Telegram tokens into GitHub, ZIP files, source code, or screenshots. Use Railway's secret/environment-variable settings.

The scoring is an opportunity/risk heuristic, not a guarantee of future returns. `UNKNOWN` means the available data was insufficient and is intentionally not guessed.
