"""Safe one-way diagnostic for the Railway Birdeye API key.

Never logs or returns the API key itself. Logs only its length and a short
SHA-256 fingerprint so it can be compared with a local copy without exposing
the credential.
"""
from __future__ import annotations

import hashlib
import logging
import os

logger = logging.getLogger(__name__)


def log_birdeye_key_fingerprint() -> str:
    key = os.getenv("BIRDEYE_API_KEY", "")
    if not key:
        fingerprint = "MISSING"
    else:
        fingerprint = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
    logger.warning(
        "Birdeye key diagnostic: fingerprint=%s length=%d",
        fingerprint,
        len(key),
    )
    return fingerprint


log_birdeye_key_fingerprint()
