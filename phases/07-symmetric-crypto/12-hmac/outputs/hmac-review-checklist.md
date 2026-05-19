---
name: "HMAC Review Checklist"
description: "A practical checklist for using and reviewing HMAC in APIs, webhooks, tokens, and protocol glue code."
phase: "07-symmetric-crypto"
lesson: "12-hmac"
---

# HMAC Review Checklist

Use this in PR reviews when you see “signature”, “MAC”, “webhook signing”, “signed request”, “API token”, or “integrity tag”.

## 1) Identify the exact construction
- What hash is used: **HMAC-SHA-256**, **HMAC-SHA-512**, etc?
- What is the **tag length** on the wire (full 32 bytes for SHA-256, or truncated like 16 bytes)?
- What is the **encoding** (raw bytes, hex, base64, URL-safe base64)?
- What is the **message format** being signed (exact bytes, including separators, newlines, canonical JSON rules, URL normalization)?

## 2) Key management questions (most real failures live here)
- Is the key **random bytes**, not a password or API key string reused from elsewhere?
- Is there clear **key rotation** (versioning, overlapping validity window, expiration)?
- Is the key stored in the right place (KMS/HSM/secret store), with least-privilege access?
- Is the key **separated by purpose** (webhooks vs cookies vs file integrity)? If not, is there explicit domain separation (see below)?

## 3) Domain separation (avoid cross-protocol surprises)
- Is a context string included in the signed bytes, e.g. `b"webhook:v1|" + payload`?
- If the same key is reused across features, do different features sign different prefixes/labels?

## 4) Verification semantics (must be strict and boring)
- Is verification done with a **constant-time compare** (`hmac.compare_digest` in Python)?
- Is the tag **decoded** and validated (correct length, correct alphabet) *before* comparing?
- On failure, does the code **reject** the request/message before parsing or acting on it?
- Are error messages non-oracular (no “first 5 bytes matched” style leakage)?

## 5) Truncation policy (if used)
- Is truncation written into the spec (e.g. “take first 16 bytes”)?
- Is the verifier enforcing the exact truncated length (rejecting too-short/too-long tags)?
- Is the chosen length reasonable (common choices: **16 bytes** / 128-bit tags)?

## 6) Common red flags
- `sha256(key + msg)` or `sha256(msg + key)` used as a “MAC”.
- `tag1 == tag2` used directly on secret tags.
- Tag computed over *parsed* structures without canonicalization (e.g. JSON with unstable key order/whitespace).
- Tag computed over user-visible strings without a specified encoding (UTF-8 vs Latin-1 vs normalization).

## 7) Minimal-safe Python pattern (reference)
```python
import base64
import hashlib
import hmac

def verify_webhook(key: bytes, body: bytes, tag_b64: str) -> bool:
    try:
        tag = base64.b64decode(tag_b64, validate=True)
    except Exception:
        return False

    expected = hmac.new(key, body, hashlib.sha256).digest()
    return hmac.compare_digest(expected, tag)
```

