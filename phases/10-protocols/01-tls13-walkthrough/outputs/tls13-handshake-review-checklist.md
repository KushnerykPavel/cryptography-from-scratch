---
name: TLS 1.3 Handshake Review Checklist
description: A practical checklist for reviewing TLS 1.3 (or TLS-like) handshake and key schedule code: transcript boundaries, HKDF labels, Finished, and KeyUpdate.
phase: 10
lesson: 01-tls13-walkthrough
---

# TLS 1.3 Handshake Review Checklist

Use this when reviewing code that:
- Implements any part of TLS 1.3 (or a custom “TLS-like” handshake).
- Derives traffic keys from a handshake transcript.
- Verifies Finished / binds keys to handshake messages.
- Performs key update / rekeying without a new handshake.

## Go / No-go (30 seconds)

- Are they using a mature TLS library (OpenSSL/BoringSSL/rustls/NSS) instead of custom TLS?
- If custom protocol is unavoidable: are they explicitly modeling transcript hashing + HKDF labels + Finished?
- Are secrets never logged in production and never persisted beyond what the spec allows (resumption only)?

## Transcript hashing

- Transcript hash is computed over the exact serialized handshake bytes (type + length + payload), in order.
- Transcript includes *all* handshake messages (including extensions), even if some are ignored.
- Transcript boundary checkpoints match the spec:
  - Handshake traffic secrets bind to `TH(ClientHello..ServerHello)`.
  - Application traffic secrets bind to `TH(ClientHello..ServerFinished)`.
- Any “change in transcript” is guaranteed to change derived secrets (no accidental hashing of normalized/parsed structures).

## HKDF + labels

- Uses HKDF correctly:
  - `HKDF-Extract(salt, IKM)` as HMAC(salt, IKM)
  - `HKDF-Expand(PRK, info, L)` chaining with counters
- TLS 1.3 uses `HKDF-Expand-Label` with:
  - `"tls13 "` prefix in the label bytes
  - 2-byte output length (uint16)
  - 1-byte label length and 1-byte context length
- Label strings match the spec exactly (common ones: `derived`, `c hs traffic`, `s hs traffic`, `c ap traffic`, `s ap traffic`, `finished`, `key`, `iv`, `traffic upd`).

## Finished verification

- `finished_key = HKDF-Expand-Label(traffic_secret, "finished", "", Hash.length)`
- `verify_data = HMAC(finished_key, transcript_hash)`
- Transcript hash used for Finished excludes the Finished message being verified.
- Any mismatch in transcript, labels, or secrets causes Finished failure (no “best effort” fallback).

## Traffic keys and IVs

- Keys and IVs are derived from the correct traffic secret:
  - `key = HKDF-Expand-Label(traffic_secret, "key", "", key_len)`
  - `iv  = HKDF-Expand-Label(traffic_secret, "iv",  "", iv_len)`
- Lengths are correct for the negotiated AEAD (e.g., AES-128-GCM: key=16 bytes, iv=12 bytes).
- Separate secrets per direction (client vs server) and per epoch (handshake vs application).

## KeyUpdate / rekeying

- Rekey uses the spec label (TLS 1.3: `traffic upd`) and does not change authentication state.
- Rekey rotates application traffic secrets without changing the handshake transcript.
- Rekey is rate-limited / abuse-resistant (no unbounded key updates on attacker-controlled triggers).

## Red flags

- Any custom TLS implementation without a compelling threat model and extensive test vectors.
- “We hash parsed JSON / structured fields” instead of raw bytes for the transcript.
- Handwritten AEAD (or nonce construction) outside a well-tested library.
- Using TLS 1.2/older PRF labels or missing the `"tls13 "` prefix.
- Recovering from Finished failure by retrying with different settings (silent downgrade).

## Questions to ask in the PR

- “Show me exactly which bytes go into the transcript hash and where you validate ordering.”
- “Which transcript hash checkpoint do you use for each secret (hs vs ap), and why?”
- “Where are HKDF labels defined, and how do you ensure they match the spec?”
- “How do you test Finished against known-good vectors (RFC 8448 or captured traces)?”
- “What’s the KeyUpdate policy and what prevents rekey spam?”

