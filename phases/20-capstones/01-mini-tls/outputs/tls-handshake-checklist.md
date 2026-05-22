---
name: TLS 1.3 Implementation Checklist
description: Checklist for reviewing TLS 1.3 handshake and record-layer implementations in code reviews and security audits.
phase: 20-capstones
lesson: 01-mini-tls
---

# TLS 1.3 Implementation Checklist

Use this checklist when reviewing any code that implements, wraps, or configures TLS 1.3 — including custom handshake logic, library integrations, and protocol adapters.

---

## Key Exchange

- [ ] Ephemeral DH key pairs are generated fresh per handshake (not cached or reused across connections)
- [ ] Private DH scalars are wiped from memory / go out of scope immediately after the shared secret is computed
- [ ] The DH group is a safe, approved curve or FFDH group (X25519, X448, or FFDHE2048+)
- [ ] The server's public DH value in ServerHello is authenticated (tied to the certificate) before use

## Key Schedule (RFC 8446 §7.1)

- [ ] `early_secret` is derived with `HKDF-Extract(0^hash_len, PSK_or_zeros)` — not with the ECDHE output
- [ ] `handshake_secret` uses `HKDF-Extract(Derive-Secret(early, "derived", ""), ECDHE_shared)`
- [ ] `master_secret` uses `HKDF-Extract(Derive-Secret(hs, "derived", ""), zeros)` — ECDHE is not mixed in a second time
- [ ] Every `HKDF-Expand-Label` call uses the "tls13 " prefix on the label (prevents cross-version key confusion)
- [ ] Traffic secrets (`c hs traffic`, `s hs traffic`, `c ap traffic`, `s ap traffic`) are bound to the correct transcript hash
- [ ] Handshake-traffic keys and application-traffic keys are derived from different parent secrets

## Transcript Hash

- [ ] The transcript hash covers all handshake messages in order from ClientHello through the message being authenticated
- [ ] The hash is recomputed (not cached from an earlier point) for each Finished and each Derive-Secret call that requires it
- [ ] Any HelloRetryRequest causes the transcript to be replaced with a synthetic `message_hash` per RFC 8446 §4.4.1

## Finished Messages

- [ ] `finished_key = HKDF-Expand-Label(traffic_secret, "finished", "", hash_len)`
- [ ] `verify_data = HMAC-Hash(finished_key, transcript_hash)` — not a direct hash of the transcript
- [ ] Finished verification uses a constant-time comparison (`hmac.compare_digest` or equivalent)
- [ ] The server's Finished is verified before the client sends its own Finished
- [ ] Handshake is aborted immediately and unconditionally if either Finished fails to verify

## AEAD / Record Layer

- [ ] Nonce = `write_iv XOR (sequence_number padded to iv_length with leading zeros)` — not just the IV, not just the counter
- [ ] The sequence number is incremented atomically before returning the encrypted record
- [ ] The sequence number is never reset without deriving a new key (key update, RFC 8446 §4.6.3)
- [ ] AEAD tag verification happens before any decrypted bytes are returned or acted upon
- [ ] Tag comparison is constant-time
- [ ] The `aad` (additional authenticated data) includes content type, protocol version, and ciphertext length per RFC 8446 §5.2
- [ ] Application data and handshake records use separate write keys (application traffic keys, not handshake traffic keys)

## Certificate / Authentication

- [ ] The server certificate chain is validated against a trusted root (not just "is it a valid X.509 cert")
- [ ] The server's CertificateVerify signature covers the entire transcript hash, not just the certificate
- [ ] The signature algorithm in CertificateVerify matches a supported algorithm listed in the ClientHello
- [ ] Client certificate authentication (mTLS), if required, is enforced on the server side before proceeding

## Configuration / Library Usage

- [ ] TLS 1.0, 1.1, 1.2 are disabled if TLS 1.3 is the target (check `minimum_version` / `PROTOCOL_TLS_CLIENT`)
- [ ] Weak cipher suites (RC4, 3DES, NULL, EXPORT) are explicitly disabled even in fallback config
- [ ] Certificate hostname verification is enabled and not suppressed (`check_hostname=True` in Python `ssl`)
- [ ] Certificates are checked against a non-empty CA bundle (`cafile` or `capath` set; not `verify_mode=CERT_NONE`)
- [ ] Session resumption tickets, if used, are encrypted with a rotating server key (not a static long-term key)

## Operational / Deployment

- [ ] Secrets (private keys, finished_key material) are not logged, even at DEBUG level
- [ ] TLS error messages returned to clients are generic ("handshake failed") — not "bad padding", "unknown CA", etc.
- [ ] Connections failing Finished verification are terminated with the same error and latency as other failures (no timing oracle)
- [ ] Key material is zeroed / freed after use where the runtime permits (use `memoryview` / `ctypes` in Python if needed)
- [ ] Certificate expiry monitoring is in place; rotation does not require a deploy

---

## Quick Reference: What Each Secret Protects

| Secret | Protects | Discarded after |
|--------|----------|-----------------|
| `early_secret` | 0-RTT early data (if PSK used) | ServerHello received |
| `client_hs_traffic` | Client EncryptedExtensions, Finished | Handshake complete |
| `server_hs_traffic` | Server Certificate, CertVerify, Finished | Handshake complete |
| `client_ap_traffic` | Client application records | Key update or session end |
| `server_ap_traffic` | Server application records | Key update or session end |

---

## Red Flags — Reject the PR

- Any use of `hmac.compare_digest` replaced with `==` for tag or Finished comparison
- Sequence number reset to 0 without a corresponding key update handshake
- `verify_mode=CERT_NONE` or `check_hostname=False` in non-test code
- Handshake-traffic write key reused for application records
- ECDHE private key stored in a class field, database, or log file
- `ssl.SSLContext` created with `ssl.PROTOCOL_SSLv23` (deprecated catch-all) without setting `minimum_version`
