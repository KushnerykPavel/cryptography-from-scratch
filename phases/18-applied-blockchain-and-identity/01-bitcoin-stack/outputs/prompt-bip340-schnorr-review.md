---
name: prompt-bip340-schnorr-review
description: A copy/paste prompt + checklist for reviewing BIP340 Schnorr (Taproot) signing and verification code on secp256k1, including SHA-256 tagged hashing and edge-case validation.
phase: 18-applied-blockchain-and-identity
lesson: 01-bitcoin-stack
---

# BIP340 Schnorr review prompt (Bitcoin / Taproot)

You are my cryptography reviewer. I will paste code that claims to implement **BIP340 Schnorr signatures** over **secp256k1**, including any message hashing / sighash logic and public key parsing. Review it as if it could ship in a wallet, signer, bridge, or custody backend.

## 1) What is being signed?

- What exact byte string is the signer computing `msg` from?
- Is it *actually* the Bitcoin/Taproot sighash format (and tagged hashing where required), or did someone sign the `txid` / raw transaction bytes by mistake?
- Is the signed message domain-separated from other protocols (wallet messages, API challenges, login nonces)?

## 2) Key handling (x-only pubkeys)

- Are BIP340 public keys handled as **32-byte x-only keys**?
- Does verification implement `lift_x(x)` and select the point with **even y**?
- If the implementation converts between full pubkeys and x-only pubkeys, are conversions consistent and unambiguous?
- Are invalid public keys rejected (x ≥ p, or x not a curve x-coordinate)?

## 3) Tagged hashing

Check that the implementation uses the exact BIP340 construction:

- `tagged_hash(tag, m) = SHA256(SHA256(tag) || SHA256(tag) || m)`
- Correct tags:
  - `"BIP0340/aux"` for auxiliary randomness
  - `"BIP0340/nonce"` for deterministic nonce derivation
  - `"BIP0340/challenge"` for `e`

## 4) Nonce safety

- Is the nonce `k` derived deterministically from (secret key, pubkey, msg, aux) as specified?
- Is `aux_rand` treated as 32 bytes? If `aux_rand` comes from outside, is it authenticated / entropy-safe?
- Does the code prevent accidental nonce reuse (caching, retries, concurrency)?
- Does the implementation normalize `k` so that `R` has **even y** (and flip `k` if not)?

## 5) Verification checks (must happen before heavy math)

Verify the verifier rejects early:

- `len(pubkey) == 32` and `len(sig) == 64`
- Parse `r = int(sig[0:32])`, `s = int(sig[32:64])`
- Reject if `r ≥ p` or `s ≥ n`
- Reject if `lift_x(pubkey)` fails (pubkey not on curve)

Then the core check should look like:

- `e = int(tagged_hash("BIP0340/challenge", r||pubkey||msg)) mod n`
- `R = s⋅G - e⋅P`
- Reject if `R` is infinity
- Reject if `R` has odd y
- Accept only if `x(R) == r`

## 6) Side-channel and implementation risks

- Is signing constant-time (no secret-dependent branching, lookup tables, or variable-time inversions)?
- If the code is “educational” or pure-Python, is it clearly labeled as **not production-safe**?
- Are secrets wiped / kept out of logs (including debug traces)?

## 7) Tests and vectors

- Does it pass known-good BIP340 test vectors (`bitcoin/bips: bip-0340/test-vectors.csv`)?
- Are there negative tests for malformed keys, out-of-range scalars, and invalid signatures?
- Are error messages and exceptions safe (no secret-dependent differences)?

## 8) Final verdict

Summarize:

- High-risk issues (fund loss / key compromise)
- Medium-risk issues (interoperability / malleability)
- Low-risk issues (style / clarity)
- Concrete remediation steps (libraries, checks, tests)

