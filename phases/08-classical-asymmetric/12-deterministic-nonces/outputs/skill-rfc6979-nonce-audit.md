---
name: rfc6979-nonce-audit
description: Audit checklist for deterministic nonces (RFC 6979) in DSA/ECDSA codebases: what to verify, what to forbid, and how to detect compromise.
version: 1.0.0
phase: 8
lesson: 12
tags: [cryptography, dsa, ecdsa, rfc6979, signatures, audits]
---

You are reviewing a system that **signs** with DSA/ECDSA (JWTs, blockchain txs, API auth, firmware, attestations). Your goal: determine whether nonce generation is safe, and whether any past signatures suggest compromise.

Output:
- A risk rating (Low/Med/High/Critical) with one sentence.
- Must-fix and nice-to-fix items.
- If compromise is plausible: an incident response plan (what to collect, what to rotate).

## 1) Quick triage (30 seconds)

Answer yes/no:

1. Is signing done using **deterministic nonces (RFC 6979)** or inside **HSM/KMS** hardware that keeps nonce generation internal?
2. If not deterministic/hardware: is `k` generated from an OS CSPRNG (never `random`, never custom PRNG)?
3. Can signer instances be cloned/restored (VM snapshots, container cloning, process forking, hibernate resume) in a way that can repeat RNG state?
4. Do logs/telemetry ever include ephemeral scalars (nonce `k`, intermediate points, internal seeds)?

If (1) is “no” and (2) or (3) is “yes”, mark **High** immediately.

## 2) What “good” looks like (nonce requirements)

Required for each signature under the same private key:
- `k` is **unique**.
- `k` is **secret** (never logged, never returned).
- `k` is **unpredictable** to attackers (either uniformly random or RFC 6979 deterministic).

RFC 6979-specific:
- `k` is derived from `(x, H(m))` using HMAC-DRBG with the RFC’s conversion rules (`bits2int`, `int2octets`, `bits2octets`).
- If a generated candidate `k` is out of range (0 or ≥ group order), the implementation updates the internal DRBG state and retries.

## 3) Implementation checklist (signing)

### Deterministic nonce generation
- Uses RFC 6979 exactly (or a well-known audited library that explicitly states RFC 6979).
- Uses the correct group order (`q`/`n`) for the curve/parameters in use.
- Hash function is explicit and consistent with protocol expectations (e.g., SHA-256 vs SHA-512).
- No “helpful” post-processing like `k %= q` (range rejection must follow RFC 6979 rules).

### Signature checks
- Rejects/avoids signatures where `r == 0` or `s == 0` (regenerate `k` and retry).
- Verifies the public key and parameters are valid and expected (wrong curve / wrong order is a real incident class).

### What to forbid in application code
- Any “bring your own nonce” hook where callers can pass `k`.
- Any custom nonce scheme like `k = H(x || m)` without RFC 6979 (even if it “seems fine”, it’s hard to audit and easy to get subtly wrong).
- Any logging of raw signature internals beyond `(r,s)` and message identifiers.

## 4) How to detect nonce reuse in the wild

For a fixed private key:
- If two signatures share the same `r`, they almost certainly share the same nonce `k`.
- Nonce reuse is typically **catastrophic**: assume private key recovery is feasible.

What to collect for analysis:
- The message bytes (or exact hashing input), hash function used, and the resulting signature `(r,s)`.
- Timestamps, signer instance IDs, deployment topology, and restart/snapshot history.

## 5) Incident response (if compromise suspected)

1. Treat the signing key as potentially compromised.
2. Rotate keys and revoke/reissue signed artifacts as needed.
3. Identify the window of exposure (when the bug/config change began).
4. Add monitoring to detect repeated `r` values per key going forward.

## 6) Review note template (copy/paste)

Risk rating: <Low/Med/High/Critical> — <one sentence>

Must-fix:
- <item>

Nice-to-fix:
- <item>

If compromise suspected:
- Evidence to gather: <bullets>
- Key rotation plan: <bullets>
- Scope of impact: <bullets>

