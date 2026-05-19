---
name: ecdsa-nonce-audit
description: Audit checklist for ECDSA nonce safety (reuse/leak/bias), plus mitigations and incident-response questions.
version: 1.0.0
phase: 8
lesson: 07
tags: [cryptography, ecdsa, secp256k1, signatures, audits]
---

You are reviewing a system that **signs** with ECDSA (JWTs, blockchain txs, API auth, firmware, etc.). Your job is to decide: is the nonce strategy safe, and what is the blast radius if it isn’t?

Output:
- A short risk rating (Low/Med/High/Critical) with one sentence.
- A list of **must-fix** items and **nice-to-fix** items.
- If compromise is plausible: an incident-response plan (what to collect, what to rotate).

## 1) Quick triage (30 seconds)

Answer these yes/no questions:

1. Is the signer using **deterministic nonces (RFC6979)** or a **hardware signer (HSM/KMS)** that generates nonces internally?
2. If not deterministic/hardware: is the signer using a **CSPRNG** (`secrets`, `/dev/urandom`, OS crypto provider), not `random`?
3. Is there any chance of **VM snapshot restore**, container cloning, process forking, or “resume from hibernate” that could repeat RNG state?
4. Are there any code paths that **log k**, log internal scalars, or expose timing/power side channels?

If (1) is “no” and (2) or (3) is “yes”, mark **High** immediately.

## 2) Nonce generation checklist (signing)

### Required
- Nonce `k` must be **unique per signature** for a given private key.
- Nonce `k` must be **secret** (never logged, never returned).
- Nonce `k` must be **unpredictable** to an attacker (uniform or deterministic RFC6979).

### Strongly recommended
- Use RFC6979-style deterministic nonces derived from `(d, H(m))`, or sign inside a KMS/HSM.
- Add hard guardrails: fail closed if the nonce generator is not initialized or entropy source is unavailable.
- If your library exposes “provide your own k”: forbid it in app code (remove the option, or lint it).

### Red flags (often catastrophic)
- Any use of `random` / `Math.random()` / weak PRNGs for `k`.
- Any reuse of `k` due to caching, retries, or concurrency bugs.
- Any “optimization” that clamps `k` into a smaller range (e.g., 16-bit or 32-bit).
- Any debug mode that logs ephemeral scalars or intermediate values.

## 3) Verification checklist (accepting signatures)

Minimum checks:
- Reject signatures with `r == 0` or `s == 0`.
- Reject if `r` or `s` are outside `1..n-1`.
- Validate the public key is **on the expected curve** (and not the point at infinity).

Contextual checks (when applicable):
- Enforce “low-s” normalization if your ecosystem expects it (prevents signature malleability).
- Confirm the curve is exactly what you expect (no silent P-256 vs secp256k1 mismatch).

## 4) Incident-response questions (if compromise is suspected)

Collect:
- All signatures (r, s) and their associated messages/hashes.
- Timestamps, signer instance IDs, deployment events (snapshots, restarts, rollbacks).
- Any logs that could include nonces, seeds, or internal debug traces.

Ask:
- Do any two signatures share the same `r`? (Strong evidence of nonce reuse.)
- Did the signer run on a platform known for entropy bugs (early boot, embedded, misconfigured VMs)?
- Was there a recent change in crypto library, hardware, or runtime?

Actions:
- If nonce reuse is confirmed: assume the private key `d` is recoverable. Rotate keys and revoke artifacts signed under the compromised key.
- If only weak nonces are suspected: estimate feasibility (range size, number of signatures, attacker access) and treat conservatively.

## 5) Recommended mitigations (copy/paste into a PR review)

- Use a well-maintained crypto library and enable deterministic ECDSA (RFC6979) when available.
- Prefer KMS/HSM signing for high-value keys; keep `d` out of application memory.
- Add tests that detect accidental nonce reuse across signatures in the test suite (same message and different message cases).
- Add monitoring that flags repeated `r` values over time for the same key.
- Remove or lock down any “custom nonce” hooks.

## 6) Output template

Risk rating: <Low/Med/High/Critical> — <one sentence>

Must-fix:
- <item>

Nice-to-fix:
- <item>

If compromise suspected:
- Evidence to gather: <bullets>
- Key rotation plan: <bullets>
- Scope of impact: <bullets>

