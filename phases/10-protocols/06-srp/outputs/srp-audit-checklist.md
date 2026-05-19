---
name: "SRP Implementation Audit Checklist"
description: "A practical checklist for reviewing SRP-6a (Secure Remote Password) implementations and integrations."
phase: "10-protocols"
lesson: "06-srp"
---

# SRP-6a Implementation Audit Checklist

Use this to review SRP in:
- legacy auth services,
- “custom SRP” clients/servers,
- protocol changes that touch SRP transcript hashing, encoding, or key confirmation.

> SRP is subtle. If you’re not required to use SRP for compatibility, prefer a modern, well-reviewed PAKE library (often OPAQUE).

## 1) Threat model sanity
- You want resistance to **offline guessing from a network transcript** (passive capture).
- You still accept that **server database compromise enables offline guessing** of user passwords (because `s` and `v` allow verifying guesses).
- You understand SRP does **not** replace rate-limiting, MFA, or secure recovery flows.

## 2) Parameter and group checks
- Uses a vetted group (safe prime `N`, generator `g`) and fixes it in code/config.
- Does not accept attacker-chosen `(N, g)` from the network.
- Uses a modern hash (e.g., SHA-256 or stronger) consistently everywhere SRP hashes.

## 3) Canonical encoding (most common real bug)
- Uses a **single canonical integer-to-bytes** encoding across the whole implementation.
- Hash inputs that require padding use `PAD(x)` where `len(PAD(x)) == len(N)` bytes.
- The transcript for `u = H(PAD(A) || PAD(B))` is exactly specified and consistent between languages.

## 4) Mandatory SRP safety checks
Server-side:
- Rejects `A % N == 0` immediately.
- Rejects client proof `M1` before revealing any server proof.

Client-side:
- Rejects `B % N == 0`.
- Rejects `u == 0`.

Both sides:
- Validate parsed integers are in range (no negative, no overflows, reasonable length bounds).

## 5) Key confirmation binding
- Client sends `M1` computed over the **full transcript** (at least `I, s, A, B, K`, plus the standard `H(N) XOR H(g)` binding).
- Server verifies `M1` and only then returns `M2 = H(A || M1 || K)`.
- Client verifies `M2` before treating the session as authenticated.

## 6) Randomness and nonce lifecycle
- `a` and `b` are generated with a CSPRNG and never reused.
- Ephemeral secrets are erased/forgotten after session completion (where practical).
- No “fallback” mode that silently reuses `a`/`b` on errors or retries.

## 7) What you do with K (integration)
- Do not use `K` directly as an encryption key without a KDF.
- Derive distinct keys (example): `Kc2s = H(K || \"c2s\")`, `Ks2c = H(K || \"s2c\")`.
- Use an AEAD (or at least HMAC) for post-login channel protection and bind it to the session identity.

## 8) Error handling and side-channel basics
- Errors do not leak whether the username exists or whether the password was wrong (where possible).
- Avoids branchy, data-dependent behavior in sensitive areas (SRP math is not constant-time in most from-scratch code).
- Logging never includes `a`, `b`, `x`, `S`, `K`, `M1`, `M2`.

## 9) Test coverage expectations
- Has known-good deterministic vectors for `k, x, v, u, M1, M2`.
- Includes negative tests for invalid `A`/`B` and wrong-password rejection.
- Includes cross-language interop tests if SRP is implemented in multiple stacks.

