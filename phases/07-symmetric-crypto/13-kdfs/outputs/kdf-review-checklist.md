---
name: KDF Review Checklist (HKDF / PBKDF2 / scrypt / Argon2)
description: A PR-ready decision guide and checklist for key separation, domain separation, salts, and safe parameter choices when deriving keys.
phase: 07-symmetric-crypto
lesson: 13-kdfs
---

# KDF Review Checklist (HKDF / PBKDF2 / scrypt / Argon2)

Use this checklist in PR reviews whenever you see:
- “derive key from …”, “stretch key”, “hash password”
- `HKDF`, `PBKDF2`, `scrypt`, `Argon2`, `bcrypt`
- a “master key” reused across multiple features

## Decision Guide (what to choose)

| If you start from... | You want... | Prefer | Notes |
|---|---|---|---|
| High-entropy secret (ECDH output, random seed, master key) | multiple independent subkeys | **HKDF** | Use distinct `info` labels per use (domain separation) |
| User password / passphrase | a key or password verifier | **Argon2id** | Modern default when available; tune memory/time; store parameters |
| User password / passphrase | a key or password verifier | **scrypt** | Strong, widely supported; memory-hard; store parameters |
| User password / passphrase | legacy/compatibility | **PBKDF2** | Not memory-hard; must use high iterations; often a migration target |

## HKDF Checklist (secret → subkeys)

- [ ] **Input entropy**: the input secret is high-entropy (not a human password).
- [ ] **Salt**: a salt is provided and unique per “instance” (session, file, device, protocol run). Empty salt is justified.
- [ ] **Domain separation**: every derived key has a unique, documented `info` label.
  - Example: `b"enc:v1"`, `b"mac:v1"`, `b"nonces:v1"`, `b"export:v1"`.
- [ ] **Key separation**: encryption keys are not reused as MAC keys, nonce seeds, wrapping keys, etc.
- [ ] **Transcript binding (protocols)**: if there is a handshake / negotiation, the `info` or context binds to it (version, suite, transcript hash).
- [ ] **Length limits**: derived output length stays within HKDF limits (and is validated).

## Password KDF Checklist (password → key/verifier)

- [ ] **Unique salt**: a per-password salt is generated and stored with the derived output.
- [ ] **Work factor**:
  - PBKDF2: iterations are high enough for your threat model.
  - scrypt/Argon2: memory and time costs are explicit, measured, and reviewed.
- [ ] **Parameter storage**: parameters (`iters` or `N/r/p` or `m/t/p`) are stored alongside the hash so verification is possible and upgrades are manageable.
- [ ] **Encoding**: password-to-bytes encoding is explicit (typically UTF-8) and consistent across platforms.
- [ ] **Constant-time verify**: comparisons use constant-time primitives (no early-return string compares).
- [ ] **Upgrade path**: there is a plan to increase work factors over time (and migrate legacy PBKDF2 when feasible).

## Red Flags (common failure patterns)

- [ ] HKDF used directly on passwords (“we salted it, so it’s fine”).
- [ ] One derived key reused across multiple purposes (“same key for enc + MAC”).
- [ ] `info` is empty everywhere or “whatever string looked nice” without a spec.
- [ ] Salts are constant, reused across users, or derived from public ids without randomness/uniqueness.
- [ ] Password KDF parameters are defaults with no measurement or threat model.
- [ ] Password hashes are stored without parameters (can’t verify or migrate safely).

## Review Template (paste into PR)

```
KDF checklist:
- Input type (high-entropy secret vs password):
- KDF choice (HKDF / PBKDF2 / scrypt / Argon2id):
- Salt source + uniqueness scope:
- Domain separation labels (info/context) per derived key:
- Derived keys (names + lengths + uses):
- Password KDF parameters (iters or N/r/p or m/t/p) + storage format:
- Encoding and constant-time verification:
- Upgrade/migration plan:
```

