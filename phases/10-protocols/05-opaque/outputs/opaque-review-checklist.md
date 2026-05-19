---
name: OPAQUE Review Checklist
description: A practical PR/audit checklist for OPAQUE (RFC 9807) password authentication and key exchange integrations.
phase: 10-protocols
lesson: 05-opaque
---

# OPAQUE (RFC 9807) Review Checklist

Use this to review a PR, design doc, or implementation that claims “OPAQUE login”, “OPRF-hardened passwords”, or “augmented PAKE”.

## 1) Threat model & deployment assumptions

- What is the attacker model: DB compromise, passive eavesdropper, active MITM, malicious server operator?
- Is the goal “password never sent to server”, “DB leak resistance”, “mutual authentication”, and/or “forward secrecy”?
- Is registration protected by a confidential authenticated channel (e.g. TLS)? If registration sends `masking_key`, it must not leak.
- Do you need user/client enumeration resistance? If yes, verify “fake record” behavior and constant-shape responses.

## 2) OPRF correctness (CFRG OPRF / RFC 9497)

- The OPRF suite (group + hash-to-group + encodings) is explicitly specified and matches the RFC/library defaults.
- The client blinding uses a uniformly random non-zero scalar; it is never reused.
- The server OPRF key is non-zero and stored securely (HSM/KMS if appropriate).
- The implementation validates received OPRF elements (deserialization and subgroup checks) and aborts on failure.
- The Finalize step domain-separates correctly (includes input length and unblinded element, plus “Finalize” label).

## 3) Password hardening (KSF / stretching)

- A memory-hard KSF is used (Argon2id recommended in most settings) with documented parameters.
- Parameters differ by platform constraints (mobile vs desktop vs backend), and are benchmarked.
- The KSF output is combined and extracted into `randomized_password` with clear labels (no key/label reuse).
- The system supports parameter upgrades (versioning) without breaking logins.

## 4) Envelope Store/Recover (key recovery)

- Envelope fields and sizes match the spec (`nonce`, `auth_tag`).
- `Store` derives:
  - `masking_key = Expand(randomized_password, "MaskingKey")`
  - `auth_key = Expand(randomized_password, nonce || "AuthKey")`
  - `export_key = Expand(randomized_password, nonce || "ExportKey")`
  - `seed = Expand(randomized_password, nonce || "PrivateKey")`
- The client keypair derivation from `seed` is deterministic and rejects invalid/zero scalars.
- The envelope MAC covers exactly what it should (nonce + cleartext credentials), and uses constant-time compare.
- `Recover` fails closed and clears intermediate secrets (where the language/runtime allows).

## 5) Credential response masking (enumeration defense)

- Server uses `record.masking_key` to generate a pad and masks `(server_public_key || envelope)` with XOR as specified.
- For missing users (and when enumeration resistance is required), server returns a fake record response with indistinguishable shape and timing.
- The client recomputes `masking_key` from `randomized_password` and unmasks before attempting `Recover`.
- Error messages do not reveal whether the account exists vs password is wrong.

## 6) AKE wiring (3DH or other AKE)

- The AKE is explicitly stated: 3DH as in RFC 9807, or another well-analyzed AKE.
- The transcript/preamble includes:
  - context/version/config
  - identities
  - `KE1`, `CredentialResponse`
  - nonces + keyshares
- DH computations match the chosen AKE exactly (role/order matters).
- Key derivation uses a KDF with domain separation and correct labels.
- Server MAC and client MAC are verified exactly as specified; all comparisons are constant-time.
- The implementation never releases `session_key` or `export_key` before successful authentication.

## 7) Validation & side channels

- All group elements are validated (range + subgroup membership checks).
- Nonce/seed generation uses a CSPRNG and never repeats.
- Timing differences are minimized for “user not found” vs “wrong password”.
- Logging does not leak sensitive material (OPRF blinds, DH secrets, derived keys, tags).

## 8) Operational considerations

- Key rotation story is defined for:
  - server OPRF seed/key
  - server static AKE key
- Backward compatibility and migration is defined (old records, parameter upgrades).
- Test vectors and interoperability tests exist and are run in CI.
- Third-party audits exist (or are planned) for production deployments.

