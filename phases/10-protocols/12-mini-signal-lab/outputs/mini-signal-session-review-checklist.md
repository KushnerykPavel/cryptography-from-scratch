---
name: mini-signal-session-review-checklist
description: A practical checklist for reviewing “Signal-like” session setup + double-ratchet messaging designs (prekeys, identity binding, KDF labels, skipped keys, persistence, replay/DoS).
version: 1.0.0
phase: 10
lesson: 12
tags: [signal, x3dh, double-ratchet, protocols, audit, e2ee, hkdf]
---

Use this as a PR review template or paste it into an LLM to drive a structured review of any “Signal-like” design (prekey bundles + ratchet).

If the design is not using an audited implementation (e.g., `libsignal`), treat it as high-risk.

## 1) Write the security claims (in one paragraph)

- What is protected (message content only? attachments? group metadata?)
- Against whom (passive network attacker, active MitM, compromised server, device compromise)?
- Which properties are claimed:
  - Forward secrecy (from when?)
  - Post-compromise security (how quickly does it heal?)
  - Offline delivery (how?)
  - Out-of-order delivery (how?)

Red flag: claims that don’t mention *identity verification* at all.

## 2) Identity trust model (the MitM question)

- What is the “identity key” for a user/device? (format, curve, rotation rules)
- How does a client learn the correct identity key?
  - QR code scan, in-person safety number, key transparency, verified profile, etc.
  - Or just TOFU (pin-first-key and warn on change)?
- What happens when the identity key changes?
  - Block sends? allow sends with warning? require manual approval?
- Is the identity binding *cryptographically enforced*?
  - Do you authenticate identity info as associated data (AD) on every message?

Red flag: “We trust the server to give the right public key.”

## 3) Prekey bundle lifecycle (offline setup)

- Bundle contents: `IK`, `SPK`, `OPK`s, identifiers for each key, and (if used) signatures.
- `OPK` rules:
  - Are OPKs single-use and deleted on first consumption?
  - Does the server hand out at most one OPK per initiation?
  - What happens when OPKs are exhausted?
- `SPK` rules:
  - Rotation interval (days/weeks)
  - Is the SPK authenticated (signature by IK / certificate / pinned key)?
- Replay/duplication:
  - If an attacker replays an old bundle or old prekey message, what breaks?

Red flag: OPKs that can be reused across multiple initiations.

## 4) Handshake transcript binding (what is authenticated?)

- What bytes are committed to `SK` derivation?
  - DH outputs and their ordering
  - KDF parameters (`salt`, `info` labels) and domain separation
- What is included in AD?
  - At least both parties’ identity keys (or their authenticated identifiers)
  - Version / algorithm identifiers
  - Optional: device ids / session ids
- Is there explicit key confirmation? (both sides know the peer derived the same session)

Red flag: negotiable protocol parameters not authenticated.

## 5) Ratchet state machine correctness

- State variables (write them down explicitly): `RK`, `CKs`, `CKr`, `DHs`, `DHr`, `Ns`, `Nr`, `PN`, `MKSKIPPED`
- When does the DH ratchet advance?
  - On receiving a new DH public key in the header (not on every message)
- Are message keys one-time and promptly erased?

Red flag: reusing the same message key for multiple messages.

## 6) Skipped keys + DoS limits

- Is there a `MAX_SKIP` (or equivalent) bound?
- What is the behavior when `N` jumps far ahead?
  - reject, drop, or request re-init?
- Are skipped keys stored with a bounded cache and eviction policy?

Red flag: unbounded “store all skipped keys forever” logic.

## 7) Replay detection and integrity

- Are headers authenticated as part of the AEAD associated data?
- Is there explicit replay detection?
  - e.g., cache seen `(dh_pub, n)` per session, or use the protocol’s semantics to reject duplicates
- Do you reject on authentication failure (no “best-effort” decrypt)?

Red flag: “decrypt then ignore MAC failure” or “accept duplicates”.

## 8) Persistence and backups (real-world breakage)

- What exactly is stored on disk for each session?
- Is ratchet state updated atomically? (avoid corruption on crash)
- Does restoring a backup roll back ratchet state? If yes:
  - can this cause permanent decryption failure?
  - can it cause key/nonce reuse?

Red flag: restoring state that can cause reuse of a transport key + nonce.

## 9) Test plan (minimum evidence)

- Official primitive vectors (X25519, HKDF, AEAD) or cross-implementation tests
- Deterministic tests for:
  - session setup agreement (both sides derive same `SK` and `AD`)
  - out-of-order delivery (`MKSKIPPED`)
  - tamper rejection (tag mismatch)
  - identity key change behavior
  - replay handling
- Fuzz/negative parsing tests (truncation, malformed headers, oversized messages)

