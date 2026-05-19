---
name: Signal X3DH + Double Ratchet Review Checklist
description: A practical PR/audit checklist for implementations or designs that claim “Signal-style E2EE”.
phase: 10-protocols
lesson: 04-signal-x3dh-double-ratchet
---

# Signal-style X3DH + Double Ratchet Review Checklist

Use this to review a PR, design doc, or implementation that claims “Signal protocol”, “X3DH”, “Double Ratchet”, “Olm”, or “Signal-like ratcheting”.

## 1) Threat model & scope

- 1:1 or group? (Group protocols are not “just Double Ratchet”.)
- Asynchronous start required? (Bob offline.)
- Device model: single device per user, or multi-device (per-device sessions)?
- Server trust assumptions: key directory, key transparency, key verification UX?
- Does the design aim for forward secrecy (FS) and post-compromise security (PCS)?

## 2) X3DH handshake correctness

- Key types and lifetimes are explicit:
  - `IK` (long-term identity key)
  - `SPK` (medium-term signed prekey)
  - `OPK` (one-time prekeys; optional but important)
  - `EK` (initiator ephemeral)
- The DH computations match the spec:
  - `DH1 = DH(IK_A, SPK_B)`
  - `DH2 = DH(EK_A, IK_B)`
  - `DH3 = DH(EK_A, SPK_B)`
  - `DH4 = DH(EK_A, OPK_B)` (only if OPK is present)
- The KDF is HKDF (or equivalent) with domain separation:
  - a fixed, agreed `salt` policy
  - an application-specific `info` label that is unique for X3DH
- `AD` (associated data) binds identities (and is authenticated by the initial AEAD).
- **Signed prekey authentication is enforced**:
  - `SPK_B` is signed by `IK_B`
  - Alice verifies the signature before using `SPK_B`
  - signature failure aborts the handshake
- Replay/duplication handling is defined (e.g., OPK consumption, EK reuse checks).

## 3) X25519 / ECDH edge cases

- Public key parsing rules are specified and strict.
- Implementations reject or safely handle small-order points:
  - all-zero shared secret checks (or equivalent cofactor-hardening strategy)
- Secrets are not reused across protocol roles without labels.

## 4) Double Ratchet state & transitions

- State variables are clearly defined and persisted safely:
  - `RK`, `DHs`, `DHr`, `CKs`, `CKr`, `Ns`, `Nr`, `PN`, `MKSKIPPED`
- Each message carries a header that includes at least:
  - sender DH ratchet public key
  - `PN` (previous sending chain length)
  - `N` (message number in current sending chain)
- A DH ratchet step triggers on receiving a new DH ratchet public key:
  - root key update with `KDF_RK(RK, DH(DHs, DHr))`
  - receiving chain key initialized from the first root update
  - sender generates a new `DHs` and does a second root update to create `CKs`
- A symmetric ratchet step happens per message:
  - `CK -> (CK', MK)` (one-time `MK`)
  - old keys are deleted as soon as possible

## 5) Out-of-order messages & DoS limits

- The design supports lost/out-of-order delivery using `MKSKIPPED`.
- There is an explicit `MAX_SKIP` (or equivalent) to cap:
  - CPU spent deriving skipped keys
  - memory used to store skipped keys
- Failure modes are defined (what happens when limits are exceeded).

## 6) AEAD usage & transcript binding

- Uses a real AEAD (AES-GCM or ChaCha20-Poly1305) from an audited library.
- Every message uses a unique message key (`MK`) exactly once.
- Associated data includes:
  - identity binding (`AD`)
  - header bytes (or an authenticated encoding of the header)
- Nonce strategy is correct:
  - fixed nonce is only acceptable if the message key is single-use
  - otherwise nonces must be unique (per key)
- Authentication failures are terminal for that ciphertext (no silent fallback).

## 7) Missing-but-important production pieces (call out explicitly)

- Header encryption (sealed sender / metadata protection) is a separate layer.
- Identity verification UX (safety numbers, key transparency, TOFU policy).
- Session management (multiple sessions, session reset, prekey rotation).
- Post-quantum variants (PQXDH, hybrid ratchets) if required.
- Side-channel resistance and secure erasure in the target environment.

## 8) “Red flags” that warrant rejection

- Custom curve / custom DH / custom KDF without a spec + test vectors.
- No signed-prekey verification (“the server is trusted” with no justification).
- No `MAX_SKIP` (unbounded skipped-key storage).
- Reusing message keys, or deriving nonces incorrectly.
- Logging secrets, exporting internal ratchet state, or “debug mode” in production builds.

## Quick decision guide (copy/paste)

- If this is production: do they use `libsignal` or a well-audited equivalent?
- If they implemented it themselves: do they have spec references + test vectors + a serious security review?
- If any “red flag” is present: do not ship.

