---
name: "Winternitz (WOTS+) Audit Checklist"
description: "Copy-paste checklist for reviewing WOTS/WOTS+ code inside XMSS/LMS/SPHINCS+ implementations."
phase: "15-pq-code-hash-multivariate"
lesson: "04-winternitz"
---

# Winternitz (WOTS+) Audit Checklist

Use this when reviewing code that implements Winternitz one-time signatures (WOTS / WOTS+) or uses them inside XMSS, LMS/LM-OTS, SPHINCS+, or any Merkle-style hash-based signature.

## 1) Fast Triage (read this first)

- Is the design **one-time** at the leaf level (one WOTS keypair per signature index)?
- Is there a **clear state model** (index increments, persistence, crash safety)?
- Are parameters (`n`, `w`, `len_1`, `len_2`, `len`) computed exactly as specified by the target standard?
- Is the implementation constant-time *where it needs to be* (at least no secret-dependent branching on private key material)?

If any of these are unclear, stop and ask for a design note before reviewing details.

## 2) Parameters & Encoding

- [ ] `w` is restricted to the allowed set for the target spec (e.g., RFC 8391 uses `w ∈ {4, 16}`).
- [ ] `len_1 = ceil(8n / lg(w))`, `len_2 = floor(lg(len_1 * (w-1)) / lg(w)) + 1`, `len = len_1 + len_2`.
- [ ] The base-`w` conversion matches the spec (bit extraction order, endianness).
- [ ] Digest handling is explicit:
  - [ ] If the spec signs an `n`-byte digest, the code either takes an `n`-byte digest input or clearly hashes/truncates to `n`.
  - [ ] No accidental “double hashing”.

## 3) Checksum (Forgery Resistance)

- [ ] Checksum is implemented and verified, not skipped “for performance”.
- [ ] Checksum digits are derived from `Σ (w-1 - msg_digit[i])`.
- [ ] Any required bit/byte alignment (e.g., shift before `toByte`) is correct for the chosen `(n, w, len_2)`.
- [ ] There are tests that would fail if checksum is removed (tamper/forgery-style tests, not just happy-path).

## 4) Key Derivation & Domain Separation (WOTS+ specific)

- [ ] Private key elements are derived by a PRF/KDF from a secret seed (or generated uniformly at random).
- [ ] Domain separation prevents collisions across:
  - [ ] chain index
  - [ ] hash step index
  - [ ] usage type (OTS vs L-tree vs tree hash) if applicable
- [ ] Address/tweak inputs are included exactly as in the target spec (byte layout, endianness).

Red flag: using plain `H(seed || i)` without a structured address/tweak model in a production implementation.

## 5) Signing & Verification Correctness

- [ ] For each digit `d_i`, signer outputs `sig_i = chain(sk_i, d_i)` (or the exact equivalent per spec).
- [ ] Verifier computes `pk'_i = chain(sig_i, (w-1 - d_i))`.
- [ ] Public key comparison is exact and uses a constant-time compare when applicable.
- [ ] Input validation exists for element lengths and signature/public key sizes.

## 6) One-Time Key Management (the real footgun)

- [ ] There is a persistent, crash-safe mechanism that prevents signing the same index twice.
- [ ] Concurrency is handled (locking / transactional increment).
- [ ] The API makes reuse hard:
  - [ ] no “sign(message, sk_seed)” convenience that can be called twice accidentally
  - [ ] clear separation between “derive leaf key by index” and “sign once”

## 7) Side-Channel & Robustness

- [ ] No secret-dependent branching or memory access based on private key bytes.
- [ ] Hash iteration counts that depend on message digits are acceptable only if they are based on public data (digits derived from the message digest).
- [ ] Avoid variable-time comparisons for secret material.

## 8) Tests & Vectors

- [ ] Deterministic vectors exist and cover:
  - [ ] base-`w` conversion
  - [ ] checksum digits
  - [ ] signature → public key derivation (`pkFromSig`)
  - [ ] tampering rejection
- [ ] Property tests cover edge cases and length rejection.

## Ready-to-paste review prompt (for Claude/ChatGPT)

Paste this into your review tool along with the relevant code:

> You are reviewing a Winternitz one-time signature (WOTS/WOTS+) implementation used inside a hash-based signature scheme. Use the attached checklist to audit: parameter derivation (n,w,len_1,len_2,len), base-w conversion, checksum correctness, chain computation, signature verification (pkFromSig), domain separation/addressing (WOTS+), and one-time key management/state handling. Identify any correctness bugs, spec mismatches, misuse risks (key reuse), missing input validation, and side-channel hazards. Provide concrete fixes and tests to add.

