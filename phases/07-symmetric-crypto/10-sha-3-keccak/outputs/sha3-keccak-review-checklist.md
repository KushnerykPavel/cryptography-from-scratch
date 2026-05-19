---
name: "SHA-3 / SHAKE / Keccak Review Checklist"
description: "A decision guide + audit checklist for correct SHA-3, SHAKE, and Keccak usage (domain separation, output lengths, and common traps)."
phase: "07-symmetric-crypto"
lesson: "10-sha-3-keccak"
---

# SHA-3 / SHAKE / Keccak — Decision Guide + Review Checklist

## 1) Quick decision guide

Pick the primitive based on what you need:

- Need a **fixed-length hash** (integrity, signatures, IDs)?
  - Use `SHA3-256` (32 bytes) or `SHA3-512` (64 bytes).
- Need **variable-length output** (transcripts, KDF-like expansion, hashing-to-many-bytes)?
  - Use `SHAKE128(out_len)` or `SHAKE256(out_len)` and treat `out_len` as part of the protocol.
- Need a **keyed** function (MAC / PRF / keyed hashing)?
  - Prefer a standardized keyed construction:
    - `HMAC` with SHA-2/SHA-3, or
    - `KMAC` (based on cSHAKE/SHAKE, SP 800-185).
  - Avoid ad-hoc “SHAKE(key || message)” unless you know exactly why it’s safe in your threat model.
- Need “**Keccak-256**” specifically (e.g., Ethereum)?
  - Use **Keccak-256** (not SHA3-256). Verify the library function name carefully.

## 2) Terminology sanity checks (catch the 80% bugs)

- “SHA3-256” is a **standardized** instance with **SHA-3 domain separation + padding**.
- “Keccak-256” is a **different** instance with **different padding/domain separation**.
- “SHAKE” is an **XOF**: you must specify an output length.
- “Hash == KDF == MAC” is false in general. Choose the right construction.

## 3) PR review checklist

### A. Correct function / correct domain
- [ ] Is the code using **SHA3** when the protocol says SHA-3, and **Keccak** when it says Keccak?
- [ ] If multiple uses share the same base primitive (e.g., SHAKE), is there explicit **domain separation** between uses?
  - Example: `SHAKE256(b"proto:v1:transcript|" || transcript, 64)` vs `SHAKE256(b"proto:v1:seed|" || seed, 32)`
- [ ] Are test vectors pinned to a spec/protocol and not “whatever output we got once”?

### B. Output length (XOF hazards)
- [ ] For SHAKE: is `out_len` explicit and constant where it must be?
- [ ] Is `out_len` included in any serialization/protocol transcript where the peer needs to agree on it?
- [ ] If output is truncated, is the truncation length justified (security level)?

### C. Bytes vs strings vs hex
- [ ] Are inputs canonicalized?
  - Strings: explicit `UTF-8` encoding.
  - Structured data: deterministic encoding (avoid “pretty JSON” as input).
- [ ] Are hashes treated as **bytes**, not hex strings, until the final presentation layer?

### D. Keyed usage
- [ ] If the code is doing anything “MAC-like”, is it using a MAC/KMAC/HMAC rather than a plain hash?
- [ ] Are keys long enough and generated from a CSPRNG (not a password)?

### E. Migration / interoperability
- [ ] Is the chosen function available across your target platforms (OpenSSL, mobile, HSM/FIPS mode)?
- [ ] If interop matters: are there golden vectors and cross-implementation tests?

## 4) Red flags (require a careful review)

- “We used `sha3_256` because it sounded modern” (no threat model / no rationale).
- “We used Keccak-256 because it’s the same as SHA3-256” (it isn’t).
- “We used SHAKE but we don’t store `out_len` anywhere” (peers will disagree).
- “We used `hash(key || message)` as a MAC” (usually wrong; use HMAC/KMAC).
- “We hash user passwords with SHA-3” (use Argon2/scrypt/PBKDF2 with proper parameters).

## 5) Minimal test plan

- [ ] Add at least 2–3 spec/protocol vectors (empty, short message, longer message).
- [ ] Cross-check against a second implementation (e.g., Python `hashlib`, OpenSSL, RustCrypto).
- [ ] Include one “encoding” test if strings/structured data are involved (to prevent accidental re-encoding changes).

