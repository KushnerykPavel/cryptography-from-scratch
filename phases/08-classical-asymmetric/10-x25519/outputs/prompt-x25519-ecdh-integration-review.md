---
name: "X25519 ECDH Integration Review Prompt"
description: "Paste into an LLM (or use as a checklist) to review an X25519 key-agreement integration for common correctness and security pitfalls."
phase: "08-classical-asymmetric"
lesson: "10-x25519"
---

# X25519 ECDH Integration Review (Prompt + Checklist)

Copy-paste the code snippet(s) that implement X25519 key exchange (and any KDF / handshake transcript code), plus a short description of the protocol context, then ask:

## Prompt

You are reviewing an X25519 (RFC 7748) ECDH integration for correctness, interoperability, and common security failures.

1) Identify exactly where X25519 is used (ephemeral-static? ephemeral-ephemeral?), and whether the exchange is authenticated (signatures, certificates, PSK, or Noise pattern). If it is unauthenticated, call out the MITM risk explicitly.

2) Validate input/output handling:
- Are private scalars generated as 32 random bytes and passed through an X25519 implementation that performs RFC 7748 clamping?
- Are public keys treated as 32-byte *raw u-coordinates* (little-endian), not PEM/DER, not Edwards point encodings?
- Is the most significant bit of the u-coordinate masked on decode (per RFC 7748), and are non-canonical field elements accepted/reduced (mod p)?
- Are serialization formats consistent across languages (endianness, "raw" encodings, no accidental hex/base64 confusion)?

3) Check the "all-zero" shared-secret rule:
- Is there a constant-time-ish all-zero check on the 32-byte shared secret (e.g., OR all bytes) and an abort if it is all-zero?
- Is the error handled safely (no retries that leak timing/data-dependent behavior, no silent fallback)?

4) Check key derivation:
- Is the raw shared secret fed into a KDF (HKDF recommended) to derive encryption/authentication keys?
- Does the KDF bind *context* (protocol name/version, ciphersuite) and *both* public keys (and any transcript hashes) to prevent cross-protocol/key-share attacks?
- Is salt/info chosen deliberately (not empty by accident)? Are multiple keys derived with domain separation labels?

5) Check protocol-level usage:
- Are X25519 keys ephemeral for forward secrecy where expected (TLS 1.3/Noise-style)?
- Are private scalars kept secret and wiped/kept out of logs/metrics?
- Are public keys validated according to the chosen protocol profile (at minimum: all-zero shared secret check; optionally: reject known small-order points if required by your threat model/library guidance)?

6) Call out side-channel and implementation risks:
- If the implementation is custom (not a vetted library), highlight constant-time requirements, clamping, ladder, and big-int timing risks.
- Recommend using a vetted library API and higher-level handshake construction when possible.

## Output format

Return:
- A short "Verdict" (OK / Needs changes / Dangerous)
- A bullet list of concrete findings (what to change, where)
- A "Safe alternative" section recommending a vetted library API (and a high-level protocol construction) if appropriate.

