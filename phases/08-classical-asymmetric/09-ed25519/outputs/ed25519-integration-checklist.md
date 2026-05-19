---
name: "Ed25519 integration & review checklist"
description: "A practical checklist for safely using Ed25519 keys, signatures, and verification in real systems."
phase: "08-classical-asymmetric"
lesson: "09-ed25519"
---

# Ed25519 integration & review checklist

Use this as a PR review checklist (or paste as a prompt into an AI reviewer) when you see Ed25519 used for authentication, signing, key ownership proofs, DID/VCs, or protocol messages.

## 1) What is Ed25519 being used for?

- What is the signed statement (exact bytes)? Is it unambiguous and versioned?
- Is the signature used for authentication, authorization, non-repudiation, or key rotation? Are those semantics documented?
- Is the message domain-separated (context string / prefix) so the same signature can’t be replayed in a different protocol?

## 2) Message encoding (most real bugs live here)

- Is the message canonicalized before signing (JSON canonicalization, protobuf deterministic encoding, etc.)?
- Are field order, whitespace, and numeric formatting fixed?
- Are length prefixes used when concatenating variable-length fields?
- Is the signed payload exactly what gets verified (no “verify hash of X” while signing “X”)?

## 3) Key handling

- Are private keys generated with a cryptographically secure RNG and stored in a secret manager / HSM / OS keychain?
- Are key formats and encodings explicit (seed vs expanded secret, hex/base64, endianness)?
- Are keys never logged, never put in crash reports, and never sent over the network?
- Is there a rotation story (versioned key ids, expiration, revocation)?

## 4) Signing API choices

- Is the implementation using a well-audited library (libsodium / NaCl, RustCrypto `ed25519-dalek`, Go `crypto/ed25519`, OpenSSL where supported)?
- Is the code using the standard Ed25519 mode (RFC 8032 “Ed25519”), not an ad-hoc variant?
- Is signing deterministic as the library intends (no custom nonce code, no mixing RNG into Ed25519 unless you truly know why)?

## 5) Verification pitfalls

- Does verification reject malformed inputs (wrong lengths, non-canonical encodings) rather than accepting “best effort”?
- Is the signature checked against the exact bytes that were signed (including prefixes / context)?
- Is the public key pinned / authenticated (e.g., via certificate chain, DID method, SSH known_hosts, or an allowlist), rather than “trust any key the client sends”?
- If the protocol allows multiple signature schemes, is there algorithm confusion protection (explicit algorithm id bound to the signed bytes)?

## 6) Protocol-level threats

- Replay: does the signed message include a nonce/challenge, timestamp, or session binding?
- Cross-protocol: could the same signature be reused in a different subsystem (login token vs blockchain tx vs webhook)?
- Downgrade: can an attacker force a weaker scheme (RSA-1024, raw ECDSA without hashing, etc.)?
- Key substitution: can an attacker swap the public key without detection (TOFU without pinning, missing certificate validation)?

## 7) Operational concerns

- Are signature failures observable (metrics) without leaking sensitive data?
- Are rate limits and abuse controls in place (verification is cheap, but not free)?
- Are error messages uniform (avoid oracle behavior that helps attackers)?

## 8) Minimal “good” reference patterns

- Signed statement example: `b"proto=v1\\nkind=login\\nuser=...\\nchallenge=...\\n"`
- Verify only after extracting and validating the exact signed bytes.
- Bind algorithm + key id into the signed bytes.

