---
name: "TLS 1.3 key schedule + transcript audit checklist"
description: "A PR review checklist for TLS 1.3 HKDF-Expand-Label, transcript hashing boundaries, and Finished verification."
phase: "10-protocols"
lesson: "02-tls13-implement"
---

# TLS 1.3 key schedule + transcript audit checklist

Use this when reviewing code that implements (or exposes) TLS 1.3 secrets, transcript hashing, or Finished verification (including QUIC stacks that reuse TLS 1.3’s key schedule).

## 1) Inputs and hash choice
- [ ] Is the hash function taken from the negotiated ciphersuite (e.g. `TLS_AES_128_GCM_SHA256` → SHA-256 everywhere in the key schedule)?
- [ ] Are the two entropy sources clearly separated: PSK (optional) and (EC)DHE shared secret `Z`?
- [ ] Is the (EC)DHE shared secret encoded exactly as specified (big-endian, left padded to group size when applicable)?

## 2) HKDF-Extract correctness
- [ ] Is `HKDF-Extract(salt, IKM)` implemented as `HMAC(salt, IKM)` (salt is a key)?
- [ ] If the spec says “salt = 0 (all zero octets)”, does the implementation use `HashLen` zero bytes?
- [ ] Is empty salt handled deliberately (not accidentally treated as “don’t use salt”)?

## 3) HKDF-Expand correctness
- [ ] Is `HKDF-Expand(PRK, info, L)` implemented as iterative HMAC with a 1-byte counter (`T(0)=empty`, `T(i)=HMAC(PRK, T(i-1)||info||i)`)?
- [ ] Does the implementation reject/avoid outputs requiring more than 255 blocks?
- [ ] Does the implementation enforce that PRK is at least `HashLen` bytes?

## 4) `HKDF-Expand-Label` encoding (TLS 1.3)
Confirm the `info` bytes are exactly:

`uint16(L) || uint8(len("tls13 " + label)) || "tls13 " + label || uint8(len(context)) || context`

- [ ] Is the `"tls13 "` prefix present (including the space)?
- [ ] Are lengths encoded correctly (`uint16` big-endian for `L`; `uint8` for label length and context length)?
- [ ] Is the label treated as ASCII bytes (no Unicode/UTF-16 surprises)?
- [ ] Is context exactly the intended byte string (often a transcript hash), not a hex string representation?

## 5) Transcript hashing boundaries
- [ ] Are transcript hashes computed over the exact handshake message bytes (handshake type + 3-byte length + body), in the exact order?
- [ ] Are record headers excluded from the transcript?
- [ ] Are encrypted record bytes excluded from the transcript hash (unless the spec explicitly says otherwise)?
- [ ] Is the boundary for each derived secret correct (i.e., which messages are included at that point)?

## 6) Client/server direction and key separation
- [ ] Are `client_*` and `server_*` traffic secrets never mixed up?
- [ ] Are `"key"` and `"iv"` derived from the correct traffic secret with zero-length context?
- [ ] If key updates exist, do they use the correct update labels/derivations and sequence number handling?

## 7) Finished verification
- [ ] Is `finished_key = HKDF-Expand-Label(traffic_secret, "finished", "", HashLen)`?
- [ ] Is `verify_data = HMAC(finished_key, Transcript-Hash(handshake_messages))`?
- [ ] Are the handshake messages included up to (but not including) the sender’s Finished?
- [ ] Is failure handled as a fatal alert/error (not a recoverable warning)?

## 8) Operational safety checks
- [ ] If the code exports secrets (key log, telemetry, debug), is it gated behind explicit “debug only” controls?
- [ ] Are secrets scrubbed/zeroed in memory where the language/runtime makes that feasible?
- [ ] Are logs protected from accidental production use (redaction, compile-time flags, environment toggles)?

## Quick red flags
- “We compute the transcript hash over the whole TLS record bytes.”
- “HKDF-Expand-Label is just HKDF-Expand with `label` appended.”
- “Empty salt means no salt; we skip Extract.”
- “Client/server traffic secrets are interchangeable; it’s the same keys anyway.”

