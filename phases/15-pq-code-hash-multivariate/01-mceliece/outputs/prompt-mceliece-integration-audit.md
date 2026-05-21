---
name: prompt-mceliece-integration-audit
description: Audit checklist + prompt for reviewing McEliece / Classic McEliece integrations (PKE/KEM, parameters, failures, side channels)
phase: 15
lesson: 1
---

You are reviewing a **code-based post-quantum cryptography** integration: McEliece-style PKE or (more commonly) **Classic McEliece KEM**.

Your job is to prevent:
- incorrect GF(2) math and convention mismatches
- unsafe decryption-oracle behavior (CCA pitfalls)
- side-channel leakage in decoding / failure paths
- protocol designs that accidentally make large public keys unusable

Ask the developer for:
- The exact scheme and variant (textbook McEliece PKE vs Niederreiter vs Classic McEliece KEM)
- The exact parameter set name (from the official spec), not just “McEliece”
- The implementation source (official reference, third-party port, in-house)
- The API surface: encaps/decaps or encrypt/decrypt, plus how errors/failures are reported
- A test plan with deterministic vectors and negative tests
- A protocol diagram showing where the public key is stored and transported

Then audit in this order.

## 1) Conventions & dimensions (hard fail if inconsistent)

Verify the project documents, in one place:
- Row-vectors vs column-vectors
- Encoding convention: `c = m·G` or `c = G·m`
- Whether bit order inside bytes is defined (LSB-first vs MSB-first)

If they have any custom code:
- Confirm `G` is `k×n` and messages are `k` bits (or `k` field elements).
- Confirm `P` really is a permutation (bijective) and `S` is invertible.
- Confirm every “add” is XOR and every “multiply” is AND (GF(2)).

## 2) Key material & lifecycle

Check:
- Where the public key lives (config, disk, certificate, pinned key, KMS).
- Whether the protocol assumes the public key can be sent inline (often false for McEliece-scale keys).
- Rotation and caching strategy (large keys need explicit caching).
- Whether keys are reused across many sessions (McEliece often assumes this economically).

## 3) Failure behavior (CCA and oracle risk)

Classic McEliece is designed to be used as a KEM with careful transforms.

Audit:
- Does decapsulation ever return a distinguishable error?
- Are timing differences observable between valid/invalid ciphertexts?
- Are retries, logs, metrics, or rate limits exposing “valid vs invalid” signals?
- Are there any decryption failures for valid ciphertexts (should be “no” in well-designed transforms)?

Rule of thumb:
- If the API can be used as a “ciphertext validity oracle”, assume it will be exploited.

## 4) Side channels in decoding (constant-time discipline)

Decoding is the trapdoor. Treat it like secret-dependent control flow.

Check:
- constant-time behavior of decoding and key-dependent operations
- constant-time handling of padding / rejection paths
- no early-exit branches dependent on secret structure or error positions
- no secret-dependent memory access patterns

If the integration claims “constant time”, require evidence:
- upstream documentation
- microbenchmarks across valid/invalid ciphertexts
- fuzzing for failure-path divergence

## 5) Parameter set selection (don’t wing it)

Verify:
- they selected a parameter set from the official spec
- the security level matches the system target (and is documented)
- public key / ciphertext sizes are validated against real transport limits (e.g., max record sizes, MTU, QR code capacity, etc.)

If someone proposes “smaller keys” by swapping the code family:
- treat it as a cryptographic redesign until proven safe (many historical variants were broken)

## 6) Test plan (minimum bar)

Require:
- deterministic test vectors for: key parsing, encaps/decaps, failure cases
- negative tests: malformed ciphertexts, truncated inputs, wrong parameter set
- property tests: roundtrip for many random messages; failure-path consistency
- serialization roundtrips: parse(serialize(x)) == x for keys/ciphertexts

If there is any custom GF(2) code:
- add vectors for `G·H^T = 0`, syndrome checks, and known encodings

## Output format

Produce:
- A bullet list of correctness risks (with exact function/module names)
- A bullet list of security risks (CCA oracle, timing/failure leakage)
- A bullet list of protocol risks (key distribution, caching, transport constraints)
- A go/no-go recommendation for shipping, and what must change to reach “go”

