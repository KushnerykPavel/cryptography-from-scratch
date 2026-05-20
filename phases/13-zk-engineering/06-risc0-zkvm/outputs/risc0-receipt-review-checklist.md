---
name: "RISC0 Receipt Review Checklist"
description: "A PR-review checklist for zkVM integrations: pin image_id, constrain journal, avoid nondeterminism, and prevent version skew."
phase: "13-zk-engineering"
lesson: "06-risc0-zkvm"
---

# RISC0 Receipt Review Checklist

Use this checklist in PR reviews and design docs for any zkVM-backed feature.

## 1) What exactly is being proven?

- Is the verifier pinned to a specific guest identity (`image_id`) rather than accepting “any valid receipt”?
- Is the `image_id` computed from the exact shipped guest binary (same build flags, same toolchain, same features)?
- Does CI fail if the guest changes but the pinned `image_id` (or constants derived from it) are not updated?

## 2) What becomes public?

- Is there a written `journal` schema (types, encoding, versioning) with examples?
- Does the guest commit **only** what the host needs (minimal journal)?
- Does the host treat the journal as **untrusted input** (length checks, bounds checks, version tag)?
- Is there a clear statement of what is public input vs private input vs derived output?

## 3) Nondeterminism and reproducibility

- Does the guest avoid clocks, RNG, environment-dependent behavior, and host syscalls that can vary across runs?
- Are any randomness needs handled via explicit inputs (committed to) rather than ambient entropy?
- Are there deterministic tests that run the guest and confirm stable outputs for fixed inputs?

## 4) Host-side verification correctness

- Does the host verify the receipt *before* parsing or acting on the journal?
- Does verification bind to the intended `image_id` (not just “verify() succeeded”)?
- Are failure modes handled safely (no partial state updates before verification completes)?

## 5) Version skew and deployment hygiene

- Is there a single source of truth for the `image_id` used by the verifier (not duplicated across services)?
- Are guest and host releases coordinated (migration plan for `journal` schema changes)?
- Is there telemetry/alerting for “receipt verified but schema parse failed” (often a sign of skew)?

## 6) Security posture (threat model)

- What attacker capability is assumed (malicious prover, compromised client, malicious relayer)?
- What is the consequence of accepting a receipt for the wrong program / wrong version?
- What is the consequence of leaking extra data through the `journal`?

## 7) Tests you should see in the repo

- Golden vectors for `journal` encoding/decoding.
- A negative test that proves a tampered journal is rejected (verification must fail).
- A negative test that proves a receipt for a different `image_id` is rejected.
- A test that proves schema versioning behavior is explicit (old/new versions fail or migrate deterministically).

## “Red flags” that should block a merge

- “We verify the receipt, but we don’t check which guest it’s for.”
- “The guest writes debug logs to the journal.”
- “The host parses the journal before verification.”
- “The guest uses time/randomness without committing it as an input.”
- “We update guest code without updating the pinned `image_id`.”

