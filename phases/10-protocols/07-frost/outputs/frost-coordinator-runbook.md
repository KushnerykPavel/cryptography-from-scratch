---
name: "FROST Coordinator Runbook"
description: "A practical checklist for coordinating two-round threshold Schnorr (FROST) signing safely and debuggably."
phase: "10-protocols"
lesson: "07-frost"
---

# FROST Coordinator Runbook

Use this as a PR-review checklist or an operational runbook when integrating FROST-style threshold Schnorr signing.

This is protocol/process guidance, not production code.

## Preflight (before any signing)

- **Ciphersuite locked**: group, scalar field, serialization, hash functions, and domain separation are fixed and versioned.
- **Identifier rules**:
  - Every participant has a unique non-zero identifier in the scalar field.
  - The identifier set used for a signing session is explicit (no implicit “all known signers”).
- **Threshold rules**:
  - You enforce `NUM_PARTICIPANTS >= MIN_PARTICIPANTS`.
  - You treat `MIN_PARTICIPIPANTS` as policy, not a suggestion.
- **Key material provenance**:
  - You know whether shares came from a trusted dealer or DKG.
  - Participants have a verifiable public key share (or a verification key) to support share validation.

## Session framing (avoid transcript mix-ups)

- **Session id**: derive a unique session identifier from stable inputs, e.g. `sid = H("frost-sid" || group_pk || msg || sorted_participant_ids || salt)`.
- **Transcript object**: store a single structured record:
  - message bytes
  - sorted commitment list
  - computed binding factors (or enough to recompute)
  - group commitment `R`
  - challenge `c`
  - signature shares received
- **No cross-session reuse**: never accept a signature share unless it references the exact transcript (same `msg`, same commitment list).

## Round 1 (collect nonce commitments)

- Require each signer to send exactly:
  - hiding nonce commitment `D_i`
  - binding nonce commitment `E_i`
  - their identifier `i`
- Validate inputs immediately:
  - `i` is in the intended participant set for this session.
  - `D_i` and `E_i` are valid group elements (on-curve / in-subgroup checks in real groups).
- Build `commitment_list`:
  - **Sort by identifier** (ascending) and keep this exact ordering for every subsequent step.
  - Reject duplicates.

## Binding factors + group commitment (critical correctness step)

- Compute per-signer binding factors `ρ_i` from:
  - group public key
  - message
  - encoded (sorted) commitment list
- Coordinator invariants:
  - `ρ_i` depends on the whole commitment list, not just `(D_i, E_i)`.
  - serialization is fixed-length, stable, and test-vector covered.
- Compute effective per-signer commitment share:
  - `R_i = D_i * (E_i ^ ρ_i)`
- Compute group commitment:
  - `R = Π R_i`
- Derive challenge:
  - `c = H(R || group_pk || msg)`

## Round 2 (collect signature shares)

- Send to each signer:
  - the message
  - the full sorted commitment list
  - the group public key
- Receive signature shares `z_i` from each signer.

## Verify shares before aggregating (fault attribution)

- Verify each `z_i` using the protocol’s share-verification equation.
- If any share fails:
  - **Do not aggregate.**
  - Identify the failing signer(s) and fail the signing session.
  - Keep the transcript for debugging/audit.

## Aggregate + final verification

- Aggregate: `z = Σ z_i` and output signature `(R, z)`.
- Verify the aggregate signature with standard Schnorr verification.
- If aggregate verification fails but share verification passed:
  - treat it as a bug in transcript construction (sorting/encoding mismatch) or state mix-up.

## Security hygiene checklist

- **Nonce lifecycle**:
  - nonces are single-use; delete after producing `z_i`.
  - never “retry signing” with the same nonce pair after an error.
- **Logging**:
  - safe to log: identifiers, commitments `(D_i, E_i)`, `R`, `c`, success/failure.
  - do not log: nonce scalars, secret shares, derived secret material.
- **Concurrency**:
  - avoid running multiple sessions with the same participants without unambiguous session ids.
  - never merge commitment lists across sessions.

## Debug checklist (when signatures don’t verify)

- Confirm every party used the exact same:
  - sorted commitment list ordering
  - serialization lengths and endianness
  - domain separation tags
  - message bytes (no implicit encoding changes)
- Recompute:
  - all `ρ_i`
  - every `R_i`
  - group `R`
  - challenge `c`
- Verify each share to pinpoint the first mismatch.

