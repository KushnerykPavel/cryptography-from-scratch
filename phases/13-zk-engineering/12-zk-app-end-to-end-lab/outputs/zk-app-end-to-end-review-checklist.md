---
name: "ZK App End-to-End Review Checklist"
description: "A practical audit checklist + review prompt for integrating ZK proofs into an application (binding, encoding, replay, verification boundaries)."
phase: "13-zk-engineering"
lesson: "12-zk-app-end-to-end-lab"
---

# ZK App End-to-End Review Checklist

Use this as a PR review checklist for any ZK feature (login, access control, private attestations, on-chain verifiers, etc.). It is intentionally system-level: most ZK failures ship at the boundaries, not in the math.

## 1) Statement and Binding

- What is the *exact statement* the verifier accepts (inputs/public signals)?
- Is the proof bound to:
  - the *user/account* (e.g., pk / identity commitment),
  - the *action* being authorized (endpoint + method + parameters),
  - the *context* (chain id / contract address / domain / app id),
  - the *freshness mechanism* (nonce / session_id / block height / timestamp)?
- Can a captured proof be replayed (same statement + same context)?

## 2) Canonical Encoding and Transcript Hashing

- Is there a single canonical encoding for all transcript fields?
  - fixed-width or length-prefixed (no ambiguous concatenation),
  - explicitly versioned (e.g., `PROTOCOL-V1`),
  - explicitly domain-separated (no cross-protocol reuse).
- Are all parameters that affect meaning included in the transcript hash?
  - group/circuit params, verifying key id, chain/network id, etc.
- Are parser/serializer mismatches possible between:
  - prover vs verifier,
  - off-chain vs on-chain verifier,
  - different language implementations?

## 3) Randomness / Nonces

- Are nonces generated with a CSPRNG in production?
- Is nonce reuse *provably catastrophic* for this proof system?
  - If yes, is there a defense-in-depth guardrail (unique nonce derivation, deterministic nonce via RFC6979-style, hardware RNG health checks, etc.)?
- If the proof system uses a random oracle (Fiat–Shamir), is the hash function and transcript binding consistent everywhere?

## 4) Parameter and Key Validation

- Are public inputs validated (range checks, subgroup checks, field membership)?
- Are verifying keys / circuit ids pinned and versioned?
- Does the verifier reject invalid elements early (before expensive verification)?

## 5) Verification API Boundaries

- Does the verifier return a *minimal* boolean + reason code, not a bag of internal details?
- Is proof verification decoupled from authorization?
  - Verifying a proof should not automatically imply “mint token” without checking policy, rate limits, and session state.

## 6) Replay Protection and State

- Where is replay prevention enforced?
  - server-side session store, nonce registry, nullifiers, on-chain mappings, etc.
- What is the expiry policy and garbage-collection story for used challenges/nullifiers?
- Is the system safe under concurrency (two verifications in parallel)?

## 7) Observability and Incident Response

- What do you log (safely) when verification fails?
  - never log witnesses/secrets,
  - log statement hashes, circuit id, verifier version, failure reason.
- Do you have metrics:
  - verification latency,
  - failure rates by reason,
  - replay attempts,
  - invalid-input rates (potential probing)?

## 8) Threat Model Quick Check

- Adversary can capture network traffic?
- Adversary can replay requests?
- Adversary controls client device?
- Adversary can submit malformed proofs/inputs to DoS verification?
- On-chain: adversary can front-run / sandwich / replay calldata?

## Output format for a review

Return:

- PASS / REVIEW / FAIL
- Highest-risk issue first (one sentence)
- Concrete fixes (what to change in the transcript/state/API)
- Concrete tests to add (positive, negative, replay, malformed inputs)
- Reminder: do not ship educational/from-scratch crypto to production; use audited libraries and proven circuits

