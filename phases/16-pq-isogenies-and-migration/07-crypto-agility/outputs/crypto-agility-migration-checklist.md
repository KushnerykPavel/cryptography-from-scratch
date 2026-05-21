---
name: "Crypto-Agility Migration Checklist (PQ + Hybrid + Deprecations)"
description: "Paste-ready checklist + prompt to review algorithm IDs, policy, negotiation, telemetry, and safe rollout during post-quantum migration."
phase: "16-pq-isogenies-and-migration"
lesson: "07-crypto-agility"
---

# Crypto-Agility Migration Checklist (PQ + Hybrid + Deprecations)

Use this when reviewing or designing:
- a post-quantum (or hybrid) rollout,
- an algorithm deprecation/removal (e.g., broken candidates),
- negotiation logic changes (TLS or any custom handshake),
- or “crypto config” refactors that touch allowlists/denylists.

This is an engineering checklist. It does not validate cryptographic correctness of primitives.

## 1) Inventory (what exists, where)

Answer with explicit file paths / config keys / protocol fields.

- What algorithm IDs exist in the system? (signature, KEM/key exchange, hash/KDF, AEAD)
- Where are algorithm IDs selected?
  - build-time flags
  - runtime config
  - protocol negotiation messages
  - library default selection
- Where are algorithm IDs persisted?
  - certificates / key blobs
  - databases
  - device firmware / provisioning
  - logs / telemetry schemas

Hard stop:
- Any algorithm ID parsing or selection that “fails open” (unknown/invalid ID becomes allowed).

## 2) Algorithm registry (make IDs an API)

Checklist:
- Stable canonical algorithm IDs (no ad-hoc strings in multiple services).
- Canonicalization rules are shared (case, separators, whitespace).
- Metadata attached to each ID:
  - family (sig / KEM / AEAD / hash)
  - minimum protocol version
  - security level / minimum acceptable parameters
  - deprecation cutoff date (if any)
  - notes (why it exists, compatibility constraints)

Hard stop:
- “Same name, different meaning” across components (split-brain security).

## 3) Policy (capability ≠ allowed)

Checklist:
- Central policy evaluator (even if multiple services enforce it).
- Policy is explicit and testable:
  - allowlist (preferred) or denylist (kill switch) or both
  - minimum security level
  - protocol version gates
  - deprecation cutoffs
  - whether classical fallback is allowed (and under what conditions)
- Policy is enforced on every selection path:
  - defaults
  - negotiated suites
  - fallback paths
  - “legacy mode”

Hard stop:
- Any code path that can negotiate or enable a deprecated/broken algorithm “for compatibility”.

## 4) Negotiation (deterministic + auditable)

Checklist:
- Deterministic selection rule documented in one sentence.
  - Example: `client ∩ server-preference ∩ policy`, pick the first server-preferred suite.
- Unknown suite IDs are rejected.
- Downgrade resistance:
  - no “silent fallback to weaker suite”
  - explicit minimums enforced by policy
  - protocol version binding (prevent old versions from selecting new algorithms)

Hard stop:
- Negotiation depends on unordered sets/maps (nondeterministic picks across runs).

## 5) Telemetry (migration is measured, not assumed)

Checklist:
- Log negotiated algorithm IDs (suite IDs) with:
  - protocol version
  - client type/build (if available)
  - deployment region/environment
- Dashboards show:
  - % of traffic using target suite(s)
  - % of traffic using legacy fallback
  - presence of any deprecated IDs (should be 0)
- Alerts:
  - deprecated ID negotiated
  - legacy fallback exceeds threshold
  - unknown ID encountered

Hard stop:
- “We deployed PQ support” without metrics proving negotiation outcomes.

## 6) Kill switch (emergencies must be boring)

Checklist:
- A fast denylist path that:
  - disables an algorithm ID everywhere
  - does not require a code release
  - propagates quickly (minutes/hours)
- Runbook for “algorithm is broken”:
  - disable negotiation
  - rotate long-lived keys (if relevant)
  - invalidate sessions / caches (if relevant)
  - communicate external impact

Hard stop:
- Deprecation response requires editing code in multiple services under time pressure.

## 7) Tests (make regressions expensive)

Must-have tests:
- Unit tests that given a policy, disallowed IDs cannot be selected.
- Negotiation tests:
  - policy blocks disallowed suites even if both peers support them
  - server preference order is honored within policy constraints
- Config validation tests:
  - unknown IDs rejected
  - deprecated IDs rejected after cutoff date
- “No forbidden algorithms” tests:
  - assert forbidden IDs never appear in negotiated suites or config allowlists

## 8) Rollout plan (safe change over time)

Checklist:
- Feature flag / staged rollout:
  - canary -> small % -> full rollout
  - rollback path tested
- Client compatibility plan:
  - which client versions can speak the target suite?
  - what is the maximum allowed fallback window?
- Sunset plan:
  - deadline to remove legacy fallback
  - deprecation date in policy (not in tribal memory)

Hard stop:
- No explicit sunset date for legacy fallback.

## Paste-Ready Prompt (for an AI reviewer)

You are a security engineer reviewing a crypto-agility change (PQ/hybrid migration, algorithm deprecation, or negotiation refactor).

1) List every algorithm ID used in the codebase/configs with file paths and contexts (sig/KEM/hash/AEAD).
2) Identify where policy is enforced and where selection/negotiation happens. Flag any selection path not gated by policy.
3) Look for downgrade risk:
   - fallback paths
   - unordered selection
   - unknown IDs accepted
   - weak suites still negotiable
4) Verify telemetry exists to measure negotiated suite IDs and that an emergency denylist/kill switch exists.
5) Propose a rollout + sunset plan (feature flags, metrics thresholds, deadlines), and list the minimum tests to prevent regressions.

Output a table:
`Component | Where | Risk | Fix | Test | Owner | ETA`

