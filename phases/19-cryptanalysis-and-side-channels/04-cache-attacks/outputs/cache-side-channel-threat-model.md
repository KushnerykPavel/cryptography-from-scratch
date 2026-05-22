---
name: Cache Side-Channel Threat Model Template
description: A template to reason about cache/timing side channels in shared-hardware environments.
phase: 19-cryptanalysis-and-side-channels
lesson: 04-cache-attacks
---

# Cache Side-Channel Threat Model Template

Use this when evaluating whether a system needs side-channel-hardened cryptography.

## 1) Assets (what must stay secret)

- Keys (symmetric keys, private keys)
- Tokens (API keys, session tokens)
- Sensitive plaintext (decrypted data, metadata)

## 2) Attacker position

- Same process? same user? same machine?
- Same core / CPU package?
- Same VM host (multi-tenant cloud)?
- Remote only (no co-residency)?

## 3) Side-channel surfaces

- Table lookups indexed by secret bits (S-boxes, precomputed windows)
- Secret-dependent branches (if/else on key bits)
- Secret-dependent memory access patterns (arrays, maps, caches)
- Variable-time parsing/verification (early exits)

## 4) Observables

- Direct timing (cycles, wall-clock time)
- Cache state inference (Prime+Probe / Flush+Reload)
- Page faults / branch predictors / microarchitectural state

## 5) Mitigations (choose what fits)

- Constant-time implementations (no secret-dependent branches/memory access)
- Avoid lookup tables for secrets (bitslicing, arithmetic formulations)
- Process isolation / dedicated hardware for high-value keys
- Library choice: prefer implementations with explicit side-channel resistance claims

## 6) Validation

- Micro-benchmarks comparing “different key bits” paths
- Side-channel tooling (where available) and code review checklist

