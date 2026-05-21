---
name: hybrid-tls-migration-checklist
description: Review checklist + prompt for migrating a service to hybrid (classical + PQ) TLS safely.
version: 1.0.0
phase: 16
lesson: 06
tags: [cryptography, tls, post-quantum, migration, crypto-agility]
---

Use this as (a) a PR review checklist or (b) a design review prompt when adding hybrid (classical + PQ) TLS.

Copy/paste prompt (fill in brackets):

You are reviewing a hybrid TLS migration for [service/system]. The goal is to negotiate classical key exchange + PQ KEM and combine secrets so the connection is secure if at least one assumption holds.

Given the following details:
- TLS endpoints: [client(s)], [server(s)], [proxies/LBs/service mesh]
- Library stack: [OpenSSL/BoringSSL/wolfSSL/rustls/etc], versions, providers/forks
- Negotiation: [which classical groups], [which KEMs], [policy for preference/fallback]
- Deployment plan: [canary %], [metrics], [rollback], [compat matrix]

Perform a security-focused review with the checklist below. Flag anything that could silently downgrade to classical-only or fail open.

Checklist

1) Negotiation and downgrade resistance
- Are the PQ/hybrid identifiers and parameters unambiguously negotiated (no “implicit defaults”)?
- Are negotiated parameters bound into the key schedule (transcript binding) so that different negotiations cannot produce the same traffic keys?
- Is there a policy decision on “hybrid required” vs “hybrid preferred”? Is this decision enforced (not just logged)?

2) Secret combination (“combiner”) correctness
- Is the combiner KDF-based (e.g., HKDF) rather than raw concatenation/XOR used as a key?
- Is the input encoding canonical and unambiguous (fixed lengths or length prefixes)?
- Is the input ordering fixed and consistent across implementations (e.g., `ss_classical || ss_pq`)?
- Is there explicit domain separation (labels/info) so this combiner output cannot be confused with some other KDF output?

3) Error handling (fail closed)
- What happens on PQ decapsulation failure? Is the handshake aborted?
- Are there any code paths that substitute `ss_pq = 0...0`, reuse an old secret, or continue with partial inputs?
- Are errors surfaced to callers/metrics, not swallowed?

4) Observability and telemetry
- Do you log (or export metrics for) negotiated classical group and PQ KEM identifiers?
- Do you measure failure rates specifically for the PQ path (encap/decap failures, handshake failures, alerts)?
- Can you correlate failures by client population / region / endpoint / library version?

5) Compatibility and rollout engineering
- Is there a tested compatibility matrix across: clients, servers, proxies, middleboxes, and TLS termination layers?
- Are there canary/feature-flag controls at the right layer (where TLS is actually terminated)?
- Is rollback safe and immediate (config only, no deploy required)?

6) Key schedule and context binding sanity checks
- Are traffic keys derived from a secret that depends on both components (hybrid) and on the transcript?
- Are exporter keys / session resumption / 0-RTT considerations addressed (if applicable)?
- Are session tickets and resumption bound to the negotiated hybrid mode to prevent resuming a different security level?

Deliverable: findings

Output:
- 3–8 “must fix” issues (downgrade risk, fail-open behavior, ambiguity)
- 3–8 “should fix” issues (observability gaps, rollout gaps, unclear policy)
- A one-paragraph risk summary and a go/no-go recommendation for the canary

