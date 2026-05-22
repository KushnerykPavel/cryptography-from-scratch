---
name: "Private Set Intersection (PSI) Protocol Review Checklist"
description: "A paste-ready checklist for designing/reviewing PSI integrations (ECDH/OPRF/HE-based PSI, leakage, encoding, abuse controls, and deployment pitfalls)."
phase: 17-fhe-and-mpc
lesson: 12-private-set-intersection
---

# Private Set Intersection (PSI) Protocol Review Checklist

Use this when you:
- integrate PSI into a product (anti-abuse, matching, fraud, identity, ads)
- review a PSI PR / vendor / protocol choice
- threat-model what PSI leaks (and how attackers can abuse it)

## 0) Define the goal (in one sentence)
Fill in the blanks:
- “Client learns ___ about `A ∩ B`, server learns ___ about `A`, adversary learns ___ from transcripts.”

Decide explicitly:
- reveal **elements** vs reveal **cardinality only**
- one-shot batch vs repeated queries over time
- who is allowed to query and how often

## 1) Threat model and security level
Checklist:
- [ ] Semi-honest vs malicious security is stated (and matches the deployment threat model).
- [ ] Security parameter is set (e.g., 128-bit) and backed by an analysis, not “seems big”.
- [ ] The protocol’s proven assumptions are listed (DDH, LWE, RO, etc.).

Red flags:
- “We assume clients are honest” in a setting where clients can self-register.
- No mitigation for malicious clients crafting adversarial inputs.

## 2) Leakage and abuse controls
Checklist:
- [ ] Set sizes are considered sensitive; if so, pad or batch to hide sizes.
- [ ] Membership-testing abuse is addressed (rate limits, query budgets, authorization).
- [ ] Repeated-query leakage is considered (linkability across runs, intersection attacks over time).

Red flags:
- Exposing PSI as a public API with no quotas (turns into a membership oracle).

## 3) Input normalization (this breaks systems in practice)
Checklist:
- [ ] Canonicalization rules are fixed and versioned (lowercasing, Unicode NFC, trimming, phone formats).
- [ ] Duplicate handling is defined (set vs multiset).
- [ ] Encoding is unambiguous (bytes vs strings; locale issues).

Red flags:
- “We hash the raw input string as-is” without a canonicalization spec.

## 4) Hashing / mapping into the protocol domain
Checklist:
- [ ] Items are hashed with a domain tag (e.g., `H("PSI:v1" || encode(item))`).
- [ ] If mapping into a group/field, invalid values are rejected (0, identity element, out-of-range).
- [ ] If the input domain is small (emails, phone numbers), add an OPRF/VOPRF or other hardening.

Red flags:
- Deterministic tags without an OPRF when the attacker can enumerate the domain.

## 5) Cryptographic parameters and key management
Checklist:
- [ ] Group/curve parameters come from a standard suite (not a home-grown prime).
- [ ] Keys are rotated with a plan for compatibility (versioned tags / key IDs).
- [ ] Keys are never reused across logically distinct PSI datasets (prevents cross-context linking).

Red flags:
- Reusing the same server key `b` forever (enables long-term linkability of tags).

## 6) “Cardinality-only” modes (Bloom filters, sketches, etc.)
Checklist:
- [ ] False positives are measured and documented (probability and worst-case behavior).
- [ ] Clients understand that “maybe in” is not a proof of membership.
- [ ] The structure is parameterized to the expected `n` and acceptable FP rate.

Red flags:
- Treating Bloom filter matches as ground truth without verification.

## 7) Malicious security and validation
Checklist:
- [ ] Inputs are validated (group membership, non-zero, correct subgroup when applicable).
- [ ] Protocol includes protections against malformed elements (invalid curve attacks, small subgroup).
- [ ] If malicious security is claimed, there are tests that exercise malicious behaviors.

Red flags:
- “ECDH PSI” without subgroup checks on curves where that matters.

## 8) Operational considerations
Checklist:
- [ ] Transcripts and intermediate values are not logged.
- [ ] Observability is privacy-safe (aggregate metrics only).
- [ ] Errors are uniform (no “which input failed?” side channel).

## 9) What to ask a PSI vendor / library
Ask for:
- security model (semi-honest vs malicious), proofs, and assumptions
- leakage statement (what sizes, tags, timing, failures leak)
- performance envelope for your `|A|`, `|B|` (and memory)
- key rotation story and backward-compatibility plan
- reproducible benchmarks and test vectors

