---
name: ZK Setup Audit Checklist
description: A decision + audit checklist for trusted/universal/transparent setup choices in ZK systems.
phase: 11-zero-knowledge-foundations
lesson: 11-universal-vs-trusted-setup
---

# ZK Setup Audit Checklist (Universal vs Trusted vs Transparent)

Use this in design reviews and PR reviews whenever a project claims:
- “no trusted setup”
- “universal setup”
- “Powers of Tau”
- “we verified the ceremony”
- “we can upgrade the circuit safely”

## 1) Name the setup model explicitly
Fill these in (don’t accept “it’s fine” as an answer):

- **Setup secrecy:** `trusted` / `transparent`
- **Reuse:** `circuit-specific` / `universal (bounded)`
- **Trust model (if trusted):** `single-party` / `updatable (multi-party)`
- **Size bound (if universal):** what’s the bound and what does it measure (constraints, degree, k)?

## 2) Threat model the toxic waste
If the setup is trusted, answer:

- What is the toxic waste (e.g., `τ`, and/or other trapdoors)?
- What breaks if it leaks (soundness, simulation soundness, extractability, composability)?
- Who could realistically leak it (ceremony participants, CI logs, build artifacts, browser entropy, HSM misuse)?
- Do you have a plan for *proving* “at least one honest contribution” (if updatable)?

## 3) Ceremony / transcript verification (trusted setups)
Require a concrete, automated verification story:

- What artifacts are you consuming (files, hashes, URLs, versions)?
- Is verification done in CI (yes/no)? If yes, where is it implemented?
- Are contributor signatures / transcript hashes checked against a pinned allowlist?
- Are you verifying you got the *final* artifact, not an intermediate?
- Do you validate subgroup checks / points-on-curve / encoding rules (library-level guarantees count, but name them)?

## 4) Parameter lifecycle and migration
Setup is never “one and done” in real systems.

- Where are parameters stored (repo, release assets, S3, IPFS)? Are hashes pinned?
- How do you version parameters? What constitutes a breaking change?
- What happens when you change the circuit (new constraints, new wiring, new gates)?
- Can old proofs still verify after an upgrade? If yes, how is that guaranteed?
- Do you have a rollback plan?

## 5) Universal setup sizing
Universal setups reduce ceremony frequency, but add bound management risk.

- What happens if you exceed the bound (hard failure, silent unsoundness, emergency ceremony)?
- How did you pick the bound (worst-case + growth over time + safety margin)?
- Are bounds enforced in code (fail loudly) and tested?

## 6) Transparency claims
If the project claims “transparent setup”:

- Which assumption is used instead (hash security, random oracle model, etc.)?
- What is the source of public randomness (transcript hashing, beacon, Fiat–Shamir)?
- Are there any hidden “trusted” steps left (e.g., hidden SRS downloads)?

## 7) Practical decision guide (quick heuristic)
- If you expect **frequent circuit changes** → prefer `universal` or `transparent` to avoid repeated ceremonies.
- If you need **tiny proofs + very fast verification** and can handle ceremony ops → `trusted` may be acceptable, but audit it hard.
- If you want to **avoid toxic waste entirely** → look for `transparent` designs and accept the trade-offs (often larger proofs / different performance).

## 8) PR review prompts (copy/paste)
- “Where in CI do we verify the setup artifacts and pin hashes?”
- “What exactly is the toxic waste, and what breaks if it leaks?”
- “Is this setup universal or circuit-specific? What’s the bound and how is it enforced?”
- “What’s our plan when the circuit changes? How do we migrate safely?”
- “If this is updatable, what evidence do we have that at least one contributor was honest?”

