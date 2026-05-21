---
name: "HNDL Decision Guide (XYZ + Inventory)"
description: "Paste-ready checklist to assess harvest-now-decrypt-later exposure and prioritize post-quantum / hybrid migration work."
phase: "16-pq-isogenies-and-migration"
lesson: "08-harvest-now-decrypt-later"
---

# HNDL Decision Guide (XYZ + Inventory)

Use this as a PR review checklist, an architecture review template, or a one-page briefing for leadership.

## 1) Define your timeline inputs (XYZ)

Fill these in per system / workflow:

- **X (data security life):** how many years must the data remain confidential?
  - Examples: customer PII (years), trade secrets (5–20+), M&A (years), auth tokens (minutes-hours)
- **Y (migration time):** how many years to fully migrate the workflow (including vendors, certificates, rollout, and rollback)?
  - Include: discovery, design, staging, performance testing, phased rollout, deprecation of old modes
- **Z (years to CRQC):** your estimate of when a cryptographically relevant quantum computer could break today’s RSA/(EC)DH at scale
  - Treat as uncertain. Plan with safety margin, not optimism.

Decision rule:

- If **X + Y > Z** ⇒ treat as **urgent** (you can’t finish before secrets expire).
- If **X − Z > 0** ⇒ there is a **non-zero HNDL exposure window** for ciphertext recorded today.

## 2) Identify what “harvestable ciphertext” exists

For each workflow, answer:

- Is the attacker realistically able to record it today?
  - Internet edge: yes (common).
  - Internal east-west: often yes (taps, compromised hosts, misconfigured observability).
  - Backups/archives: yes if exfiltration is plausible.
- If recorded, would future quantum capability reveal secrets?
  - **In transit:** depends on key establishment (classical vs hybrid/PQ).
  - **At rest:** depends on how DEKs are wrapped and stored (envelope encryption details).
  - **Signing:** not decryption, but future forgery can break trust (supply chain).

## 3) Classify each workflow (simple buckets)

- **Classical key establishment** (Shor-vulnerable): RSA, DH, ECDH/ECDHE, X25519 (classical curve)
- **Hybrid key establishment:** classical + PQ combined (transition strategy)
- **Post-quantum key establishment:** PQ only (end state, when ecosystem supports it)

If you don’t know which bucket a workflow is in, your first task is discovery (inventory).

## 4) Build a “crypto inventory row” per workflow

Minimal fields (copy/paste):

- `name`:
- `kind`: `in_transit` | `at_rest` | `signing`
- `key_establishment_mode`: `classical` | `hybrid` | `pqc`
- `X` (data_security_life_years):
- `Y` (migration_years):
- `blast_radius`: 1 (small) | 2 (medium) | 3 (large)
- `notes`: protocols, endpoints, vendors, cert paths, key storage, failure modes

Tip: start with the top 10 workflows that move or protect your most sensitive data.

## 5) Prioritize: what gets migrated first?

Use these heuristics (ordered):

1) Highest **X** (long-lived secrets) + classical key establishment
2) Highest **blast radius** (a compromise affects many users/systems)
3) Largest **Y** (longer migrations must start earlier)
4) Workflows where “fix later” is impossible (recorded ciphertext can’t be patched)

If you need a numeric score for triage, use the lesson script:

- `python3 code/main.py`

Then mirror the ordering in your tracker.

## 6) PR review checklist (paste into code review)

When reviewing changes to TLS/VPN/SSH/backup/signing:

- Does this change introduce or keep **classical** key establishment for long-lived data?
- If hybrid/PQ is used, is there a **downgrade risk** back to classical-only?
- Is the crypto choice **configurable** (crypto-agility) or hard-coded?
- Are certificates/roots/signing keys part of the story (not just “the cipher suite”)?
- Does telemetry/logging accidentally store sensitive material longer than intended?

## 7) Meeting agenda template (30 minutes)

Goal: decide “what gets migrated first and why”.

1) Agree on a conservative Z assumption (or a range).
2) List top 10 workflows with long-lived secrets.
3) For each: write down X, Y, and key establishment mode.
4) Sort by urgency: X+Y−Z margin, then blast radius.
5) Assign owners for: discovery, vendor roadmap, performance testing, rollout plan.

