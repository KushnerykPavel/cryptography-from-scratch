# Threat Modeling Basics

> Cryptography is an answer. A threat model is the question.

**Type:** Learn
**Languages:** Python (stdlib)
**Prerequisites:** Phase 0 · 02 (encodings), 04 (test vectors), 05 (constant-time thinking), 06 (picking a library)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## The Problem

Two teams build “secure encryption for our app”.

Team A picks a strong cipher, writes a clean `encrypt()` function, ships it, and gets breached anyway because:

- the attacker steals keys from logs
- the attacker replays old ciphertexts (no freshness)
- the attacker flips bits in transit (no integrity)
- the attacker compromises one client device (no forward secrecy / no key rotation plan)
- the attacker uses timing and cache signals (no side-channel hygiene)

Team B starts by writing a one-page threat model: assets, trust boundaries, attackers, and what “secure” means for *this* system. Only then do they choose primitives and protocols. They still use audited libraries — but they choose the *right* ones, and they add the non-crypto controls that make the crypto meaningful.

In cryptography, the most common failure mode is not “AES is broken”. It’s “we used the wrong tool for the actual attacker”.

## The Concept

A threat model is a structured statement of:

1. **Assets.** What must be protected (keys, messages, identities, funds, metadata).
2. **Security goals.** What properties you need (confidentiality, integrity, authenticity, freshness, forward secrecy, non-repudiation, availability).
3. **Trust boundaries.** Where control changes hands (client ↔ server, app ↔ OS, process ↔ network).
4. **Attacker capabilities.** What the adversary can do (eavesdrop, tamper, compromise a device, query a decryption oracle, measure timing).
5. **Assumptions.** What you are *choosing* to trust (device secure enclave exists, server is honest-but-curious, users keep secrets, RNG is good).

Threat modeling is not “list all possible bad things”. It is “name the adversary and pick your guarantees”.

### The three layers you must separate

Most crypto designs fail by mixing these layers:

1. **Primitive security.** “This construction is IND-CPA / IND-CCA secure under assumptions X.”
2. **Implementation security.** “This code is constant-time, uses safe APIs, handles errors correctly, zeroizes, rotates keys.”
3. **System security.** “Keys are not logged, endpoints are hardened, update channel is signed, ops can revoke, users can recover.”

You can lose at any layer. Threat models force you to say which layer you are defending against which attacker.

### Minimal threat model template (one page)

Use this as the default shape. If you cannot fill a cell, your design is not ready.

| Category | Answer |
|---|---|
| System | What are we building? One paragraph. |
| Assets | What are the “crown jewels”? |
| Adversaries | Who attacks? (pick 1–2 primary, 1 secondary) |
| Capabilities | Passive? Active MITM? Compromised client? Compromised server? Side channels? |
| Goals | Confidentiality / integrity / authenticity / freshness / FS / deniability / availability |
| Out of scope | What we explicitly do not defend against (and why) |
| Trust boundaries | Where do keys live? Where does plaintext exist? |
| Key management | Generation, storage, rotation, backup, revocation |
| Operational controls | Logging, rate limits, monitoring, updates, incident response |

### Common attacker profiles (crypto-flavored)

| Attacker | Typical capability | What breaks first if you ignore them |
|---|---|---|
| Passive network observer | reads packets | missing encryption / wrong metadata assumptions |
| Active MITM | tamper / replay | missing authentication (no AEAD / no signatures) |
| Malicious client | chooses inputs | padding oracles, nonce misuse, parsing ambiguity |
| Compromised server | sees ciphertext + some secrets | key separation, key escrow, access control |
| Endpoint compromise | steals local state | key storage, session tokens, recovery flows |
| Side-channel attacker | measures time/cache/power | non-constant-time code, branching on secrets |

## Build It

We’ll build a tiny tool that turns a structured “threat model spec” into a Markdown one-pager. The point is not automation — it’s forcing a consistent shape so you can review models like code.

### Step 1: Define a threat model spec

Create a JSON file (or a Python dict) with the fields you care about:

```json
{
  "system": {
    "name": "Encrypted Notes (toy)",
    "description": "A single-user notes app that syncs to a server."
  },
  "assets": [
    {"name": "note contents", "why": "privacy", "impact": "high"},
    {"name": "encryption keys", "why": "all notes depend on them", "impact": "critical"}
  ],
  "trust_boundaries": [
    {"from": "device", "to": "sync server", "data": "ciphertext + metadata"}
  ],
  "adversaries": [
    {"name": "passive network observer", "capabilities": ["eavesdrop"]},
    {"name": "server compromise", "capabilities": ["read stored ciphertext", "tamper with stored blobs"]}
  ],
  "security_goals": [
    "confidentiality",
    "integrity",
    "replay resistance"
  ],
  "out_of_scope": [
    "device compromise (this toy app assumes the OS is not malware)"
  ],
  "notes": [
    "Use an audited AEAD library; never roll your own."
  ]
}
```

### Step 2: Generate a one-page Markdown threat model

Run:

```bash
python phases/00-setup-and-tooling/07-threat-modeling/code/main.py --example
python phases/00-setup-and-tooling/07-threat-modeling/code/main.py --in threat_model.json
```

This prints a Markdown document you can paste into an issue/PR and review.

## Use It

In real projects, threat modeling is a *process*, not a file:

- Start with a **dataflow diagram** (even ASCII). Mark trust boundaries explicitly.
- Use a checklist like **STRIDE** (Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege) to enumerate threats per boundary.
- Translate threats into **requirements**: AEAD, signatures, key rotation, rate limits, audit logs, secure update channel, hardware-backed keys, etc.
- Keep the threat model close to engineering reality: update it when architecture changes.

Threat models are also how you decide when to stop. “We defend against passive network observers and active MITM, but not compromised endpoints” is a decision you can design to.

## Attack It

Attack the *model*, not the math. Here are the classic threat-model failures in cryptography:

1. **Undefined attacker.** “Secure” without naming capabilities.
2. **Ignored endpoints.** Encrypting the wire while the key sits in logs or localStorage.
3. **Missing freshness.** Encrypting without replay protection (timestamps, nonces, counters).
4. **Key conflation.** Reusing one key for multiple roles (encryption, MAC, KDF, identity).
5. **Oracle leakage.** Returning different error messages/timings that create decryption/signature oracles.
6. **Side-channel denial.** Assuming constant-time is optional “later”.

Pick one system you care about (password login, API tokens, E2EE messaging, encrypted backups) and try to write the adversary in one sentence. If you can’t, you can’t pick crypto yet.

## Ship It

This lesson ships a reusable “threat model one-pager” generator:

- `outputs/skill-crypto-threat-model.md` — a skill/prompt that produces a one-page threat model for a cryptography-heavy system.
- `code/main.py` — a tiny Markdown generator you can run locally or in CI to enforce structure.

## Exercises

1. **Easy:** Write a threat model for “API keys in a mobile app” that explicitly includes a malicious client attacker.
2. **Medium:** Write a threat model for “password-based login” and decide whether your attacker includes offline password guessing.
3. **Hard:** Threat-model an E2EE messaging app. Mark where plaintext exists and what forward secrecy means in your model.

## Key Terms

| Term | What people say | What it actually means |
|---|---|---|
| Threat model | “Security checklist” | A concrete attacker + concrete guarantees |
| Asset | “Sensitive data” | The thing whose compromise matters (keys, identities, funds) |
| Trust boundary | “Network boundary” | Any place control/assumptions change hands |
| Passive attacker | “Eavesdropper” | Can read traffic/storage but cannot modify it |
| Active attacker | “MITM” | Can tamper/replay/forge, not just observe |
| Freshness | “No replay” | The receiver can reject old/replayed messages |
| Key management | “Key storage” | Generation + storage + rotation + revocation + recovery |
| Oracle | “Helpful error” | A response difference that leaks secret-dependent information |

## Test Vectors

This is a non-primitive, workflow lesson. The tests in `tests/vectors.json` validate that the Markdown generator is deterministic and schema-validated.

## Further Reading

- NIST SP 800-30 — Guide for Conducting Risk Assessments
- OWASP Application Security Verification Standard (ASVS)
- Ross Anderson — *Security Engineering* (threat modeling mindset)
