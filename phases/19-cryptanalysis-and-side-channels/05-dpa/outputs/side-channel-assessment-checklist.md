---
name: Side-Channel Assessment Checklist
description: A checklist for assessing whether an implementation needs timing/power/EM/fault hardening.
phase: 19-cryptanalysis-and-side-channels
lesson: 05-dpa
---

# Side-Channel Assessment Checklist

Use this during design review and implementation review for crypto on real devices.

## 1) Attacker capabilities

- Physical access to the device?
- Proximity for EM measurements?
- Ability to run code on same host (timing/cache)?
- Ability to induce faults (glitching, voltage, laser, rowhammer)?
- Ability to collect many measurements?

## 2) Where secrets influence behavior

- Lookup tables indexed by secret bits
- Secret-dependent branches or loop bounds
- Secret-dependent memory access patterns
- Operations that depend on nonce quality (ECDSA/EdDSA nonces)

## 3) Countermeasures (pick what matches the threat model)

- Constant-time implementations
- Masking (randomize intermediate representations)
- Hiding (reduce SNR: jitter, shuffling, noise) — defense-in-depth
- Hardware features (secure enclaves, dedicated HSMs, tamper resistance)

## 4) Validation

- Unit tests for functional correctness are not enough
- Side-channel testing where possible (even basic differential tests)
- Review library claims: “constant-time” must match your platform and use-case

