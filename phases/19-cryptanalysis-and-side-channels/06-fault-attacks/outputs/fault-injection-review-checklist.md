---
name: Fault Injection Review Checklist
description: A checklist for reviewing whether an implementation detects and resists fault injection.
phase: 19-cryptanalysis-and-side-channels
lesson: 06-fault-attacks
---

# Fault Injection Review Checklist

Use this when reviewing crypto on embedded devices, smart cards, secure elements, or HSMs.

## 1) Fault model assumptions

- Can an attacker glitch voltage/clock?
- Can they induce EM/laser faults?
- Can they trigger faults repeatedly and observe outputs?

## 2) High-risk primitives/paths

- RSA-CRT signing/decryption
- ECDSA scalar multiplication and inversion
- Symmetric implementations with complex control flow or tables

## 3) Countermeasures to look for

- Redundant computation + compare (recompute and verify)
- Checksums / invariant checks during CRT recombination
- Detect-and-abort behavior (never return faulty outputs)
- Hardware fault detectors (where applicable)

## 4) Practical verification

- Unit tests that simulate corrupted intermediate values
- Fuzzing to ensure faults don’t leak partial structure
- Logging/telemetry for repeated fault-trigger attempts

