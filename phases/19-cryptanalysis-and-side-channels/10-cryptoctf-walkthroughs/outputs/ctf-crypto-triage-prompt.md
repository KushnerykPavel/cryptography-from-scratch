---
name: Crypto CTF Triage Prompt
description: A copy-pastable prompt/checklist for quickly triaging crypto challenges and artifacts.
phase: 19-cryptanalysis-and-side-channels
lesson: 10-cryptoctf-walkthroughs
---

# Crypto CTF Triage Prompt

Paste this into your notes or into an assistant when starting a crypto challenge.

## Inputs

- What artifacts do I have? (ciphertext, key, parameters, code, hints)
- What format are they in? (hex/base64/bytes/integers)
- What is the goal? (plaintext, key, flag, forgery)

## Fast checks (do these first)

1) **Encoding layers**
- Is it hex? base64? base32? URL-safe base64? gzip?

2) **XOR mistakes**
- single-byte XOR?
- repeating-key XOR?
- known-plaintext XOR?

3) **RSA sanity checks**
- compute gcds across moduli (shared primes)
- check small e + no padding (textbook RSA)
- check if message < N and looks structured

4) **Hash/MAC pitfalls**
- is it `Hash(key||msg)` (length extension risk)?
- is it raw digest used as MAC?

## Escalate only if needed

- Lattices (small roots / HNP)
- padding oracles / side channels
- protocol logic flaws

