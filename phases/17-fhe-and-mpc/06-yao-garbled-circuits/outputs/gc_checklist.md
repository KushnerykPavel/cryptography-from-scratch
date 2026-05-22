---
name: "Garbled Circuits Architecture Checklist"
description: "A secure design checklist for deploying Yao's Garbled Circuits."
phase: 17
lesson: 6
---

# Garbled Circuits Architecture Checklist

Use this checklist during the design phase of any system implementing Secure Two-Party Computation via Yao's Garbled Circuits.

### 1. Protocol Design
- [ ] **One-Time Execution:** Does the Garbler generate fresh labels for every single execution? (Labels must NEVER be reused across multiple evaluations).
- [ ] **Oblivious Transfer Security:** Are you using a formally verified implementation of Oblivious Transfer (e.g., from EMP-toolkit) rather than rolling your own?
- [ ] **Information Leakage:** Does the protocol ensure that the Evaluator only learns the final output and nothing else?

### 2. Circuit Optimization
- [ ] **Free-XOR:** Does your framework support the Free-XOR optimization? (XOR gates can be evaluated for free without cryptography, drastically reducing communication overhead).
- [ ] **Point-and-Permute:** Are the garbled tables optimized using a select bit, meaning the evaluator decrypts exactly 1 ciphertext instead of 4?
- [ ] **Half-Gates:** Does the system use the half-gates optimization (requiring only 2 ciphertexts per AND gate)?

### 3. Implementation Pitfalls
- [ ] **Randomness:** Is the random number generator cryptographically secure (CSPRNG) and properly seeded?
- [ ] **Constant-Time Cryptography:** Are the underlying symmetric encryption operations (e.g., AES) constant-time to prevent timing side channels?
- [ ] **Network Layer Encryption:** Is the communication channel between Garbler and Evaluator encrypted and authenticated (e.g., TLS) to prevent Man-In-The-Middle tampering of the Garbled Tables?

### 4. Malicious Security (Optional but Recommended)
- [ ] **Malicious vs Semi-Honest:** Does your threat model account for a malicious party trying to send improperly garbled circuits or bad inputs? 
- [ ] **Cut-and-Choose / Authenticated Garbling:** If malicious security is required, have you implemented techniques like Cut-and-Choose or Authenticated Garbling to prove the circuit was constructed correctly?
