---
name: FHE Readiness Checklist
description: A reusable checklist for evaluating whether a use case is a good candidate for Fully Homomorphic Encryption.
phase: 20-capstones
lesson: 04-fhe-inference
---

# FHE Readiness Checklist

Use this before committing to an FHE-based design. FHE is powerful but expensive; most use cases have cheaper alternatives. Work through each section honestly.

## 1) Is FHE actually necessary?

- [ ] The data must remain encrypted at the compute party at all times (not just in transit).
- [ ] Trusted Execution Environments (Intel SGX, AMD SEV) are unavailable or unacceptable (e.g., hardware trust assumptions ruled out by threat model).
- [ ] Secure Multi-Party Computation (MPC) is ruled out because there is only one compute party (not two or more colluding servers).
- [ ] Differential privacy alone is insufficient (you need exact computation, not approximate aggregate statistics).

If none of the above apply, reconsider: FHE adds 100x–10000x compute overhead. A simpler approach is likely better.

## 2) Circuit complexity assessment

- [ ] Identify the depth of the computation (number of sequential multiplications). FHE without bootstrapping supports only shallow circuits (typically depth 10–30).
- [ ] Count the number of distinct ciphertext-ciphertext multiplications. Each one consumes noise budget.
- [ ] Determine if bootstrapping is required. Bootstrapping adds ~seconds per refresh on current hardware.
- [ ] Confirm that the computation can be expressed in the target scheme's arithmetic: integers mod t (BFV/BGV) or approximate reals (CKKS).

## 3) Scheme selection

| Need | Recommended scheme |
|------|--------------------|
| Integer arithmetic, exact result | BFV or BGV |
| Approximate real arithmetic (ML, statistics) | CKKS |
| Boolean / bitwise logic, very low latency | TFHE or FHEW |
| Hybrid (integer + boolean) | CHIMERA / switching |

- [ ] Scheme chosen matches the arithmetic type of the computation.
- [ ] Noise budget analysis completed: worst-case noise after full evaluation < q / (2t).
- [ ] Parameter set (n, q, t) chosen to meet both security (>= 128-bit) and correctness requirements.

## 4) Performance feasibility

- [ ] Estimated FHE runtime is acceptable for the latency SLA (typical: ms for simple ops, minutes for deep nets without bootstrapping).
- [ ] Ciphertext expansion factor (typically 100x–1000x vs plaintext) fits within storage and bandwidth constraints.
- [ ] Hardware acceleration considered: GPU (cuFHE), FPGA, or cloud FHE-as-a-service.
- [ ] Batching / SIMD packing considered: CKKS and BFV can pack thousands of values into one ciphertext — critical for throughput.

## 5) Key management

- [ ] Secret key generation uses a cryptographically secure RNG (not Python's `random`).
- [ ] Key distribution plan defined: who holds the secret key, how is it stored and rotated?
- [ ] If threshold decryption is needed (multiple key holders required to decrypt), a threshold FHE or MPC layer is included.
- [ ] Public key and evaluation keys (relinearization key, Galois keys) have defined lifecycle and revocation path.

## 6) Library and dependency audit

- [ ] Chosen library is actively maintained and has had a public security audit (e.g., SEAL, OpenFHE, Concrete, TFHE-rs).
- [ ] No hand-rolled FHE primitives in production (educational toy schemes like this one are not secure).
- [ ] Parameter selection uses library-provided tools or HOMENC standard parameter sets — not hand-tuned values.
- [ ] Build and supply-chain integrity verified (pinned versions, reproducible builds).

## 7) Correctness testing plan

- [ ] Unit tests cover: encrypt/decrypt roundtrip, each homomorphic operation with known inputs and expected outputs.
- [ ] Noise budget tests: run evaluation at maximum expected input size and confirm decryption is correct.
- [ ] Fuzz / randomised tests: verify correctness over a large sample of random inputs, not just happy-path examples.
- [ ] Cross-check: FHE output matches reference plaintext computation on all test vectors.

## 8) Known limitations to document for users

- [ ] Results are exact (BFV/BGV) or approximate (CKKS) — document the expected precision.
- [ ] Computation is not adaptive: the circuit structure (which operations, in which order) must be fixed before encryption. The server cannot branch on encrypted values.
- [ ] Key size and ciphertext size disclosed to users if they affect protocol design (e.g., TLS record limits).
- [ ] Timing is not constant with respect to plaintext values at the library level — but the plaintext is not observable from timing in practice for correctly implemented schemes.
