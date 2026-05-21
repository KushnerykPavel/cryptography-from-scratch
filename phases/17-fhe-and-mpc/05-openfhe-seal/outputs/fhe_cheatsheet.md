---
name: FHE Architecture Cheatsheet
description: A quick reference for FHE parameters, keys, and operations using SEAL/OpenFHE paradigms.
phase: 17
lesson: 05
---

# FHE Architecture Cheatsheet

Keep this reference handy when building applications with Microsoft SEAL, OpenFHE, or TenSEAL.

## The Big Three Schemes

- **BGV / BFV:** Exact integer arithmetic. Good for databases, private set intersection, integer statistics.
- **CKKS:** Approximate arithmetic (fixed-point real numbers). Good for machine learning, linear regression, neural networks.
- **TFHE (FHEW):** Fast exact boolean gates and lookup tables with infinite depth (fast bootstrapping).

## Essential Objects

1. **Context (`FHEContext` / `SEALContext`)**: Validates parameters and pre-computes tables. Everything needs a reference to this.
2. **KeyGenerator**: Creates the `SecretKey` and `PublicKey`. Also generates Evaluation Keys.
3. **BatchEncoder / CKKSEncoder**: Bridges standard arrays to `Plaintext` polynomials.
4. **Encryptor**: Takes `Plaintext` + `PublicKey` -> `Ciphertext`.
5. **Evaluator**: Runs `Add`, `Multiply`, `Relinearize`, `Rotate`.
6. **Decryptor**: Takes `Ciphertext` + `SecretKey` -> `Plaintext`.

## The Keys

- **SecretKey**: Used only for decryption. Never leaves the client.
- **PublicKey**: Used for encryption. Can be public.
- **RelinearizationKey (RelinKey)**: A type of evaluation key. Given to the server to reduce the size of ciphertexts after a multiplication.
- **GaloisKey**: A type of evaluation key. Given to the server to perform cyclic rotations on batched arrays (SIMD rotations).

## The Cardinal Rules of FHE Programming

1. **Addition is cheap. Multiplication is expensive.** Both in terms of CPU time and Noise Budget.
2. **Minimize Multiplicative Depth.** Turn sequential operations into tree operations. `(a*b)*(c*d)` has depth 2. `a*(b*(c*d))` has depth 3.
3. **Relinearize after every Multiplication.** Unless you explicitly know you are adding the result immediately and don't care about the size growth.
4. **Batch everything.** A ciphertext operation on 1 number costs exactly the same as an operation on 8,192 numbers. Use SIMD slots to amortize the cost.

## Debugging: Why did my FHE app return garbage?

- **Noise Budget Exhausted**: You did too many multiplications for your chosen `poly_modulus_degree` and `coeff_modulus` chain.
- **Forgot to Relinearize**: Your ciphertext sizes exploded and corrupted the evaluation.
- **Scale Out of Bounds (CKKS)**: You did not match scales before addition, or your scaling factor dropped below precision thresholds.
