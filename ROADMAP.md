# Roadmap

Progress tracking for every phase and lesson.

**Total estimated time: ~300 hours (at your own pace)**

**Legend:** ✅ Complete | 🚧 In Progress | ⬚ Planned

## Phase 0: Setup & Tooling — ⬚ (~9 hours)

| # | Lesson | Status | Est. |
|---|--------|--------|------|
| 01 | Dev Environment — Python, Rust, Node, Crypto Stack | ⬚ | ~75 min |
| 02 | Bytes, Hex, Base64 — Encoding Hygiene | ⬚ | ~45 min |
| 03 | Big Integers in Every Language | ⬚ | ~45 min |
| 04 | Test Vectors — RFC / NIST CAVP Workflow | ⬚ | ~75 min |
| 05 | Constant-Time Thinking & Side-Channel Hygiene | ⬚ | ~75 min |
| 06 | Picking a Crypto Library — When and Why | ⬚ | ~45 min |
| 07 | Threat Modeling Basics | ⬚ | ~75 min |
| 08 | Reproducible Builds & Signed Releases | ⬚ | ~75 min |

## Phase 1: Math Foundations I — Number Theory — ⬚ (~21 hours)

| # | Lesson | Status | Est. |
|---|--------|--------|------|
| 01 | Modular Arithmetic from Scratch | ⬚ | ~75 min |
| 02 | GCD, Bezout, Extended Euclidean Algorithm | ⬚ | ~75 min |
| 03 | Modular Inverse & Fast Exponentiation | ⬚ | ~75 min |
| 04 | Fermat's Little Theorem & Euler's Theorem | ⬚ | ~45 min |
| 05 | Chinese Remainder Theorem | ⬚ | ~75 min |
| 06 | Euler's Totient & Carmichael Function | ⬚ | ~45 min |
| 07 | Quadratic Residues & Tonelli-Shanks | ⬚ | ~75 min |
| 08 | Legendre & Jacobi Symbols | ⬚ | ~45 min |
| 09 | Prime Generation — Trial Division to Sieves | ⬚ | ~75 min |
| 10 | Miller-Rabin Primality Testing | ⬚ | ~75 min |
| 11 | AKS & Provable Primality | ⬚ | ~45 min |
| 12 | Pollard Rho & Pollard p-1 Factoring | ⬚ | ~75 min |
| 13 | Quadratic Sieve — Idea and Implementation | ⬚ | ~75 min |
| 14 | Index Calculus & Discrete Log | ⬚ | ~75 min |
| 15 | Baby-Step Giant-Step & Pollard's Rho for DLP | ⬚ | ~75 min |
| 16 | Smooth Numbers & Hidden Subgroup | ⬚ | ~45 min |
| 17 | Continued Fractions for Cryptanalysis | ⬚ | ~45 min |
| 18 | Number Theory Lab — Build a `numth` Library | ⬚ | ~120 min |

## Phase 2: Math Foundations II — Abstract Algebra — ⬚ (~16 hours)

| # | Lesson | Status | Est. |
|---|--------|--------|------|
| 01 | Groups — Definition, Examples, Order | ⬚ | ~75 min |
| 02 | Cyclic Groups & Generators | ⬚ | ~45 min |
| 03 | Subgroups, Cosets, Lagrange's Theorem | ⬚ | ~75 min |
| 04 | Group Homomorphisms & Isomorphisms | ⬚ | ~45 min |
| 05 | Rings, Ideals, Quotient Rings | ⬚ | ~75 min |
| 06 | Fields and Field Extensions | ⬚ | ~75 min |
| 07 | Finite Fields GF(p) | ⬚ | ~75 min |
| 08 | Finite Fields GF(2^n) — Binary Polynomial Math | ⬚ | ~75 min |
| 09 | Polynomial Rings — Add, Mul, Mod, Division | ⬚ | ~75 min |
| 10 | Irreducible Polynomials & Field Construction | ⬚ | ~75 min |
| 11 | Roots of Unity & Cyclotomic Polynomials | ⬚ | ~75 min |
| 12 | NTT — Number Theoretic Transform | ⬚ | ~75 min |
| 13 | FFT for Polynomial Multiplication | ⬚ | ~75 min |
| 14 | Algebra Lab — Build a Finite Field Library | ⬚ | ~120 min |

## Phase 3: Math Foundations III — Elliptic Curves — ⬚ (~13 hours)

| # | Lesson | Status | Est. |
|---|--------|--------|------|
| 01 | Why Elliptic Curves — Group Law in Pictures | ⬚ | ~45 min |
| 02 | Weierstrass Form & Point Addition | ⬚ | ~75 min |
| 03 | Scalar Multiplication — Double-and-Add, NAF, wNAF | ⬚ | ~75 min |
| 04 | Montgomery Ladder & Constant-Time Scalar Mul | ⬚ | ~75 min |
| 05 | Edwards & Twisted Edwards Curves | ⬚ | ~75 min |
| 06 | Montgomery Curves — Curve25519 Construction | ⬚ | ~75 min |
| 07 | secp256k1 — Bitcoin's Curve | ⬚ | ~75 min |
| 08 | NIST P-256 — Pitfalls and Backdoors | ⬚ | ~45 min |
| 09 | Pairings — Weil & Tate from Scratch | ⬚ | ~75 min |
| 10 | BLS12-381 & BN254 — Pairing-Friendly Curves | ⬚ | ~75 min |
| 11 | Hashing to Curves — RFC 9380 | ⬚ | ~75 min |
| 12 | Curve Lab — Build an EC Arithmetic Library | ⬚ | ~120 min |

## Phase 4: Math Foundations IV — Lattices — ⬚ (~14 hours)

| # | Lesson | Status | Est. |
|---|--------|--------|------|
| 01 | What Is a Lattice — Geometry of Z^n | ⬚ | ~45 min |
| 02 | Bases, Determinant, Successive Minima | ⬚ | ~75 min |
| 03 | SVP and CVP — The Hard Problems | ⬚ | ~75 min |
| 04 | Gauss / Lagrange Reduction in 2D | ⬚ | ~75 min |
| 05 | LLL Algorithm from Scratch | ⬚ | ~120 min |
| 06 | BKZ — Block Korkine-Zolotarev | ⬚ | ~75 min |
| 07 | Babai's Nearest Plane Algorithm | ⬚ | ~75 min |
| 08 | Discrete Gaussian Sampling | ⬚ | ~75 min |
| 09 | LWE — Learning With Errors | ⬚ | ~75 min |
| 10 | Ring-LWE & Module-LWE | ⬚ | ~75 min |
| 11 | NTRU Lattices | ⬚ | ~75 min |
| 12 | Lattice Lab — Break a Toy RSA with Coppersmith | ⬚ | ~120 min |

## Phase 5: Math Foundations V — Probability & Information — ⬚ (~10 hours)

| # | Lesson | Status | Est. |
|---|--------|--------|------|
| 01 | Probability Basics for Cryptographers | ⬚ | ~45 min |
| 02 | Statistical Distance & Total Variation | ⬚ | ~75 min |
| 03 | Min-Entropy, Shannon Entropy, Renyi Entropy | ⬚ | ~75 min |
| 04 | Computational Indistinguishability | ⬚ | ~75 min |
| 05 | The Hybrid Argument | ⬚ | ~75 min |
| 06 | Negligible Functions & Reductions | ⬚ | ~45 min |
| 07 | Random Oracle Model — Heuristic vs Reality | ⬚ | ~75 min |
| 08 | The Simulator — How Security Proofs Work | ⬚ | ~75 min |
| 09 | Pseudorandomness — PRG, PRF, PRP | ⬚ | ~75 min |
| 10 | Birthday Bound & Generic Attacks | ⬚ | ~45 min |

## Phase 6: Math Foundations VI — Coding Theory — ⬚ (~7 hours)

| # | Lesson | Status | Est. |
|---|--------|--------|------|
| 01 | Linear Codes — Generator & Parity-Check Matrices | ⬚ | ~75 min |
| 02 | Hamming Distance & Minimum Distance | ⬚ | ~45 min |
| 03 | Hamming Codes from Scratch | ⬚ | ~45 min |
| 04 | Reed-Solomon Codes | ⬚ | ~75 min |
| 05 | Reed-Muller Codes | ⬚ | ~45 min |
| 06 | Goppa Codes — McEliece's Foundation | ⬚ | ~75 min |
| 07 | Syndrome Decoding & NP-Hardness | ⬚ | ~75 min |
| 08 | Coding Lab — Build a Reed-Solomon Encoder | ⬚ | ~75 min |

## Phase 7: Symmetric Cryptography — ⬚ (~16 hours)

| # | Lesson | Status | Est. |
|---|--------|--------|------|
| 01 | One-Time Pad & Information-Theoretic Security | ⬚ | ~45 min |
| 02 | Stream Ciphers — RC4, ChaCha20 from Scratch | ⬚ | ~75 min |
| 03 | Block Ciphers — Feistel Networks | ⬚ | ~75 min |
| 04 | DES & 3DES — History and Why They Died | ⬚ | ~45 min |
| 05 | AES from Scratch — SubBytes, ShiftRows, MixColumns | ⬚ | ~120 min |
| 06 | Block Cipher Modes — ECB, CBC, CTR, CFB | ⬚ | ~75 min |
| 07 | Authenticated Encryption — GCM, CCM, OCB | ⬚ | ~75 min |
| 08 | ChaCha20-Poly1305 from Scratch | ⬚ | ~75 min |
| 09 | Hash Functions — Merkle-Damgard, SHA-256 | ⬚ | ~75 min |
| 10 | SHA-3 / Keccak from Scratch | ⬚ | ~75 min |
| 11 | BLAKE2 & BLAKE3 | ⬚ | ~45 min |
| 12 | HMAC — Build, Attack, Defend | ⬚ | ~45 min |
| 13 | KDFs — HKDF, PBKDF2, Argon2, scrypt | ⬚ | ~75 min |
| 14 | Symmetric Lab — Build a Mini libsodium | ⬚ | ~120 min |

## Phase 8: Classical Asymmetric Cryptography — ⬚ (~16 hours)

| # | Lesson | Status | Est. |
|---|--------|--------|------|
| 01 | RSA from Scratch — KeyGen, Encrypt, Decrypt | ⬚ | ~75 min |
| 02 | RSA Padding — PKCS#1 v1.5, OAEP, PSS | ⬚ | ~75 min |
| 03 | Attacking Textbook RSA — Common Modulus, Hastad, Wiener | ⬚ | ~120 min |
| 04 | Diffie-Hellman & Discrete Log | ⬚ | ~75 min |
| 05 | ElGamal Encryption | ⬚ | ~45 min |
| 06 | DSA & ECDSA from Scratch | ⬚ | ~75 min |
| 07 | Attacking ECDSA — Reused Nonces, Bias, Lattice Recovery | ⬚ | ~75 min |
| 08 | Schnorr Signatures | ⬚ | ~75 min |
| 09 | Ed25519 from Scratch | ⬚ | ~75 min |
| 10 | X25519 ECDH | ⬚ | ~75 min |
| 11 | BLS Signatures & Aggregation | ⬚ | ~75 min |
| 12 | Deterministic Nonces — RFC 6979 | ⬚ | ~45 min |
| 13 | Key Encapsulation vs Key Agreement | ⬚ | ~45 min |
| 14 | Asymmetric Lab — Build a Mini Signing Service | ⬚ | ~120 min |

## Phase 9: Hashes, Commitments, Accumulators — ⬚ (~9 hours)

| # | Lesson | Status | Est. |
|---|--------|--------|------|
| 01 | Hash-Based Commitments | ⬚ | ~45 min |
| 02 | Pedersen Commitments | ⬚ | ~75 min |
| 03 | Vector Commitments | ⬚ | ~75 min |
| 04 | Merkle Trees from Scratch | ⬚ | ~75 min |
| 05 | Sparse Merkle Trees & Verkle Trees | ⬚ | ~75 min |
| 06 | KZG / Polynomial Commitments | ⬚ | ~120 min |
| 07 | Poseidon — ZK-Friendly Hash | ⬚ | ~75 min |
| 08 | RSA & Class Group Accumulators | ⬚ | ~75 min |

## Phase 10: Protocols — ⬚ (~14 hours)

| # | Lesson | Status | Est. |
|---|--------|--------|------|
| 01 | TLS 1.3 — Handshake Walkthrough | ⬚ | ~120 min |
| 02 | TLS 1.3 — Implement the Handshake from Scratch | ⬚ | ~120 min |
| 03 | Noise Protocol Framework | ⬚ | ~75 min |
| 04 | Signal Protocol — X3DH & Double Ratchet | ⬚ | ~120 min |
| 05 | OPAQUE — Asymmetric PAKE | ⬚ | ~75 min |
| 06 | SRP — Secure Remote Password | ⬚ | ~45 min |
| 07 | Threshold Signatures — FROST | ⬚ | ~120 min |
| 08 | Threshold Encryption | ⬚ | ~75 min |
| 09 | Tor & Onion Routing | ⬚ | ~75 min |
| 10 | Mix Networks | ⬚ | ~45 min |
| 11 | OPRFs & VOPRFs | ⬚ | ~75 min |
| 12 | Protocol Lab — Build a Mini Signal | ⬚ | ~120 min |

## Phase 11: Zero-Knowledge Foundations — ⬚ (~13 hours)

| # | Lesson | Status | Est. |
|---|--------|--------|------|
| 01 | What ZK Means — Completeness, Soundness, ZK | ⬚ | ~75 min |
| 02 | Sigma Protocols from Scratch | ⬚ | ~75 min |
| 03 | Schnorr ID Protocol & Proof of Knowledge | ⬚ | ~75 min |
| 04 | Fiat-Shamir Heuristic | ⬚ | ~75 min |
| 05 | Chaum-Pedersen Equality of Discrete Logs | ⬚ | ~75 min |
| 06 | OR Proofs & AND Proofs | ⬚ | ~75 min |
| 07 | Range Proofs — From Naive to Bulletproofs | ⬚ | ~120 min |
| 08 | Bulletproofs from Scratch | ⬚ | ~120 min |
| 09 | Inner Product Argument | ⬚ | ~75 min |
| 10 | Knowledge Soundness — Extractors | ⬚ | ~75 min |
| 11 | Universal vs Trusted Setup | ⬚ | ~45 min |
| 12 | ZK Foundations Lab — Build a Σ-Protocol Library | ⬚ | ~120 min |

## Phase 12: ZK Proof Systems — ⬚ (~22 hours)

| # | Lesson | Status | Est. |
|---|--------|--------|------|
| 01 | Arithmetic Circuits — The Universal Computer | ⬚ | ~75 min |
| 02 | R1CS — Rank-1 Constraint Systems | ⬚ | ~75 min |
| 03 | QAP — Quadratic Arithmetic Programs | ⬚ | ~120 min |
| 04 | Pinocchio Protocol | ⬚ | ~75 min |
| 05 | Groth16 from Scratch | ⬚ | ~120 min |
| 06 | PLONK — Universal SNARKs | ⬚ | ~120 min |
| 07 | PLONK from Scratch | ⬚ | ~120 min |
| 08 | Lookup Arguments — Plookup, Halo2 Lookups | ⬚ | ~75 min |
| 09 | PLONKish Arithmetization | ⬚ | ~75 min |
| 10 | Halo2 — IPA-Based PLONKish | ⬚ | ~120 min |
| 11 | STARKs from Scratch — AIR & Trace | ⬚ | ~120 min |
| 12 | FRI — Fast Reed-Solomon IOP | ⬚ | ~120 min |
| 13 | DEEP-FRI & Recent Improvements | ⬚ | ~75 min |
| 14 | Recursive Proofs | ⬚ | ~75 min |
| 15 | Folding Schemes — Nova, SuperNova, HyperNova | ⬚ | ~120 min |
| 16 | ZK Proof Systems Lab — Compare Groth16 vs PLONK vs STARK | ⬚ | ~120 min |

## Phase 13: ZK Engineering — ⬚ (~13 hours)

| # | Lesson | Status | Est. |
|---|--------|--------|------|
| 01 | Writing Circom Circuits | ⬚ | ~75 min |
| 02 | snarkjs — Trusted Setup, Prove, Verify | ⬚ | ~75 min |
| 03 | Halo2 in Rust — A Working Circuit | ⬚ | ~120 min |
| 04 | arkworks — Multi-Backend Proving | ⬚ | ~75 min |
| 05 | Noir — Aztec's ZK Language | ⬚ | ~75 min |
| 06 | zkVMs — RISC0 from User to Internals | ⬚ | ~120 min |
| 07 | SP1 & Jolt — STARK-Based zkVMs | ⬚ | ~75 min |
| 08 | On-Chain Verifiers — Solidity Verifier Generation | ⬚ | ~75 min |
| 09 | Proof Aggregation & Recursion in Practice | ⬚ | ~75 min |
| 10 | ZK Privacy — Tornado-Style Mixers | ⬚ | ~75 min |
| 11 | ZK Identity — Semaphore | ⬚ | ~75 min |
| 12 | ZK Engineering Lab — Build a ZK App End to End | ⬚ | ~120 min |

## Phase 14: Post-Quantum I — Lattice-Based — ⬚ (~16 hours)

| # | Lesson | Status | Est. |
|---|--------|--------|------|
| 01 | Why Quantum Breaks Classical Crypto | ⬚ | ~75 min |
| 02 | Shor's Algorithm — Walkthrough | ⬚ | ~75 min |
| 03 | Grover's Algorithm & Symmetric Impact | ⬚ | ~45 min |
| 04 | Regev Encryption from Scratch | ⬚ | ~120 min |
| 05 | Dual Regev & Trapdoors | ⬚ | ~75 min |
| 06 | Kyber / ML-KEM from Scratch | ⬚ | ~120 min |
| 07 | Kyber Internals — NTT & Compression | ⬚ | ~75 min |
| 08 | Dilithium / ML-DSA from Scratch | ⬚ | ~120 min |
| 09 | Falcon — NTRU + GPV Sampling | ⬚ | ~120 min |
| 10 | NTRU Encryption & NTRU Prime | ⬚ | ~75 min |
| 11 | FrodoKEM — LWE Without Rings | ⬚ | ~75 min |
| 12 | NewHope & Saber — Earlier Designs | ⬚ | ~45 min |
| 13 | BIKE & HQC — Code-Based KEMs | ⬚ | ~75 min |
| 14 | Lattice PQC Lab — Build a Mini Kyber | ⬚ | ~120 min |

## Phase 15: Post-Quantum II — Code, Hash, Multivariate — ⬚ (~11 hours)

| # | Lesson | Status | Est. |
|---|--------|--------|------|
| 01 | McEliece — The Original PQ Cryptosystem | ⬚ | ~120 min |
| 02 | Classic McEliece — NIST Round 4 | ⬚ | ~75 min |
| 03 | Lamport One-Time Signatures | ⬚ | ~45 min |
| 04 | Winternitz One-Time Signatures | ⬚ | ~75 min |
| 05 | Merkle Signatures (MSS) from Scratch | ⬚ | ~75 min |
| 06 | XMSS — RFC 8391 | ⬚ | ~75 min |
| 07 | LMS — RFC 8554 | ⬚ | ~45 min |
| 08 | SPHINCS+ from Scratch | ⬚ | ~120 min |
| 09 | Multivariate Cryptography — Rainbow's Death | ⬚ | ~75 min |
| 10 | UOV & MAYO — Modern Multivariate | ⬚ | ~75 min |

## Phase 16: Post-Quantum III — Isogenies & Migration — ⬚ (~9 hours)

| # | Lesson | Status | Est. |
|---|--------|--------|------|
| 01 | Isogenies — Maps Between Elliptic Curves | ⬚ | ~75 min |
| 02 | SIDH & Why It Was Broken | ⬚ | ~75 min |
| 03 | CSIDH from Scratch | ⬚ | ~120 min |
| 04 | SQIsign — Compact Isogeny Signatures | ⬚ | ~75 min |
| 05 | NIST PQC Standards Tour | ⬚ | ~45 min |
| 06 | Hybrid TLS — Classical + PQ | ⬚ | ~75 min |
| 07 | Crypto-Agility — Designing for Migration | ⬚ | ~75 min |
| 08 | Harvest-Now-Decrypt-Later — Threat & Timeline | ⬚ | ~45 min |
| 09 | PQ Migration Lab — Audit a Real Codebase | ⬚ | ~120 min |

## Phase 17: Advanced — FHE & MPC — ⬚ (~14 hours)

| # | Lesson | Status | Est. |
|---|--------|--------|------|
| 01 | What FHE Is — Levels, Schemes, Limits | ⬚ | ~75 min |
| 02 | BGV / BFV from Scratch | ⬚ | ~120 min |
| 03 | CKKS — FHE for Real Numbers | ⬚ | ~120 min |
| 04 | TFHE — Bootstrapping in 0.1s | ⬚ | ~120 min |
| 05 | OpenFHE & SEAL Tour | ⬚ | ~75 min |
| 06 | Garbled Circuits — Yao's Protocol | ⬚ | ~120 min |
| 07 | GMW Protocol | ⬚ | ~75 min |
| 08 | BGW & Information-Theoretic MPC | ⬚ | ~75 min |
| 09 | SPDZ — Active Security with Preprocessing | ⬚ | ~120 min |
| 10 | Beaver Triples & Multiplication Triples | ⬚ | ~45 min |
| 11 | Threshold FHE & Distributed Decryption | ⬚ | ~75 min |
| 12 | Private Set Intersection | ⬚ | ~75 min |

## Phase 18: Applied — Blockchain & Identity — ⬚ (~10 hours)

| # | Lesson | Status | Est. |
|---|--------|--------|------|
| 01 | Bitcoin Crypto Stack — secp256k1, SHA-256, Schnorr | ⬚ | ~75 min |
| 02 | Ethereum Crypto Stack — secp256k1, Keccak, BLS | ⬚ | ~75 min |
| 03 | BLS Aggregation in Eth2 | ⬚ | ~75 min |
| 04 | VRFs — Verifiable Random Functions | ⬚ | ~75 min |
| 05 | VDFs — Verifiable Delay Functions | ⬚ | ~75 min |
| 06 | Anonymous Credentials — BBS+ | ⬚ | ~75 min |
| 07 | W3C Verifiable Credentials & DIDs | ⬚ | ~45 min |
| 08 | ZK Rollups — How a Rollup Actually Verifies | ⬚ | ~75 min |
| 09 | Account Abstraction & ZK Accounts | ⬚ | ~75 min |
| 10 | Threshold Wallets — DKG to Signing | ⬚ | ~120 min |

## Phase 19: Cryptanalysis & Side Channels — ⬚ (~11 hours)

| # | Lesson | Status | Est. |
|---|--------|--------|------|
| 01 | Padding Oracle Attacks — CBC, RSA-OAEP | ⬚ | ~75 min |
| 02 | Bleichenbacher's Million Message Attack | ⬚ | ~75 min |
| 03 | Timing Attacks on RSA & ECDSA | ⬚ | ~75 min |
| 04 | Cache Attacks — Flush+Reload, Prime+Probe | ⬚ | ~75 min |
| 05 | DPA — Differential Power Analysis | ⬚ | ~75 min |
| 06 | Fault Injection & Bellcore Attack | ⬚ | ~75 min |
| 07 | Lattice Attacks on RSA — Coppersmith | ⬚ | ~120 min |
| 08 | Lattice Attacks on ECDSA — HNP | ⬚ | ~75 min |
| 09 | Length Extension & Hash Misuse | ⬚ | ~45 min |
| 10 | CryptoCTF Walkthroughs | ⬚ | ~120 min |

## Phase 20: Capstones — ⬚ (~12 hours)

| # | Lesson | Status | Est. |
|---|--------|--------|------|
| 01 | Build a Mini TLS 1.3 Library | ⬚ | ~120 min |
| 02 | Build a ZK Voting System | ⬚ | ~120 min |
| 03 | Build a PQ-Secure Messenger | ⬚ | ~120 min |
| 04 | Build an FHE Inference Service | ⬚ | ~120 min |
| 05 | Build a Mini ZK Rollup | ⬚ | ~120 min |
| 06 | Build a Threshold Wallet | ⬚ | ~120 min |
