# Your Progress

This file is for manual tracking if you prefer markdown over automation.

For **automated tracking**, run:

- `/find-your-level` — placement quiz, sets entry phase
- `/check-understanding <phase>` — phase quiz, records score
- `/my-progress` — dashboard view

Automation writes to `.progress.json` (git-ignored, personal). The dashboard
parses ROADMAP.md hours so you don't have to maintain numbers by hand.

---

## Manual checklist (optional)

Tick lessons as you complete them. Keep this in a personal fork, not the
public repo — your progress is yours.

### Phase 0 — Setup & Tooling

- [ ] 01 Dev Environment
- [ ] 02 Bytes, Hex, Base64
- [ ] 03 Big Integers
- [ ] 04 Test Vectors
- [ ] 05 Constant-Time Thinking
- [ ] 06 Picking a Crypto Library
- [ ] 07 Threat Modeling
- [ ] 08 Reproducible Builds

### Phase 1 — Number Theory

- [ ] 01 Modular Arithmetic
- [ ] 02 GCD, Bezout, EEA
- [ ] 03 Modular Inverse & Fast Exp
- [ ] 04 Fermat & Euler
- [ ] 05 CRT
- [ ] 06 Totient & Carmichael
- [ ] 07 Quadratic Residues, Tonelli-Shanks
- [ ] 08 Legendre & Jacobi
- [ ] 09 Prime Generation
- [ ] 10 Miller-Rabin
- [ ] 11 AKS
- [ ] 12 Pollard Rho & p-1
- [ ] 13 Quadratic Sieve
- [ ] 14 Index Calculus & DLog
- [ ] 15 BSGS & Rho for DLP
- [ ] 16 Smooth Numbers
- [ ] 17 Continued Fractions
- [ ] 18 numth Library Lab

### Phase 2 — Abstract Algebra

- [ ] 01 Groups
- [ ] 02 Cyclic Groups
- [ ] 03 Subgroups, Cosets, Lagrange
- [ ] 04 Homomorphisms
- [ ] 05 Rings, Ideals, Quotients
- [ ] 06 Fields & Extensions
- [ ] 07 GF(p)
- [ ] 08 GF(2^n)
- [ ] 09 Polynomial Rings
- [ ] 10 Irreducible Polynomials
- [ ] 11 Roots of Unity & Cyclotomics
- [ ] 12 NTT
- [ ] 13 FFT
- [ ] 14 Finite Field Library Lab

### Phase 3 — Elliptic Curves

- [ ] 01 Why Elliptic Curves
- [ ] 02 Weierstrass & Point Addition
- [ ] 03 Scalar Multiplication
- [ ] 04 Montgomery Ladder
- [ ] 05 Edwards Curves
- [ ] 06 Montgomery / Curve25519
- [ ] 07 secp256k1
- [ ] 08 NIST P-256
- [ ] 09 Pairings
- [ ] 10 BLS12-381 & BN254
- [ ] 11 Hash-to-Curve
- [ ] 12 EC Arithmetic Lab

### Phase 4 — Lattices

- [ ] 01 What Is a Lattice
- [ ] 02 Bases, Determinant, Minima
- [ ] 03 SVP & CVP
- [ ] 04 Gauss/Lagrange 2D
- [ ] 05 LLL
- [ ] 06 BKZ
- [ ] 07 Babai
- [ ] 08 Gaussian Sampling
- [ ] 09 LWE
- [ ] 10 RLWE & MLWE
- [ ] 11 NTRU Lattices
- [ ] 12 Coppersmith Lab

### Phase 5 — Probability & Information

- [ ] 01 Probability Basics
- [ ] 02 Statistical Distance
- [ ] 03 Entropies
- [ ] 04 Computational Indistinguishability
- [ ] 05 Hybrid Argument
- [ ] 06 Negligible & Reductions
- [ ] 07 Random Oracle Model
- [ ] 08 The Simulator
- [ ] 09 PRG, PRF, PRP
- [ ] 10 Birthday Bound

### Phase 6 — Coding Theory

- [ ] 01 Linear Codes
- [ ] 02 Hamming Distance
- [ ] 03 Hamming Codes
- [ ] 04 Reed-Solomon
- [ ] 05 Reed-Muller
- [ ] 06 Goppa Codes
- [ ] 07 Syndrome Decoding
- [ ] 08 RS Encoder Lab

### Phase 7 — Symmetric Crypto

- [ ] 01 One-Time Pad
- [ ] 02 Stream Ciphers
- [ ] 03 Feistel
- [ ] 04 DES & 3DES
- [ ] 05 AES
- [ ] 06 Block Cipher Modes
- [ ] 07 AEAD
- [ ] 08 ChaCha20-Poly1305
- [ ] 09 SHA-256
- [ ] 10 SHA-3 / Keccak
- [ ] 11 BLAKE2 & BLAKE3
- [ ] 12 HMAC
- [ ] 13 KDFs
- [ ] 14 Mini libsodium Lab

### Phase 8 — Classical Asymmetric

- [ ] 01 RSA
- [ ] 02 RSA Padding
- [ ] 03 RSA Attacks
- [ ] 04 Diffie-Hellman
- [ ] 05 ElGamal
- [ ] 06 DSA & ECDSA
- [ ] 07 ECDSA Attacks
- [ ] 08 Schnorr
- [ ] 09 Ed25519
- [ ] 10 X25519
- [ ] 11 BLS Signatures
- [ ] 12 Deterministic Nonces
- [ ] 13 KEM vs Key Agreement
- [ ] 14 Mini Signing Service Lab

### Phase 9 — Hashes, Commitments, Accumulators

- [ ] 01 Hash Commitments
- [ ] 02 Pedersen
- [ ] 03 Vector Commitments
- [ ] 04 Merkle Trees
- [ ] 05 Sparse Merkle & Verkle
- [ ] 06 KZG
- [ ] 07 Poseidon
- [ ] 08 RSA & Class Group Accumulators

### Phase 10 — Protocols

- [ ] 01 TLS 1.3 Walkthrough
- [ ] 02 TLS 1.3 Implementation
- [ ] 03 Noise Framework
- [ ] 04 Signal X3DH + Double Ratchet
- [ ] 05 OPAQUE
- [ ] 06 SRP
- [ ] 07 FROST
- [ ] 08 Threshold Encryption
- [ ] 09 Tor & Onion Routing
- [ ] 10 Mix Networks
- [ ] 11 OPRFs & VOPRFs
- [ ] 12 Mini Signal Lab

### Phase 11 — Zero-Knowledge Foundations

- [ ] 01 What ZK Means
- [ ] 02 Sigma Protocols
- [ ] 03 Schnorr ID
- [ ] 04 Fiat-Shamir
- [ ] 05 Chaum-Pedersen
- [ ] 06 OR/AND Proofs
- [ ] 07 Range Proofs
- [ ] 08 Bulletproofs
- [ ] 09 Inner Product Argument
- [ ] 10 Extractors
- [ ] 11 Universal vs Trusted Setup
- [ ] 12 Σ-Protocol Library Lab

### Phase 12 — ZK Proof Systems

- [ ] 01 Arithmetic Circuits
- [ ] 02 R1CS
- [ ] 03 QAP
- [ ] 04 Pinocchio
- [ ] 05 Groth16
- [ ] 06 PLONK Overview
- [ ] 07 PLONK Implement
- [ ] 08 Lookup Arguments
- [ ] 09 PLONKish Arithmetization
- [ ] 10 Halo2
- [ ] 11 STARKs
- [ ] 12 FRI
- [ ] 13 DEEP-FRI
- [ ] 14 Recursive Proofs
- [ ] 15 Folding Schemes
- [ ] 16 SNARK/STARK Comparison Lab

### Phase 13 — ZK Engineering

- [ ] 01 Circom
- [ ] 02 snarkjs
- [ ] 03 Halo2 Rust
- [ ] 04 arkworks
- [ ] 05 Noir
- [ ] 06 RISC0 zkVM
- [ ] 07 SP1 & Jolt
- [ ] 08 On-Chain Verifiers
- [ ] 09 Proof Aggregation & Recursion
- [ ] 10 ZK Mixers
- [ ] 11 Semaphore
- [ ] 12 ZK App End-to-End Lab

### Phase 14 — PQ Lattice

- [ ] 01 Why Quantum Breaks Classical
- [ ] 02 Shor's Algorithm
- [ ] 03 Grover & Symmetric
- [ ] 04 Regev Encryption
- [ ] 05 Dual Regev & Trapdoors
- [ ] 06 Kyber / ML-KEM
- [ ] 07 Kyber Internals
- [ ] 08 Dilithium / ML-DSA
- [ ] 09 Falcon
- [ ] 10 NTRU Encryption
- [ ] 11 FrodoKEM
- [ ] 12 NewHope & Saber
- [ ] 13 BIKE & HQC
- [ ] 14 Mini Kyber Lab

### Phase 15 — PQ Code/Hash/Multivariate

- [ ] 01 McEliece
- [ ] 02 Classic McEliece
- [ ] 03 Lamport
- [ ] 04 Winternitz
- [ ] 05 Merkle Signatures
- [ ] 06 XMSS
- [ ] 07 LMS
- [ ] 08 SPHINCS+
- [ ] 09 Multivariate / Rainbow
- [ ] 10 UOV & MAYO

### Phase 16 — PQ Isogenies & Migration

- [ ] 01 Isogenies
- [ ] 02 SIDH Broken
- [ ] 03 CSIDH
- [ ] 04 SQIsign
- [ ] 05 NIST PQC Standards
- [ ] 06 Hybrid TLS
- [ ] 07 Crypto-Agility
- [ ] 08 Harvest-Now-Decrypt-Later
- [ ] 09 PQ Migration Lab

### Phase 17 — FHE & MPC

- [ ] 01 FHE Overview
- [ ] 02 BGV / BFV
- [ ] 03 CKKS
- [ ] 04 TFHE
- [ ] 05 OpenFHE & SEAL
- [ ] 06 Yao Garbled Circuits
- [ ] 07 GMW
- [ ] 08 BGW
- [ ] 09 SPDZ
- [ ] 10 Beaver Triples
- [ ] 11 Threshold FHE
- [ ] 12 PSI

### Phase 18 — Applied Blockchain & Identity

- [ ] 01 Bitcoin Stack
- [ ] 02 Ethereum Stack
- [ ] 03 BLS Aggregation Eth2
- [ ] 04 VRFs
- [ ] 05 VDFs
- [ ] 06 BBS+
- [ ] 07 W3C VC & DIDs
- [ ] 08 ZK Rollups
- [ ] 09 Account Abstraction & ZK
- [ ] 10 Threshold Wallets

### Phase 19 — Cryptanalysis & Side Channels

- [ ] 01 Padding Oracles
- [ ] 02 Bleichenbacher
- [ ] 03 Timing Attacks
- [ ] 04 Cache Attacks
- [ ] 05 DPA
- [ ] 06 Fault Attacks
- [ ] 07 Coppersmith on RSA
- [ ] 08 HNP on ECDSA
- [ ] 09 Length Extension
- [ ] 10 CryptoCTF Walkthroughs

### Phase 20 — Capstones

- [ ] 01 Mini TLS 1.3
- [ ] 02 ZK Voting
- [ ] 03 PQ Messenger
- [ ] 04 FHE Inference
- [ ] 05 Mini ZK Rollup
- [ ] 06 Threshold Wallet
