# Myths

Common misconceptions about cryptography. One paragraph per myth, with a citation.

## "Encryption hides everything about the message"

**Reality:** Vanilla encryption hides plaintext content but leaks message *length*, sometimes *frequency* (ECB), *timing* of when messages are sent, and *metadata* (who talks to whom). AEAD authenticates content but not whether two ciphertexts came from the same key. Use padding, mixnets, and metadata protection if length / traffic analysis matter. *Source:* Boneh-Shoup §9.

## "RSA is broken"

**Reality:** RSA *as a mathematical primitive* with conservative parameters (≥3072-bit modulus, OAEP / PSS padding) is not broken classically. What is broken: textbook RSA (no padding), low-exponent RSA without padding, RSA with poor randomness. RSA is also broken by quantum computers (Shor) — but that's a future threat, not a present one. *Source:* Boneh's Twenty Years of Attacks on RSA.

## "Quantum computers will break all crypto tomorrow"

**Reality:** Cryptographically-relevant quantum computers (CRQC) need millions of stable logical qubits. As of 2026 we have ~1000 noisy physical qubits. NIST estimates 10–30 years. The real urgent threat is *harvest-now-decrypt-later*: attackers store ciphertext today and decrypt when CRQCs arrive. Migrate KEMs first. *Source:* NIST IR 8413, Mosca's theorem.

## "AES-256 is more secure than AES-128"

**Reality:** For passive attackers, AES-128 has a 128-bit security level, sufficient against any classical adversary. AES-256 buys quantum-resilience under Grover (effective 128-bit post-Grover) and is *related-key weaker* than AES-128. Use AES-256 in PQ-ready protocols, AES-128 elsewhere. *Source:* Biryukov-Khovratovich Related-Key Cryptanalysis of AES-256.

## "If I use HTTPS, my data is safe"

**Reality:** TLS 1.3 protects bytes in transit between two endpoints. It does not protect against compromised servers, malicious CAs, traffic analysis, or browser exploits. End-to-end encryption (Signal, Matrix) is a different threat model. *Source:* Krawczyk's TLS Security Analysis.

## "Hashing is encryption"

**Reality:** Hashing is one-way and produces fixed-length output. Encryption is reversible (with a key). You cannot "decrypt" SHA-256. Use hashes for integrity, encryption for confidentiality. *Source:* every textbook ever.

## "Hashing passwords with SHA-256 is enough"

**Reality:** SHA-256 is fast, which is exactly the wrong property for password hashing. Use Argon2id, scrypt, or bcrypt — designed to be slow and memory-hard. *Source:* OWASP Password Storage Cheat Sheet.

## "Zero-knowledge means no one can see anything"

**Reality:** ZK proves a *statement* is true without revealing the *witness* to that statement. The verifier still sees the statement, public inputs, and proof. ZK ≠ confidentiality of public inputs. *Source:* Goldwasser-Micali-Rackoff 1985.

## "Trusted setup is fine, trust me"

**Reality:** A trusted setup ceremony is only as secure as the assumption that *at least one participant* discarded their secret. Single-party setups (like the original Pinocchio) require trusting one entity. Modern ceremonies (Powers of Tau, Filecoin) involve thousands of contributors; the ceremony is broken only if every participant colludes. PLONK has *universal* setup; STARKs and Bulletproofs have *transparent* setup (no secret randomness). *Source:* Bowe et al., Powers of Tau.

## "ECDSA is just RSA with smaller keys"

**Reality:** ECDSA is fragile in ways RSA is not. Reusing a nonce reveals the private key. Biased nonces enable lattice attacks. Sony's PS3 was compromised exactly this way. Use deterministic nonces (RFC 6979) or Ed25519 / Schnorr. *Source:* Bleichenbacher's PS3 talk; RFC 6979.

## "Random numbers are random"

**Reality:** Most crypto-fail postmortems trace back to bad RNG. Debian's broken OpenSSL (2008), Sony PS3, Bitcoin wallets sharing nonces. Always use OS RNG (`/dev/urandom`, `getrandom()`, `BCryptGenRandom`). Never `rand()` / `Math.random()`. *Source:* Heninger et al., Mining Your Ps and Qs.

## "Post-quantum means lattice-based"

**Reality:** Lattice-based dominates because it's efficient, but PQ also includes code-based (McEliece, BIKE, HQC), hash-based (SPHINCS+, XMSS), multivariate (UOV, MAYO), and isogeny-based (CSIDH, SQIsign). NIST standards include both lattice (ML-KEM, ML-DSA, Falcon) and hash-based (SPHINCS+). Diversity matters — if lattice assumptions fall, you want a code or hash-based fallback. *Source:* NIST PQC standardization round 4.

## "FHE means I can run any computation on encrypted data fast"

**Reality:** FHE works, but with overhead. CKKS and BFV multiplications are 10⁴-10⁶× slower than plaintext. Bootstrapping (TFHE) is fast for boolean ops but slow for arithmetic. FHE is right for low-throughput, high-privacy use cases (medical inference) — not for general computation. *Source:* OpenFHE benchmarks; Lauter et al.
