# Why Quantum Breaks Classical Crypto

> Quantum doesn’t “weaken” RSA — it changes the problem from *hard* to *easy*.

**Type:** Learn
**Languages:** Python
**Prerequisites:** Phase 08, Lesson 01 (RSA); Phase 08, Lesson 04 (Diffie–Hellman); Phase 07 (symmetric basics)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain why Shor breaks RSA and discrete-log crypto
- Compute Grover-style effective security for brute-force key search
- Implement toy demos that make “hard assumptions” concrete
- Distinguish “broken” (public-key) from “reduced margin” (symmetric/hash)
- Apply a migration mapping from classical primitives to PQ replacements

## The Problem

Your system relies on cryptographic assumptions you don’t control: that factoring large integers is infeasible (RSA), that discrete logs are infeasible (Diffie–Hellman/ECDH), and that brute-force key search is infeasible (symmetric keys). Those assumptions are what make “public key” safe and what sets key sizes (128-bit, 256-bit, 3072-bit RSA, etc.).

Quantum algorithms change the *shape* of these assumptions. For public-key crypto, Shor’s algorithm turns “infeasible” problems (factoring, discrete log) into polynomial-time problems — meaning the security story collapses, not just degrades. For symmetric crypto and hashes, Grover’s algorithm doesn’t fully break them, but it cuts brute-force margins roughly in half. That changes which key sizes are “enough”, and it changes what you should store today if you need confidentiality for 10–30 years (harvest-now, decrypt-later).

If you can’t reason about which primitives are affected and how, you can’t do a credible PQ migration: you’ll either overreact (throw out everything), or underreact (ship a “quantum-ready” claim that is false).

## The Concept

Two algorithmic facts drive almost all PQ migration work:

1. **Shor (public-key):** factoring and discrete log become *efficient* on a large enough quantum computer.
2. **Grover (brute force):** unstructured search becomes √ faster, which is roughly “security bits ÷ 2”.

This leads to a useful mental table:

| Primitive family | What you assume today | Quantum effect | Practical consequence |
|---|---|---|---|
| RSA | factoring is hard | **Shor breaks it** | RSA key exchange/signatures must be replaced |
| (EC)DH / ECDH | discrete log is hard | **Shor breaks it** | DH/ECDH key exchange must be replaced |
| ECDSA/EdDSA | discrete log is hard | **Shor breaks it** | most current signatures must be replaced |
| AES | brute-force key search is hard | **Grover halves margin** | bump key sizes (e.g. AES-256) |
| SHA-256 | preimage search is hard; collisions need birthday | **Grover/BHT reduce exponents** | margins change, but 256-bit outputs remain strong |

In this lesson you’ll *not* implement quantum algorithms. Instead, you’ll build small deterministic demos that make the consequences feel concrete: “if I can factor `n`, I can recover `d`”, and “if Grover halves bits, what does that mean for key sizes?”

## Build It

### Step 1: Quantify Grover's impact (key search)

```python
def grover_effective_security_bits(classical_security_bits: int) -> float:
    if classical_security_bits < 0:
        raise ValueError("classical_security_bits must be >= 0")
    return classical_security_bits / 2.0


def grover_required_bits_for_target_security(target_security_bits: int) -> int:
    if target_security_bits < 0:
        raise ValueError("target_security_bits must be >= 0")
    return 2 * target_security_bits


def bht_effective_collision_security_bits(hash_output_bits: int) -> float:
    if hash_output_bits < 0:
        raise ValueError("hash_output_bits must be >= 0")
    return hash_output_bits / 3.0
```

These helpers encode the one-line “back of the envelope” rules you’ll use constantly in PQ work: Grover makes brute-force behave like √, so *bits halve*; and BHT-style quantum collision search changes the birthday exponent from ~1/2 to ~1/3.

### Step 2: Toy hash-prefix preimage search (brute force)

```python
import hashlib


def sha256_prefix_bits(data: bytes, prefix_bits: int) -> int:
    if prefix_bits < 0:
        raise ValueError("prefix_bits must be >= 0")
    digest = hashlib.sha256(data).digest()
    digest_int = int.from_bytes(digest, byteorder="big")
    if prefix_bits == 0:
        return 0
    return digest_int >> (256 - prefix_bits)


def find_sha256_prefix_preimage(prefix_bits: int, target_prefix: int, max_tries: int) -> tuple[int, int]:
    if prefix_bits < 0:
        raise ValueError("prefix_bits must be >= 0")
    if max_tries < 0:
        raise ValueError("max_tries must be >= 0")
    if prefix_bits == 0:
        if target_prefix != 0:
            raise ValueError("for prefix_bits=0, target_prefix must be 0")
    else:
        if not (0 <= target_prefix < (1 << prefix_bits)):
            raise ValueError("target_prefix out of range for prefix_bits")

    for x in range(max_tries):
        prefix = sha256_prefix_bits(str(x).encode("utf-8"), prefix_bits)
        if prefix == target_prefix:
            return x, x + 1
    raise ValueError("no preimage found within max_tries")
```

This is a deterministic “brute force feels like brute force” demo: you search for an `x` such that `sha256(str(x))` starts with a chosen number of zero bits. You’ll compare the observed query count to the *expected* classical vs Grover-style query counts.

### Step 3: RSA break: once you can factor n, you can recover d

```python
import math
from dataclasses import dataclass


def egcd(a: int, b: int) -> tuple[int, int, int]:
    if a < 0 or b < 0:
        raise ValueError("egcd expects non-negative inputs")
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def modinv(a: int, m: int) -> int:
    if m <= 0:
        raise ValueError("m must be > 0")
    a = a % m
    g, x, _y = egcd(a, m)
    if g != 1:
        raise ValueError("inverse does not exist")
    return x % m


def rsa_keypair_from_primes(p: int, q: int, e: int = 65537) -> tuple[int, int, int]:
    if p <= 1 or q <= 1:
        raise ValueError("p and q must be > 1")
    if p == q:
        raise ValueError("p and q must be distinct")
    if e <= 1:
        raise ValueError("e must be > 1")
    n = p * q
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)
    return n, e, d


def rsa_encrypt(m: int, n: int, e: int) -> int:
    if not (0 <= m < n):
        raise ValueError("message representative must be in [0, n)")
    return pow(m, e, n)


def rsa_decrypt(c: int, n: int, d: int) -> int:
    if not (0 <= c < n):
        raise ValueError("ciphertext representative must be in [0, n)")
    return pow(c, d, n)


@dataclass(frozen=True)
class TrialDivisionResult:
    factor: int | None
    steps: int


def trial_division_small_factor(n: int, max_divisor: int | None = None) -> TrialDivisionResult:
    if n <= 1:
        raise ValueError("n must be > 1")
    if n % 2 == 0:
        return TrialDivisionResult(2, 1)

    limit = int(math.isqrt(n))
    if max_divisor is not None:
        if max_divisor < 2:
            raise ValueError("max_divisor must be >= 2")
        limit = min(limit, max_divisor)

    steps = 0
    d = 3
    while d <= limit:
        steps += 1
        if n % d == 0:
            return TrialDivisionResult(d, steps)
        d += 2
    return TrialDivisionResult(None, steps)


def factor_semiprime_by_trial_division(n: int) -> tuple[int, int, int]:
    result = trial_division_small_factor(n)
    if result.factor is None:
        raise ValueError("n did not factor by trial division (maybe prime or too large?)")
    p = result.factor
    q = n // p
    if p * q != n:
        raise AssertionError("internal factoring invariant failed")
    return p, q, result.steps


def break_rsa_by_factoring(n: int, e: int) -> tuple[int, int, int]:
    p, q, _steps = factor_semiprime_by_trial_division(n)
    _n, _e, d = rsa_keypair_from_primes(p, q, e=e)
    return p, q, d
```

This is the core “Shor breaks RSA” consequence in one sentence: *RSA is safe only because factoring is hard; if factoring becomes easy, the private key can be derived from the public key.* Here you do the derivation with tiny numbers by explicitly factoring `n` and recomputing `d`.

### Step 4: Migration mapping (what to replace, and with what)

```python
def pqc_replacement_for(primitive: str) -> str:
    key = primitive.strip().lower()
    mapping = {
        "rsa": "Replace with ML-KEM (Kyber) for KEM; keep RSA only for legacy, behind crypto-agility.",
        "ecdh": "Replace with hybrid key exchange: X25519 + ML-KEM (draft/standard TLS hybrid patterns).",
        "dh": "Replace with hybrid key exchange: (EC)DH + ML-KEM; prefer X25519 for the classical half.",
        "ecdsa": "Replace with ML-DSA (Dilithium) or a hybrid signature (classical + ML-DSA) during migration.",
        "ed25519": "Replace with ML-DSA or hybrid Ed25519 + ML-DSA, depending on protocol and ecosystem support.",
        "sha-256": "Keep SHA-256; quantum changes security margins (preimage ~halves), but 256-bit outputs remain strong.",
        "aes-128": "Prefer AES-256 if you want ~128-bit security against Grover-style key search.",
    }
    if key not in mapping:
        raise ValueError(f"unknown primitive: {primitive!r}")
    return mapping[key]
```

Most migration mistakes happen *before* you ever touch a PQ library: teams don’t inventory primitives, don’t distinguish “broken” vs “reduced margin”, and don’t plan hybrid transitions. This function is a tiny stand-in for a real migration decision guide.

Run it:

```bash
python3 code/main.py
```

## Use It

In real systems you do not implement primitives by hand. You use standardized PQ algorithms and protocol integrations:

- **Key exchange / KEM:** ML-KEM (Kyber) in a reputable library (OpenSSL/BoringSSL forks as they add support; liboqs; language-specific wrappers).
- **Signatures:** ML-DSA (Dilithium) or standardized alternatives depending on ecosystem support.
- **Hybrid patterns:** many protocols will run *classical + PQ* in parallel during migration (to avoid betting everything on one new primitive immediately).

What this lesson gives you is the ability to audit code and ask the right questions: “Is this RSA used for signatures or key transport?”, “Is this ECDH in TLS?”, “What long-lived data is encrypted today that could be decrypted later?”

## Pitfalls

- Treating Grover like it “breaks AES” and ripping out symmetric crypto instead of bumping key sizes.
- Forgetting **signatures**: many threat models focus on confidentiality (KEMs) but ignore update signing, package registries, and identity systems.
- Ignoring **harvest-now, decrypt-later**: data encrypted today may be stored and decrypted in the future once a CRQC exists.
- Migrating only one layer: swapping a library call while leaving protocol/certificate formats and operational tooling unchanged.
- Skipping crypto-agility: hard-coding algorithm choices so you can’t rotate quickly when standards or implementations evolve.

## Ship It

This lesson produces:
- `outputs/pqc-migration-audit-prompt.md` — a paste-ready prompt/checklist to audit a repo for classical crypto exposure and sketch a PQ migration plan.

Use it when you review a PR, start a migration epic, or need to quickly inventory where RSA/ECDH/ECDSA are used (and whether that data has long-term confidentiality requirements).

## Exercises

1. Easy. Run `python3 code/main.py`. Observe how “factoring ⇒ recover `d`” makes RSA collapse with tiny numbers.
2. Medium. Change `prefix_bits` in `main()` from `16` to `20`. Observe how the brute-force query count grows, and compare to the Grover-style √ rule.
3. Hard. Pick one real codebase you know. Inventory where it uses RSA/ECDH/ECDSA, classify each usage (KEM vs signature vs certificate), and write a “hybrid-first” migration plan.

## Key Terms

| Term | What people say | What it actually means |
|---|---|---|
| CRQC | “Cryptographically relevant quantum computer” | A quantum computer large/clean enough to break real cryptographic parameters (not today’s toy demos) |
| Shor’s algorithm | “Quantum factoring” | A polynomial-time algorithm for factoring and discrete log on a quantum computer |
| Grover’s algorithm | “Quantum speedup” | A √ speedup for unstructured search (e.g., brute-force key search, preimages) |
| Harvest-now, decrypt-later | “Store ciphertexts for later” | An attacker records encrypted traffic/data today and decrypts it later when capabilities improve |
| Crypto-agility | “Support many algorithms” | Engineering practice: the system can rotate/upgrade primitives quickly without redesigning everything |

## Further Reading

- Peter W. Shor, *Algorithms for quantum computation: discrete logarithms and factoring* (1994) — the result that makes RSA/ECDH/ECDSA non-viable in the long run.
- Lov K. Grover, *A fast quantum mechanical algorithm for database search* (1996) — √ speedup for brute-force search.
- NIST, *Post-Quantum Cryptography Standardization* (ongoing) — the standardization process behind ML-KEM and ML-DSA.
