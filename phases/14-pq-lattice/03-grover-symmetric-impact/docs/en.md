# Grover's Algorithm & Symmetric Impact

> Quadratic speedup halves your security bits.

**Type:** Learn
**Languages:** Python
**Prerequisites:** Phase 08 (symmetric crypto basics), Phase 09 (hashes), Phase 14 Lesson 01 (Why Quantum Breaks Classical)
**Time:** ~45 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain why Grover gives a quadratic speedup for unstructured search
- Compute “effective security bits” for key search under classical vs Grover models
- Implement a tiny sizing calculator for AES keys and hash output sizes
- Distinguish preimage resistance from collision resistance under quantum attacks (Grover vs BHT)
- Apply a practical rule-of-thumb to choose symmetric parameters in post-quantum designs

## The Problem

You’re designing a system meant to survive the “harvest now, decrypt later” threat model. You upgrade your public-key crypto to lattice KEMs and signatures (Kyber/Dilithium), but you still need to decide: what about **AES** and **SHA-2**? Do you keep AES-128? Do you need SHA-512 everywhere? If you get this wrong, you can end up with a “post-quantum” system whose weakest link is still symmetric.

Worse, teams often reason about symmetric security using a mental model that’s too binary: “quantum breaks RSA, so quantum breaks everything.” That leads to overreaction (slow, overbuilt systems) or underreaction (deploying AES-128 in places where you really wanted 128-bit post-quantum strength).

This lesson gives you a compact, reusable model: express work factors in **log2 units (“security bits”)**, then update those bits under Grover’s scaling. You’ll use that model to choose AES key sizes and hash output sizes with clear tradeoffs.

## The Concept

Grover’s algorithm is the canonical quantum speedup for “I have a black box, I’m trying to find the one input that makes it return true”:

- **Classical unstructured search:** ~`2^k` trials to find a `k`-bit secret (up to constant factors).
- **Grover search:** ~`2^(k/2)` oracle queries to find a `k`-bit secret (quadratic speedup).

It’s not magic parallelism: it’s amplitude amplification. If your best classical strategy is brute force with no structure to exploit, Grover is the best-known generic quantum improvement.

### A simple “security bits” model

Define:

- `log2(work)` = “how many bits of brute-force effort” an attacker must spend.
- For key search: `work_classical ≈ 2^k`, `work_grover ≈ 2^(k/2)`.
- With `P` identical workers (classical or quantum) you can (roughly) divide work by `P`, so `log2(work)` drops by `log2(P)`.

### Hashes: preimage vs collision under quantum

For an ideal `n`-bit hash:

| Goal | Classical cost | Quantum cost (idealized) |
|------|----------------|--------------------------|
| Preimage / second preimage | ~`2^n` | ~`2^(n/2)` (Grover) |
| Collision | ~`2^(n/2)` (birthday) | ~`2^(n/3)` (BHT) |

The key takeaway: **Grover hits preimage-style targets**; collisions have a different quantum algorithm (BHT) with a different exponent.

## Build It

### Step 1: Classical brute-force work (in log2 bits)
```python
def _require_int(name: str, x: int, *, min_value: int | None = None) -> int:
    if not isinstance(x, int):
        raise TypeError(f"{name} must be an int")
    if min_value is not None and x < min_value:
        raise ValueError(f"{name} must be >= {min_value}")
    return x


def is_power_of_two(n: int) -> bool:
    if not isinstance(n, int):
        raise TypeError("n must be an int")
    return n > 0 and (n & (n - 1)) == 0


def log2_pow2(n: int) -> int:
    n = _require_int("n", n, min_value=1)
    if not is_power_of_two(n):
        raise ValueError("n must be a power of two")
    return n.bit_length() - 1


def classical_key_search_log2_work(*, key_bits: int, parallelism: int = 1) -> int:
    """
    Classical brute-force key search work factor, expressed as log2(trials).

    Model: ~2^key_bits total trials; parallelism reduces work linearly.
    """

    key_bits = _require_int("key_bits", key_bits, min_value=1)
    parallelism = _require_int("parallelism", parallelism, min_value=1)
    return key_bits - log2_pow2(parallelism)
```
This step builds a tiny “log2 work” accounting system. We deliberately keep it simple: represent attacker effort in bits (`log2(work)`), and treat parallelism as a linear reduction of that work. The `power of two` restriction makes `log2(P)` exact and keeps the math crisp for a learning script.

### Step 2: Grover key search halves the exponent (in log2 bits)
```python
def grover_key_search_log2_work(*, key_bits: int, parallelism: int = 1) -> Fraction:
    """
    Grover key search work factor, expressed as log2(oracle queries).

    Model: ~2^(key_bits/2) queries; parallelism reduces work linearly.
    """

    key_bits = _require_int("key_bits", key_bits, min_value=1)
    parallelism = _require_int("parallelism", parallelism, min_value=1)
    return Fraction(key_bits, 2) - log2_pow2(parallelism)
```
This is the core lesson: replace `k` with `k/2`. Using `Fraction` keeps results exact for odd bit lengths (e.g., `255/2`), and makes it clear that Grover changes exponents, not constants.

### Step 3: Sizing AES keys for a post-quantum target (rule of thumb)
```python
def min_key_bits_for_target_under_grover(*, target_security_bits: int, safety_margin_bits: int = 0) -> int:
    """
    Minimum key size (in bits) so that Grover cost is at least target bits.

    With the simple model: grover_security ~= key_bits/2 - margin.
    """

    target_security_bits = _require_int("target_security_bits", target_security_bits, min_value=1)
    safety_margin_bits = _require_int("safety_margin_bits", safety_margin_bits, min_value=0)
    return 2 * (target_security_bits + safety_margin_bits)


def recommend_aes_key_bits(*, target_security_bits: int, safety_margin_bits: int = 0) -> int:
    """
    Recommend AES key size from {128, 192, 256} for a post-quantum target.

    Returns the smallest standard AES key size meeting the target under Grover.
    """

    need = min_key_bits_for_target_under_grover(
        target_security_bits=target_security_bits,
        safety_margin_bits=safety_margin_bits,
    )
    for candidate in (128, 192, 256):
        if candidate >= need:
            return candidate
    raise ValueError("target_security_bits too high for standard AES key sizes")
```
This turns the rule-of-thumb into a mechanical decision: to get `t` post-quantum security bits against key search, you need about `2t` key bits. That maps cleanly to AES-128/192/256.

### Step 4: Hash preimage vs collision costs under quantum
```python
def hash_preimage_log2_work_classical(*, output_bits: int, parallelism: int = 1) -> int:
    output_bits = _require_int("output_bits", output_bits, min_value=1)
    parallelism = _require_int("parallelism", parallelism, min_value=1)
    return output_bits - log2_pow2(parallelism)


def hash_preimage_log2_work_grover(*, output_bits: int, parallelism: int = 1) -> Fraction:
    output_bits = _require_int("output_bits", output_bits, min_value=1)
    parallelism = _require_int("parallelism", parallelism, min_value=1)
    return Fraction(output_bits, 2) - log2_pow2(parallelism)


def hash_collision_log2_work_classical(*, output_bits: int) -> Fraction:
    """
    Collision search cost for an ideal n-bit hash: ~2^(n/2) (birthday bound).
    """

    output_bits = _require_int("output_bits", output_bits, min_value=2)
    return Fraction(output_bits, 2)


def hash_collision_log2_work_quantum_bht(*, output_bits: int) -> Fraction:
    """
    Quantum collision search cost (BHT): ~2^(n/3) for an ideal n-bit hash.
    """

    output_bits = _require_int("output_bits", output_bits, min_value=3)
    return Fraction(output_bits, 3)
```
This step separates two very different “hash security” questions. Grover changes the **preimage** exponent from `n` to `n/2`, while BHT changes the **collision** exponent from `n/2` to `n/3`. You need both when you pick hash output sizes for signatures, commitments, and transcript hashing.

Run it:
python3 code/main.py

## Use It

Use these rules of thumb when choosing parameters in real systems (then confirm against your organization’s threat model and standards):

- **Symmetric encryption / MAC key search:** aim for ~`2t` key bits to get `t` “Grover bits”.
  - Common mapping: “128-bit PQ target” → AES-256.
- **Hash preimage targets:** aim for ~`2t` output bits to get `t` Grover preimage bits.
  - Common mapping: “128-bit PQ preimage target” → SHA-256 (Grover preimage ~128 bits).
- **Hash collision targets:** be explicit about whether collisions matter; if they do, remember quantum collisions scale like `2^(n/3)`.

Production equivalents:

- AES and SHA-2 are widely deployed in OpenSSL, BoringSSL, libsodium, and most HSMs; the “sizing” decision is about key sizes and hash choices, not about implementing new primitives.
- Standards and profiles often already reflect these choices (e.g., using AES-256 and SHA-384/SHA-512 in higher assurance profiles).

## Pitfalls

- Treating Grover as “AES-128 is broken” instead of “AES-128 offers ~64 Grover bits for key search.”
- Mixing up **preimage** and **collision** security (and forgetting that collisions have a different quantum exponent).
- Assuming `log2(work)` maps directly to wall-clock time without considering circuit depth, error correction overhead, and oracle cost.
- Forgetting parallelism: `P` machines (classical or quantum) reduce `log2(work)` by `log2(P)` in this model.
- Applying Grover where structure exists (e.g., protocol flaws, side channels, or algebraic structure) — those break the “unstructured search” assumption.

## Ship It

Save and reuse the checklist in `outputs/grover-symmetric-sizing-checklist.md` when you:

- review a PR that changes AES key sizes, hash algorithms, or security targets,
- design a hybrid classical+post-quantum protocol,
- audit “security bits” claims in documentation.

It’s designed to be pasted into a review comment and used as a decision guide.

## Exercises

1. Easy. Run `python3 code/main.py`. Observe how AES-128/192/256 map to ~64/96/128 Grover bits.
2. Medium. Modify `code/main.py` to compute recommendations under a fixed parallelism budget (e.g., `parallelism=2**20`) and compare outcomes.
3. Hard. Take a real design doc (or RFC) that specifies symmetric parameters, and write a short “Grover sizing review” using the shipped checklist.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Grover’s algorithm | “Quantum brute force” | A generic quadratic speedup for unstructured search problems |
| Oracle | “A black box” | A reversible function inside the quantum circuit that marks correct candidates |
| Security bits | “128-bit security” | Log2 of the attacker’s work factor under a defined attack model |
| Preimage resistance | “Hard to invert” | Hard to find *any* input mapping to a chosen hash output |
| Collision resistance | “Hard to collide” | Hard to find *any two* distinct inputs with the same hash output |
| Birthday bound | “Collisions are sqrt” | Classical collision search needs ~`2^(n/2)` work for an `n`-bit hash |
| BHT (quantum collision) | “Collisions are faster on quantum” | Quantum collision search scales roughly like `2^(n/3)` for ideal hashes |
| Hybrid cryptography | “Use both classical and PQ” | Combine classical and post-quantum primitives so breaking one doesn’t break the system |

## Further Reading

- L. K. Grover, “A Fast Quantum Mechanical Algorithm for Database Search” (1996) — Original Grover search result.
- G. Brassard, P. Høyer, M. Mosca, A. Tapp, “Quantum Amplitude Amplification and Estimation” (2002) — Clean framework for Grover-style speedups.
- G. Brassard, P. Høyer, A. Tapp, “Quantum Algorithm for the Collision Problem” (1997) — The BHT collision speedup.
- NIST, “Post-Quantum Cryptography” project pages (ongoing) — Context for PQ threat models and parameter choices.
