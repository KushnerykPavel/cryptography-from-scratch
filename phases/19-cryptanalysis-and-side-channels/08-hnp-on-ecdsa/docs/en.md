# Nonce Leakage in ECDSA — HNP (Toy)

> If nonces leak bits, private keys leak too.

**Type:** Build
**Languages:** Python
**Prerequisites:** Modular arithmetic; inverses; basic ECDSA equation familiarity
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain why ECDSA requires unpredictable nonces k
- Compute the ECDSA-like signature equation modulo q
- Implement a toy leakage model where nonce MSBs are revealed
- Distinguish brute-force recovery from lattice-based HNP recovery
- Apply a toy HNP check to recover a secret key from multiple leaked prefixes

## The Problem

ECDSA’s security depends critically on the nonce `k` being secret and uniformly random for every signature. If `k` repeats, is biased, or leaks bits (timing, cache, power, RNG issues), attackers can often recover the private key.

Many real-world breaks have been caused by nonce problems: weak RNGs, deterministic-but-buggy nonces, or side-channel leakage. The math is unforgiving: each signature gives an equation linking `k` and the private key `x`.

This lesson shows the core idea of the Hidden Number Problem (HNP): multiple partial constraints about `k` can pin down `x`. We use brute force on toy parameters; real attacks use lattices.

## The Concept

ECDSA has the form:

`s = k^{-1}(h + x*r) mod q`

If you know `r, s, h` and you guess `x`, you can solve for the implied `k`:

`k = s^{-1}(h + x*r) mod q`

If the signer leaks the top bits of each `k`, you can test which `x` makes all implied `k` values match the leaked prefixes.

## Build It

### Step 1: ECDSA-like equation modulo q
```python
def toy_ecdsa_sign(h: int, x: int, k: int, q: int) -> Tuple[int, int]:
    r = k % q
    s = (inv_mod(k, q) * (h + x * r)) % q
    return r, s
```
This toy equation is enough to model why nonce leakage breaks ECDSA-like schemes.

### Step 2: Simulate leaked nonce MSB prefixes
```python
pref = k_i >> leak_bits
```
If the bottom `leak_bits` are unknown, then `k >> leak_bits` is the leaked MSB prefix.

### Step 3: Recover the secret key by brute forcing x (toy HNP)
```python
def recover_secret_key_from_leaked_nonce_prefixes(sigs: List[ToySig], q: int, leak_bits: int) -> int:
    for x in range(q):
        ok = True
        for sig in sigs:
            k = (inv_mod(sig.s, q) * (sig.h + x * sig.r)) % q
            if (k >> leak_bits) != sig.k_prefix:
                ok = False
                break
        if ok:
            return x
    raise RuntimeError("no key found")
```
Brute forcing is feasible only because `q` is tiny in the demo. Real HNP recovery uses lattice reduction.

Run it:
python3 code/main.py

## Use It

- Use deterministic nonces (RFC 6979) where appropriate, implemented correctly.
- Use hardened constant-time implementations that avoid nonce leakage via side channels.
- Treat nonce bias/leakage as a private-key compromise.

## Pitfalls

- Reusing nonces across messages.
- Assuming “leaking a few bits of k” is harmless.
- RNG failures in embedded or virtualized environments.
- Side-channel leakage from inversion or scalar multiplication.
- Logging/debugging that exposes values tied to k.

## Ship It

Save an ECDSA nonce hygiene checklist: `outputs/ecdsa-nonce-hygiene-checklist.md`.

## Exercises

1. Easy. Run `python3 code/main.py`. Observe that leaked nonce prefixes recover x in the toy setting.
2. Medium. Reduce the number of signatures and see when recovery becomes ambiguous.
3. Hard. Introduce a wrong prefix and discuss why brute force fails but lattice HNP can still succeed with enough constraints.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Nonce k | “random per signature” | Secret scalar that must be unpredictable and unique |
| Prefix leak | “known top bits” | Attacker learns MSBs of k, leaving only low bits unknown |
| HNP | “lattice attack” | Solve for a hidden value given many partial constraints |
| Key recovery | “private key leak” | Once x is known, all signatures are compromised |

## Further Reading

- RFC 6979, “Deterministic Usage of the Digital Signature Algorithm (DSA) and ECDSA” — deterministic nonces to avoid RNG failures
- Howgrave-Graham & Smart, “Lattice Attacks on Digital Signature Schemes” — HNP framing for signature leakage
