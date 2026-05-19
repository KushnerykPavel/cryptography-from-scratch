# RSA & Class Group Accumulators
> Commit to a set with one number; prove membership with one more.

**Type:** Build  
**Languages:** Python  
**Prerequisites:** `phases/09-hashes-commitments-accumulators/01-hash-commitments`, `phases/09-hashes-commitments-accumulators/04-merkle-trees`  
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain what an accumulator commits to and what a witness proves
- Compute an RSA accumulator value from prime representatives
- Implement deterministic hash-to-prime for set elements
- Distinguish RSA accumulators from class group accumulators (setup and assumptions)
- Apply a design checklist to choose accumulators vs Merkle/KZG for a project

## The Problem
You want a compact commitment to a large set (say, “these 50,000 users are allowed to withdraw”) and you want each user to carry a *small* proof that they’re in the set. A Merkle tree can do that, but proofs grow with `log n`, updates require tree machinery, and you might not want to ship tree paths everywhere.

Accumulators give you another tradeoff: a single group element `A` commits to the entire set, and a membership proof is typically one group element `w`. This is especially attractive when you need *many* membership proofs and you care about proof size more than update cost.

But accumulators come with sharp edges: you have to encode elements carefully (to avoid collisions), you must understand update semantics, and some accumulator flavors require assumptions or setup that are very different from Merkle trees.

## The Concept
An accumulator is a commitment to a set where the commitment stays constant size.

The standard RSA-style accumulator works like this:

- Map each element `x` to a **prime representative** `p(x)` (a prime number).
- Pick an RSA modulus `N = p*q` and a base `g` in a subgroup of `Z*_N` (in practice: a quadratic residue).
- Define the accumulator value:

  `A = g^( Π p(x) ) mod N`

Membership witness for a particular `x` is:

`w_x = g^( Π p(y) for y != x ) mod N`

Verification is one modular exponentiation:

`w_x^(p(x)) mod N == A`

The “unknown-order group” part is the key insight:
- Verification never uses `φ(N)` or the group order.
- You only need `N` and `g`.

That same pattern is why **class group accumulators** are interesting: class groups give you an unknown-order group *without* generating `N=p*q` via a trusted setup. The math of class groups is more complex, but the accumulator API can feel similar: “raise to a prime representative; multiply exponents by chaining exponentiations.”

## Build It

### Step 1: Prime representatives (hash-to-prime)
We’ll deterministically map an element to a prime: hash, slice to `bits`, force odd + top bit, then increment a counter until it’s prime. In real protocols this is called “hash-to-prime” and it’s what makes the set elements behave like unique primes.

```python
def is_probable_prime(n: int) -> bool:
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False

    d = n - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2

    bases = [2, 325, 9375, 28178, 450775, 9780504, 1795265022]
    for a in bases:
        a %= n
        if a == 0:
            continue
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def hash_to_prime(message: bytes, *, domain: str = "rsa-accum", bits: int = 32) -> int:
    if bits < 8:
        raise ValueError("bits must be >= 8")

    counter = 0
    while True:
        h = hashlib.sha256(
            domain.encode("utf-8")
            + b"\x00"
            + counter.to_bytes(4, "big")
            + b"\x00"
            + message
        ).digest()
        x = int.from_bytes(h, "big")
        candidate = (x & ((1 << bits) - 1)) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate
        counter += 1
```

### Step 2: Accumulate a set into one value
We implement the group arithmetic helpers and the accumulator update rule. Notice `rsa_accumulate` never builds the giant exponent `Π p(x)` explicitly; it chains exponentiations:

`(((g^p1)^p2)^p3) = g^(p1*p2*p3)`.

```python
def egcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def modinv(a: int, m: int) -> int:
    g, x, _y = egcd(a, m)
    if g != 1:
        raise ValueError("inverse does not exist")
    return x % m


def pow_mod_signed(base: int, exponent: int, modulus: int) -> int:
    if exponent >= 0:
        return pow(base, exponent, modulus)
    return pow(modinv(base, modulus), -exponent, modulus)


def qr_base(modulus: int, seed: bytes) -> int:
    x = int.from_bytes(hashlib.sha256(seed).digest(), "big") % modulus
    if x == 0:
        x = 2
    while math.gcd(x, modulus) != 1:
        x = (x + 1) % modulus
        if x == 0:
            x = 2
    return pow(x, 2, modulus)


def rsa_accumulate(prime_reps: Iterable[int], *, modulus: int, base: int) -> int:
    acc = base % modulus
    for p in prime_reps:
        if p <= 1:
            raise ValueError("prime representatives must be > 1")
        acc = pow(acc, p, modulus)
    return acc


def rsa_add(acc_value: int, prime_rep: int, *, modulus: int) -> int:
    if prime_rep <= 1:
        raise ValueError("prime representative must be > 1")
    return pow(acc_value % modulus, prime_rep, modulus)
```

### Step 3: Membership witnesses + fast updates
A membership witness for `x` is the accumulator of “everything except `x`”. If the set grows by a new element `z`, you can update *every* existing witness by exponentiating it by `p(z)` (one exponentiation per witness).

```python
def rsa_membership_witness(
    all_prime_reps: list[int],
    member_prime_rep: int,
    *,
    modulus: int,
    base: int,
) -> int:
    if member_prime_rep not in all_prime_reps:
        raise ValueError("member_prime_rep must be in the set")
    witness = base % modulus
    skipped = False
    for p in all_prime_reps:
        if not skipped and p == member_prime_rep:
            skipped = True
            continue
        witness = pow(witness, p, modulus)
    return witness


def rsa_update_witness_on_add(witness: int, added_prime_rep: int, *, modulus: int) -> int:
    if added_prime_rep <= 1:
        raise ValueError("prime representative must be > 1")
    return pow(witness % modulus, added_prime_rep, modulus)


def rsa_verify_membership(
    acc_value: int, witness: int, member_prime_rep: int, *, modulus: int
) -> bool:
    if member_prime_rep <= 1:
        return False
    return pow(witness % modulus, member_prime_rep, modulus) == (acc_value % modulus)
```

### Step 4: Non-membership proofs (RSA-specific)
RSA accumulators can also produce *non-membership* proofs (show “`x` is not in the set”) using Bezout coefficients.

Let `s = Π p(y)` for `y` in the set and `x` be a prime rep not in the set. If `gcd(s, x)=1`, there exist integers `a,b` such that:

`a*s + b*x = 1`.

With `A = g^s`, define `d = g^b`. Then:

`A^a * d^x = g^(a*s) * g^(b*x) = g`.

```python
def rsa_nonmembership_proof(
    all_prime_reps: Iterable[int],
    nonmember_prime_rep: int,
    *,
    modulus: int,
    base: int,
) -> tuple[int, int]:
    if nonmember_prime_rep <= 1:
        raise ValueError("prime representative must be > 1")

    s = 1
    for p in all_prime_reps:
        if p <= 1:
            raise ValueError("prime representatives must be > 1")
        if p == nonmember_prime_rep:
            raise ValueError("nonmember_prime_rep must not be in the set")
        s *= p

    if math.gcd(s, nonmember_prime_rep) != 1:
        raise ValueError("nonmember_prime_rep must be coprime to the set product")

    _g, a, b = egcd(s, nonmember_prime_rep)
    d = pow_mod_signed(base % modulus, b, modulus)
    return (a, d)


def rsa_verify_nonmembership(
    acc_value: int,
    nonmember_prime_rep: int,
    proof_a: int,
    proof_d: int,
    *,
    modulus: int,
    base: int,
) -> bool:
    if nonmember_prime_rep <= 1:
        return False
    left = (
        pow_mod_signed(acc_value % modulus, proof_a, modulus)
        * pow(proof_d % modulus, nonmember_prime_rep, modulus)
    ) % modulus
    return left == (base % modulus)
```

Run it:
`python3 code/main.py`

## Use It
Production systems rarely use a from-scratch accumulator implementation. Typical patterns:

- **RSA accumulators in libraries:** implemented as part of research code or specialized stacks; you generally want audited, battle-tested implementations with careful parameter generation and element encoding.
- **Class group primitives (related ecosystem):** class groups appear in verifiable delay functions (VDFs) and other protocols that rely on unknown-order groups; class-group accumulator implementations, when used, live in specialized cryptography codebases.
- **Common alternatives:** if you only need membership proofs, Merkle trees are widely deployed and easy to audit; if you need succinct proofs with pairing-friendly commitments, KZG is common (with trusted setup tradeoffs).

## Pitfalls
- **Bad element encoding:** skipping hash-to-prime (or using small / reused primes) can break soundness; collisions become “free membership”.
- **Wrong base `g`:** for RSA accumulators you typically want `g` in the quadratic residues subgroup; picking arbitrary `g` can leak structure or enable edge-case weirdness.
- **Assuming deletions are easy:** adding elements is straightforward; deletions and fully dynamic witness maintenance are more complex and easy to get wrong.
- **Trusted setup confusion:** RSA accumulators need a modulus whose factorization is unknown to everyone who can influence security; “we generated `N=p*q` and threw away `p,q`” is only safe if you trust the generator.
- **Mixing up membership vs non-membership:** non-membership proofs have extra conditions (`gcd(s, x)=1`) and different failure modes.

## Ship It
Save and use the checklist at `outputs/accumulator-review-checklist.md` when you:
- Review a PR introducing an accumulator (RSA or class group)
- Decide between Merkle/KZG/accumulators for set membership problems
- Audit parameter generation and element encoding choices

## Exercises
1. Easy. Run `python3 code/main.py`. Observe that the membership witness verifies *before* and *after* adding a new element (witness update by exponentiation).
2. Medium. Extend `code/main.py` to build witnesses for all elements and update all of them when adding a new element. Print the percentage that still verifies.
3. Hard. Sketch an “accumulator-backed allowlist” API: choose one of Merkle, RSA accumulator, or KZG and write down (a) what the server stores, (b) what the client carries, (c) what changes on updates, and (d) the trust assumption you’re making.

## Key Terms
| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Accumulator | “One value commits to a big set” | A commitment with constant-size commitment and (usually) constant-size membership proofs |
| Prime representative | “Hash-to-prime” | A deterministic mapping from an element to a prime used as an exponent factor |
| Witness | “Proof of membership” | A group element that, when exponentiated by `p(x)`, matches the accumulator |
| Unknown-order group | “You can’t reduce exponents mod the order” | A group where no one knows the group order (e.g., RSA groups without factoring, class groups) |
| Trusted setup | “Someone generated parameters” | A process that must not leak trapdoors (e.g., the factorization of `N`) |

## Further Reading
- Josh Benaloh, Michael de Mare, *One-Way Accumulators: A Decentralized Alternative to Digital Signatures* (1993) — classic RSA accumulator construction.
- Jan Camenisch, Anna Lysyanskaya, *Dynamic Accumulators and Application to Efficient Revocation of Anonymous Credentials* (2002) — dynamic updates and credential revocation.
- Dan Boneh et al., *Batching Techniques for Accumulators* (various) — practical witness update strategies and constraints.
- Wesolowski / Pietrzak VDF papers + class group implementations — good intuition for “unknown-order groups without RSA setup”.
