# What FHE Is — Levels, Schemes, Limits

> Ciphertexts carry a *noise budget*: homomorphic computation spends it; bootstrapping earns it back.

**Type:** Learn
**Languages:** Python
**Prerequisites:** `04-lattices/09-lwe` (noise + hardness intuition), `04-lattices/10-rlwe-mlwe` (ring view), `04-lattices/05-lll` (what attacks look like), `11-zero-knowledge-foundations/04-fiat-shamir` (circuits as “programs”)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain what “homomorphic” means in terms of `Enc`, `Dec`, and `Eval`, and why *noise* is the main limiter
- Distinguish PHE vs SHE vs FHE, and map “supported operations” to “supported circuit depth”
- Compute and track a simple “noise proxy” for a toy ciphertext and predict when decryption will fail
- Implement a tiny (insecure) DGHV-style toy scheme and evaluate a small XOR/AND circuit on ciphertexts
- Apply a practical scheme-selection rubric (BFV/BGV vs CKKS vs TFHE) to a concrete product requirement

## The Problem

You want to compute on sensitive user data that you are not allowed to see.

Concrete examples:

- A hospital wants cloud analytics on patient records without giving the cloud plaintext.
- A fintech wants to score credit risk on a user’s income/transactions without revealing them to the model host.
- A mobile app wants to query a proprietary model API without the server learning the user’s input (and without shipping the model to the client).

If you only have “encrypt/decrypt”, you must choose between two bad options: (1) send plaintext to the server (privacy loss), or (2) run everything locally (cost/latency/UX loss). Fully Homomorphic Encryption (FHE) exists to create a third option: **send ciphertexts, compute on ciphertexts, decrypt only at the edge**.

This lesson gives you the vocabulary and the mental model you need to reason about FHE systems before you touch a production library: *supported operations, noise budget, circuit depth, and why bootstrapping is the unlock*.

## The Concept

### Homomorphic encryption in one line

An encryption scheme is **homomorphic** for a function class `F` if anyone can turn encryptions of inputs into an encryption of the output:

```text
c_i = Enc(sk, m_i)
c   = Eval(f, c_1, ..., c_k)
Dec(sk, c) = f(m_1, ..., m_k)
```

The “magic” is that `Eval` does not need the secret key.

### Levels: PHE vs SHE vs FHE

| Level | What it supports | Typical reality |
|------:|------------------|-----------------|
| PHE (partially) | One operation unbounded (e.g., only additions) | Great for sums/means/counts (Paillier-style “additive HE”) |
| SHE (somewhat) | Both add + mul, but only up to a *small* multiplicative depth | Enough for shallow boolean or low-degree polynomials |
| FHE (fully) | Arbitrary circuits (any depth) | Works by periodically *refreshing* ciphertexts (bootstrapping) |

### The noise budget mental model

Most practical FHE families behave like this:

- A ciphertext encrypts a message *plus a small error term (“noise”)*.
- Homomorphic **addition** grows noise roughly linearly.
- Homomorphic **multiplication** grows noise much faster (often superlinearly / “explosively”).
- Decryption succeeds only if the final noise remains below a threshold.

That’s why FHE system design feels like “circuit budgeting”: you pick parameters so your circuit can finish before the noise budget runs out, or you insert a refresh step (bootstrapping) to reset noise.

### Scheme families (what they’re “for”)

| Family | Plaintext type | Strength | Typical use |
|--------|----------------|----------|-------------|
| BFV / BGV | exact integers mod `t` | arithmetic circuits (adds + muls) | private sums, linear algebra, exact integer logic |
| CKKS | approximate reals/complex | fast approximate arithmetic | ML inference, signal processing, approximate stats |
| (FHEW /) TFHE | bits / small integers | fast bootstrapped boolean / LUTs | comparisons, thresholds, decision trees, exact bit logic |

This lesson’s toy code is *not* BFV/BGV/CKKS/TFHE. It’s a minimal “ciphertext = plaintext + noise” demonstration that makes noise growth visible with integer arithmetic.

## Build It

### Step 1: Keygen + centered modular reduction (a “noise lens”)

```python
def _require_odd_positive(name: str, x: int) -> None:
    if not isinstance(x, int):
        raise TypeError(f"{name} must be int")
    if x <= 0:
        raise ValueError(f"{name} must be > 0")
    if x % 2 == 0:
        raise ValueError(f"{name} must be odd")


def centered_mod(x: int, modulus: int) -> int:
    _require_odd_positive("modulus", modulus)
    r = x % modulus
    if r > modulus // 2:
        r -= modulus
    return r


def generate_odd_int(bits: int, rng: random.Random) -> int:
    if not isinstance(bits, int):
        raise TypeError("bits must be int")
    if bits < 3:
        raise ValueError("bits must be >= 3")
    if not isinstance(rng, random.Random):
        raise TypeError("rng must be random.Random")

    x = rng.getrandbits(bits)
    x |= 1
    x |= 1 << (bits - 1)
    return x


def keygen_dghv(*, p_bits: int, rng: random.Random) -> int:
    return generate_odd_int(p_bits, rng)
```

Real FHE schemes decrypt by taking something “mod `q` and then rounding” (or “mod `p` and then mod 2” in the toy integer scheme below). `centered_mod` is a convenient way to *see* what decryption is really looking at: the centered residue in `(-p/2, p/2]`.

### Step 2: Encrypt/decrypt a bit (ciphertext = multiple of p + noisy bit)

```python
def _require_bit(name: str, m: int) -> None:
    if not isinstance(m, int):
        raise TypeError(f"{name} must be int")
    if m not in (0, 1):
        raise ValueError(f"{name} must be 0 or 1")


def encrypt_bit_with_qr(p: int, m: int, *, q: int, r: int) -> int:
    _require_odd_positive("p", p)
    _require_bit("m", m)
    if not isinstance(q, int):
        raise TypeError("q must be int")
    if q <= 0:
        raise ValueError("q must be > 0")
    if not isinstance(r, int):
        raise TypeError("r must be int")
    return p * q + 2 * r + m


def encrypt_bit(
    p: int,
    m: int,
    *,
    q_bits: int,
    r_bound: int,
    rng: random.Random,
) -> int:
    _require_odd_positive("p", p)
    _require_bit("m", m)
    if not isinstance(q_bits, int):
        raise TypeError("q_bits must be int")
    if q_bits < 2:
        raise ValueError("q_bits must be >= 2")
    if not isinstance(r_bound, int):
        raise TypeError("r_bound must be int")
    if r_bound <= 0:
        raise ValueError("r_bound must be > 0")
    if not isinstance(rng, random.Random):
        raise TypeError("rng must be random.Random")

    q = rng.getrandbits(q_bits) | 1
    r = rng.randint(-r_bound, r_bound)
    return encrypt_bit_with_qr(p, m, q=q, r=r)


def decrypt_bit(p: int, c: int) -> int:
    _require_odd_positive("p", p)
    if not isinstance(c, int):
        raise TypeError("c must be int")
    mu = centered_mod(c, p)
    return mu % 2


def ciphertext_noise(p: int, c: int) -> int:
    _require_odd_positive("p", p)
    if not isinstance(c, int):
        raise TypeError("c must be int")
    mu = centered_mod(c, p)
    m = mu % 2
    return abs(mu - m)
```

In this toy scheme, the ciphertext is `c = p*q + 2*r + m` with a secret odd `p`, a large random `q`, and a small random `r` (“noise”). Decryption looks at `mu = centered_mod(c, p)` which (when noise is small) equals `2*r + m`, and then returns the parity `mu % 2`.

### Step 3: Homomorphic XOR and AND (add/mul on ciphertexts)

```python
def homomorphic_xor(c1: int, c2: int) -> int:
    if not isinstance(c1, int) or not isinstance(c2, int):
        raise TypeError("c1 and c2 must be int")
    return c1 + c2


def homomorphic_and(c1: int, c2: int) -> int:
    if not isinstance(c1, int) or not isinstance(c2, int):
        raise TypeError("c1 and c2 must be int")
    return c1 * c2
```

Because `c mod p` exposes `2*r + m`, and `2*r` is even, **adding ciphertexts corresponds to XOR** (addition mod 2), and **multiplying ciphertexts corresponds to AND** (multiplication mod 2). This is the “boolean circuit” view of FHE: XOR/AND gates are enough to express any computation, but multiplication makes the noise blow up faster.

### Step 4: Depth limit + a fake “refresh” to illustrate bootstrapping

```python
def noise_budget_ok(p: int, c: int) -> bool:
    _require_odd_positive("p", p)
    if not isinstance(c, int):
        raise TypeError("c must be int")
    return ciphertext_noise(p, c) < (p // 4)


def refresh_via_decrypt_reencrypt(
    p: int,
    c: int,
    *,
    q_bits: int,
    r_bound: int,
    rng: random.Random,
) -> int:
    m = decrypt_bit(p, c)
    return encrypt_bit(p, m, q_bits=q_bits, r_bound=r_bound, rng=rng)


def eval_circuit_xor_and(
    p: int,
    c_bits: Sequence[int],
    *,
    q_bits: int,
    r_bound: int,
    rng: random.Random,
) -> int:
    if len(c_bits) != 3:
        raise ValueError("c_bits must have length 3 (a, b, c)")
    a, b, c = c_bits
    t = homomorphic_and(a, b)
    out = homomorphic_xor(t, c)
    if not noise_budget_ok(p, out):
        out = refresh_via_decrypt_reencrypt(p, out, q_bits=q_bits, r_bound=r_bound, rng=rng)
    return out
```

Real FHE bootstrapping does **not** decrypt-and-reencrypt. It *homomorphically* evaluates the decryption circuit (or a related refresh transform) to produce a new ciphertext with reduced noise. Here we use a fake refresh to make the budgeting idea obvious in a tiny demo.

Run it:

```bash
python3 code/main.py
```

## Use It

Use a production FHE library rather than implementing anything yourself:

- **Microsoft SEAL** (C++): BFV and CKKS (exact integers mod `t`, and approximate reals)
- **OpenFHE** (C++): BGV, BFV, CKKS, and TFHE-family schemes (plus threshold/multiparty features)
- **HElib** (C++): classic BGV ecosystem
- **TFHE / TFHE-rs** (C++ / Rust): TFHE-style fast boolean/LUT bootstrapping
- **Concrete / Concrete-ML** (Zama): TFHE-oriented tooling, especially for private inference workflows

Rule of thumb:

- If you need exact integer arithmetic and batching: start with BFV/BGV.
- If you need real-valued linear algebra / ML-ish workloads: start with CKKS.
- If you need comparisons, argmax, branching, and exact bit logic: start with TFHE-style (often via LUTs).

## Pitfalls

- Treating FHE as “just encryption”: in practice you must design the computation as a circuit and budget multiplicative depth
- Ignoring ciphertext expansion: ciphertexts can be orders of magnitude larger than plaintexts, affecting bandwidth and storage
- Forgetting key material complexity: evaluation keys (relinearization / rotation / bootstrapping keys) can dominate size and setup time
- Assuming floats are exact: CKKS is *approximate*; accuracy is part of parameter selection and test design
- Expecting secret-dependent branching: “if/else” is not free — it becomes polynomial/LUT work (TFHE) or expensive approximations (CKKS/BFV)

## Ship It

This lesson ships a practical “pick the right tool” artifact:

- `outputs/decision-guide-fhe-vs-mpc.md`

Use it when you’re deciding between:

- FHE vs MPC vs TEEs,
- CKKS vs BFV/BGV vs TFHE,
- and when you want a review checklist before approving an “FHE feature” design.

## Exercises

1. Easy: Run `python3 code/main.py`. Observe how `ciphertext_noise` grows after XOR and AND, and where decryption starts to fail.
2. Medium: Change `ToyDGHVParams(p_bits=..., r_bound=...)` in `code/main.py`. Find a setting where you can do many XORs but only 1–2 AND layers before failure.
3. Hard: Pick a real workload (e.g., private sum, private linear regression step, or private thresholding) and, using the decision guide in `outputs/`, argue which approach (BFV/BGV vs CKKS vs TFHE vs MPC) you’d choose and why.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| Homomorphic encryption | “Compute on encrypted data” | An `Eval` algorithm maps ciphertexts to a ciphertext of the function output without the secret key |
| Circuit depth | “How hard is the computation?” | Roughly, how many multiplication layers are in the computation; the key driver of parameters/runtime |
| Noise | “Random error term” | A small hidden term inside a ciphertext that grows under operations; too much noise breaks decryption |
| Noise budget | “How much compute I can do” | A threshold: once noise exceeds it, decryption becomes incorrect |
| Bootstrapping | “Reset the noise” | A refresh step that produces a new ciphertext of the same plaintext with reduced noise, enabling unbounded depth |
| BFV / BGV | “Exact integer HE” | Schemes for modular arithmetic on encrypted integers (good for exact arithmetic circuits) |
| CKKS | “HE for reals” | Approximate arithmetic scheme for vectors of real/complex values (great for ML-ish workloads) |
| TFHE | “Bitwise HE” | Fast bootstrapped boolean / LUT-based computation (good for comparisons and branching-like logic) |

## Further Reading

- van Dijk, Gentry, Halevi, Vaikuntanathan, *Fully Homomorphic Encryption over the Integers* (2009/2010) — the famous “integers + noise” construction that makes the noise-budget story concrete
- HomomorphicEncryption.org, *Standards / security guidelines* — community parameter guidance and terminology
- OpenFHE team, *OpenFHE documentation and scheme tours* — practical APIs, scheme switching, and multiparty extensions
- Gentry, *Computing Arbitrary Functions of Encrypted Data* (CACM) — readable high-level narrative of the bootstrapping idea
