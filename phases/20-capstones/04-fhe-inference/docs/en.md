# Build an FHE Inference Service

> The server runs your ML model on data it can never read.

**Type:** Build
**Languages:** Python
**Prerequisites:** BFV/BGV FHE schemes, homomorphic addition/multiplication, polynomial rings
**Time:** ~90 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain the BFV ciphertext structure and why it supports homomorphic addition and scalar multiplication
- Implement keygen, encrypt, and decrypt for a toy BFV-like scheme over integers mod q
- Compose homo_add and homo_scalar_mul to evaluate a linear expression on encrypted inputs
- Reason about noise budget: why plaintext modulus t, ciphertext modulus q, and noise bound B must be co-designed
- Identify the gap between this toy scheme and a production FHE library (polynomial rings, bootstrapping, relinearization)

## The Problem

A hospital wants to outsource ML inference: a cloud provider runs a trained model to triage incoming patient records. The trouble is the records are sensitive — the cloud provider should never see plaintext data, even during computation. Standard encryption does not help: you must decrypt before you can compute, so the cloud sees everything.

Fully Homomorphic Encryption (FHE) flips this around. The client encrypts its inputs, sends the ciphertexts to the server, and the server evaluates the model directly on the ciphertexts — producing an encrypted result. The server learns nothing about the inputs or the output. Only the client, holding the secret key, can decrypt the final answer.

This pattern is not science fiction. Libraries like SEAL, OpenFHE, and Concrete already run neural networks, logistic regression, and SQL queries on encrypted data at practical (if not yet fast) speeds. Understanding the mechanics from scratch — key structure, noise growth, encoding — prepares you to use those libraries deliberately rather than by cargo-cult.

## The Concept

**BFV structure.** A BFV-like ciphertext encrypting a plaintext `m` is a pair `(c0, c1)` where:

```
c0 = b*r + e0 + encode(m)  mod q
c1 = a*r + e1              mod q
```

`a` is a random public vector, `b = -<a,s> + e_pk` is the public key (derived from secret `s`), `r` is a random masking scalar, and `e0`, `e1` are tiny noise terms. Decryption recovers `m` by computing:

```
v = c0 + <c1, s>  mod q
  = encode(m) + noise
m = round(v / Delta)  mod t
```

where `Delta = round(q/t)` is the scaling factor that "lifts" the plaintext into the most significant bits of `Z_q`.

**Homomorphic addition** works because ciphertexts are linear in the message:

```
homo_add((c0_a, c1_a), (c0_b, c1_b)) = (c0_a + c0_b mod q,  c1_a + c1_b mod q)
```

Decrypting the sum gives `encode(a) + encode(b) + noise_a + noise_b`, which rounds to `a + b` so long as total noise stays below `q / (2t)`.

**Scalar multiplication** by a public integer `w` simply scales both components:

```
homo_scalar_mul((c0, c1), w) = (c0*w mod q,  c1*w mod q)
```

Noise is also scaled by `|w|`. This is why large weights erode the noise budget.

**Noise budget.** Every operation adds noise. Fresh encryption contributes ~`B` noise. A scalar mul by `w` multiplies that noise by `|w|`. A final addition accumulates all the terms. As long as total noise < `q / (2t)`, decryption is exact. Pick q large enough and t/B small enough that the worst-case evaluation fits within budget.

**Linear classifier.** Given public weights `(w_0, …, w_{k-1})` and an encrypted bias `enc(bias)`, the encrypted score is:

```
enc(score) = sum_i( w_i * enc(x_i) ) + enc(bias)
```

The server does this entirely in ciphertext space. The client decrypts only the final score, learns the class (`score > 0 → class 1`), and the server never learns either the inputs or the output.

## Build It

### Step 1: Parameters and helpers

```python
T = 1 << 16          # plaintext modulus
Q = 1 << 48          # ciphertext modulus
N = 8                # key dimension
B = 8                # noise bound (samples from [-B, B])
T_HALF = T >> 1

def _mod_centered(x: int, m: int) -> int:
    """Symmetric-range modular reduction: result in (-m/2, m/2]."""
    r = x % m
    if r > m // 2:
        r -= m
    return r

def _sample_noise(rng: random.Random, bound: int) -> int:
    return rng.randint(-bound, bound)

def _sample_ternary(rng: random.Random) -> int:
    return rng.randint(-1, 1)
```

`T` and `Q` are co-designed so that `Q / (2*T) = 2^31` — plenty of headroom for the cumulative noise from four scalar multiplications by weights up to 150.

### Step 2: Key generation

```python
class SecretKey:
    def __init__(self, s: Tuple[int, ...]) -> None:
        if len(s) != N:
            raise ValueError(f"SecretKey requires length-{N} vector")
        self.s = s

class PublicKey:
    def __init__(self, a: Tuple[int, ...], b: int) -> None:
        if len(a) != N:
            raise ValueError(f"PublicKey requires length-{N} a-vector")
        self.a = a
        self.b = b

def keygen(rng: random.Random) -> Tuple[SecretKey, PublicKey]:
    s = tuple(_sample_ternary(rng) for _ in range(N))
    a = tuple(rng.randint(0, Q - 1) for _ in range(N))
    e = _sample_noise(rng, B)
    dot_as = sum(ai * si for ai, si in zip(a, s)) % Q
    b = (-dot_as + e) % Q
    return SecretKey(s), PublicKey(a, b)
```

The secret key `s` has ternary entries `{-1, 0, 1}` — small enough that `<c1, s>` stays bounded. The public key `b` hides `s` under the LWE hardness assumption: given `(a, b)`, recovering `s` is computationally hard when `a` is uniform and `e` is small.

### Step 3: Encrypt and decrypt

```python
def _delta() -> int:
    return (Q + T // 2) // T

def _encode(m: int) -> int:
    delta = _delta()
    return (m % T) * delta % Q

def _decode(v: int) -> int:
    delta = _delta()
    v_sym = _mod_centered(v, Q)
    m_raw = (v_sym + delta // 2) // delta if v_sym >= 0 else -((-v_sym + delta // 2) // delta)
    return _mod_centered(m_raw, T)

def encrypt(pk: PublicKey, m: int, rng: random.Random) -> Ciphertext:
    r = _sample_ternary(rng)
    e0 = _sample_noise(rng, B)
    e1 = tuple(_sample_noise(rng, B) for _ in range(N))
    m_enc = _encode(m % T)
    c0 = (pk.b * r + e0 + m_enc) % Q
    c1 = tuple((pk.a[i] * r + e1[i]) % Q for i in range(N))
    return c0, c1

def decrypt(sk: SecretKey, ct: Ciphertext) -> int:
    c0, c1 = ct
    dot = sum(c1[i] * sk.s[i] for i in range(N)) % Q
    v = (c0 + dot) % Q
    return _decode(v)
```

`_decode` uses symmetric-range reduction to return signed integers — essential for the classifier, where scores can be negative.

### Step 4: Homomorphic operations

```python
def homo_add(ct_a: Ciphertext, ct_b: Ciphertext) -> Ciphertext:
    c0_a, c1_a = ct_a
    c0_b, c1_b = ct_b
    c0 = (c0_a + c0_b) % Q
    c1 = tuple((c1_a[i] + c1_b[i]) % Q for i in range(N))
    return c0, c1

def homo_scalar_mul(ct: Ciphertext, scalar: int) -> Ciphertext:
    c0, c1 = ct
    c0_new = (c0 * scalar) % Q
    c1_new = tuple((c1[i] * scalar) % Q for i in range(N))
    return c0_new, c1_new
```

Both operations are exact modular arithmetic — no approximation, no key material needed. The noise simply accumulates.

### Step 5: Linear inference

```python
MODEL_WEIGHTS: Tuple[int, ...] = (3, 5, 8, 150)
MODEL_BIAS: int = -400
THRESHOLD: int = 0

def homo_linear(
    encrypted_inputs: Tuple[Ciphertext, ...],
    weights: Tuple[int, ...],
    encrypted_bias: Ciphertext,
) -> Ciphertext:
    if len(encrypted_inputs) != len(weights):
        raise ValueError("inputs and weights must have the same length")
    result = encrypted_bias
    for enc_x, w in zip(encrypted_inputs, weights):
        term = homo_scalar_mul(enc_x, w)
        result = homo_add(result, term)
    return result
```

The server calls `homo_linear` with the client's encrypted features and its own encrypted bias. It returns an encrypted score. The client decrypts it and applies the threshold — never trusting the server with any plaintext.

Run it:
```
python3 code/main.py
```

## Use It

Production FHE for ML inference uses:

- **CKKS** (not BFV) for approximate real-valued arithmetic — standard for neural networks.
- **Polynomial rings** `Z_q[x]/(x^n + 1)` instead of integer vectors — enables SIMD batching of thousands of values per ciphertext.
- **Bootstrapping** to refresh the noise budget mid-circuit, enabling deep models.
- **Relinearization** and **key switching** to handle ciphertext-ciphertext products (needed for ReLU approximations).

Libraries: Microsoft SEAL, OpenFHE, Zama's Concrete (targets neural nets end-to-end), TFHE-rs (gate-level FHE in Rust).

## Pitfalls

- Noise budget overflow: choosing `q` too small for the circuit depth causes decryption garbage with no obvious error.
- Signed plaintext confusion: forgetting that `_decode` returns values in `(-T/2, T/2]` and comparing against an unsigned threshold.
- Encoding mismatch: multiplying plaintexts without accounting for the `Delta` scaling causes the decoded result to be off by a factor of `Delta`.
- Large weights: a weight of 10000 multiplies noise by 10000; with `B=8` and 4 features, total noise reaches 320000 — fine here but borderline for larger models.
- Fixed-seed RNG in production: this demo uses `random.Random(42)` for reproducibility. Real encryption must use a cryptographically secure RNG.

## Ship It

Save the FHE readiness checklist to `outputs/fhe-readiness-checklist.md`. Use it before deciding whether a given use case is a good candidate for FHE.

## Exercises

1. Easy. Run `python3 code/main.py` and verify that the FHE scores match the plaintext scores exactly for both persons.
2. Medium. Add a fifth feature (`occupation_score`, range 1–10, weight 20) to the model. Recheck the noise budget and confirm decryption still works.
3. Hard. Replace the ternary secret key `s` with a binary key `{0, 1}^n`. Measure the change in decryption correctness across 1000 random encryptions of random messages. Explain the result.

## Key Terms

| Term | What people say | What it actually means |
|------|-----------------|------------------------|
| BFV | "A somewhat-HE scheme" | A levelled FHE scheme where messages are integers mod t lifted by Delta = q/t into Z_q |
| LWE | "The hardness assumption" | Learning With Errors: distinguishing `(a, <a,s>+e)` from uniform is believed computationally hard |
| Noise budget | "How deep a circuit can be" | The margin `q/(2t) - current_noise`; hits zero when decryption fails |
| Delta | "The scaling factor" | `round(q/t)`; places plaintext in the high-order bits of the ciphertext modulus |
| Scalar-ciphertext mul | "Plaintext-ciphertext multiplication" | Multiplying both ciphertext components by a public integer; noise scales by the scalar |
| Ternary secret key | "Small secret" | Entries in {-1, 0, 1}; keeps the inner product `<c1, s>` bounded to control decryption noise |

## Further Reading

- Fan & Vercauteren, "Somewhat Practical Fully Homomorphic Encryption" (2012) — the BFV scheme paper
- Cheon et al., "Homomorphic Encryption for Arithmetic of Approximate Numbers" (2017) — CKKS, the standard for ML
- Boura et al., "CHIMERA: Combining Ring-LWE-based Fully Homomorphic Encryption Schemes" (2020) — scheme comparison
- Zama, "Concrete ML" documentation — end-to-end FHE ML inference using quantized neural networks
