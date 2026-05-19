# Min-Entropy, Shannon Entropy, Renyi Entropy

> Shannon counts symbols on average; min-entropy counts what the attacker guesses first.

**Type:** Learn
**Languages:** Python
**Prerequisites:** Phase 05 · 01 (Probability Basics) · 02 (Statistical Distance)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Distinguish Shannon entropy, min-entropy, collision entropy, and max-entropy and state when each is the right choice.
- Explain why min-entropy, not Shannon entropy, is the security-relevant quantity for keys and RNGs.
- Compute the Rényi family H_α and verify the monotone-decreasing-in-α property.
- Apply the Leftover Hash Lemma to size an extractor: L ≤ H_∞ − 2·log₂(1/ε).
- Identify the three classic entropy mistakes in RNG specs and KDF pipelines.

## The Problem

"How much randomness is in this key?" sounds like one question, but it is at
least three:

- *How compressible is the source?* — **Shannon entropy** `H(X)`.
- *How hard is it to guess in one shot?* — **min-entropy** `H_∞(X)`.
- *How often do two samples collide?* — **collision (Rényi-2) entropy** `H_2(X)`.

Cryptographers care about **min-entropy** because adversaries are
guess-first, not average-case. A passphrase generator with `H = 60` bits but
`H_∞ = 20` is a 1-in-a-million key. Quoting Shannon entropy as a security
parameter is one of the most common entropy mistakes in the wild.

This lesson installs the entropy zoo with crypto-aware reflexes: which one to
use, when, and how they relate.

## The Concept

### Shannon entropy

```
H(X) = -Σ_x p(x) log2 p(x)        (units: bits)
```

Average number of bits needed to describe a sample. Tight for compression
(Shannon source coding theorem). For a fair coin, `H = 1`. For a fair `n`-way
die, `H = log2 n`.

### Min-entropy

```
H_∞(X) = -log2 max_x p(x)
```

`H_∞ = k` means the best guesser succeeds with probability `2^-k` on the
first try. This is the entropy that bounds **guessing attacks** and feeds
randomness extractors.

### Collision entropy (Rényi-2)

```
H_2(X) = -log2 Σ_x p(x)^2
```

`Σ p(x)^2` is the collision probability of two independent samples. Comes up
in birthday bounds, hashing, and the leftover hash lemma.

### Max-entropy (Rényi-0)

```
H_0(X) = log2 |support(X)|
```

Just the log of the support size. Sets the upper bound for everything below.

### Rényi family

The full family:

```
H_α(X) = (1 / (1 - α)) · log2 Σ_x p(x)^α        (α ≥ 0, α ≠ 1)
```

Special cases:

| α | Name | Formula | Use |
|---|------|---------|-----|
| 0 | Hartley / max-entropy | `log2 |supp|` | upper bound |
| 1 | Shannon | `-Σ p log2 p` | compression / channel capacity |
| 2 | Collision | `-log2 Σ p^2` | birthday bounds, leftover hash |
| ∞ | Min-entropy | `-log2 max p` | **crypto security** |

Key fact: `H_α` is **monotone decreasing** in `α`. So

```
H_∞(X) ≤ H_2(X) ≤ H_1(X) ≤ H_0(X)
```

The cryptographically *honest* number is always the smallest of these.

### KL divergence (relative entropy)

```
D(P || Q) = Σ_x p(x) log2 (p(x) / q(x))
```

Bits "wasted" if you code `P` using a code optimal for `Q`. **Not** a metric:
asymmetric, can be `+∞` when `Q` puts zero mass where `P` puts mass. Lower-
bounds statistical distance via Pinsker:

```
SD(P, Q) ≤ sqrt( (ln 2 / 2) · D(P || Q) )
```

### Mutual information & conditional entropy

For a joint distribution `P(X, Y)`:

```
I(X; Y) = H(X) + H(Y) - H(X, Y) = D( P(X,Y) || P(X)·P(Y) )
H(X | Y) = H(X, Y) - H(Y)
I(X; Y) = H(X) - H(X | Y)
```

`I(X; Y) = 0` iff `X` and `Y` are independent. In side-channel analysis,
`I(secret; leakage)` measures how much the leakage knows about the secret.

### Why min-entropy, not Shannon, for keys

A toy generator that outputs `0` with probability `0.99` and a uniformly
random 127-bit string with probability `0.01`:

- `H ≈ 0.08 + 0.01·127 ≈ 1.35` (close to zero — looks bad)
- `H_∞ ≈ -log2 0.99 ≈ 0.0145` (catastrophic — best guess `0`)

Shannon undersells *and* oversells depending on the distribution. Min-entropy
always speaks the attacker's language.

### Leftover Hash Lemma (operational summary)

If `H_∞(X) ≥ k` and you apply a uniformly chosen 2-universal hash `h` with
output length `L`, then `(h, h(X))` is `ε`-close to uniform on `(seed × {0,1}^L)`
provided

```
L ≤ k - 2·log2(1/ε)
```

Rule of thumb: to extract `L` bits at statistical security `2^-s`, you need
`H_∞ ≥ L + 2s` raw bits.

## Build It

### Step 1: the named entropies

```python
def shannon_entropy(pmf):
    return -sum(p * math.log2(p) for p in pmf.values() if p > 0)

def min_entropy(pmf):
    return -math.log2(max(pmf.values()))

def collision_entropy(pmf):
    return -math.log2(sum(p * p for p in pmf.values()))

def max_entropy(pmf):
    return math.log2(sum(1 for p in pmf.values() if p > 0))
```

Each takes a PMF and returns bits. All four differ; pick the right one for the threat model.

### Step 2: Rényi family

```python
def renyi_entropy(pmf, alpha):
    if math.isinf(alpha): return min_entropy(pmf)
    if alpha == 0:         return max_entropy(pmf)
    if alpha == 1:         return shannon_entropy(pmf)
    s = sum(p ** alpha for p in pmf.values() if p > 0)
    return (1.0 / (1.0 - alpha)) * math.log2(s)
```

Dispatching special cases keeps the formula numerically stable at `α → 1`.

### Step 3: KL divergence and mutual information

```python
def kl_divergence(p, q):
    total = 0.0
    for x, px in p.items():
        if px <= 0: continue
        qx = q.get(x, 0.0)
        if qx <= 0: return math.inf
        total += px * math.log2(px / qx)
    return total

def mutual_information(pxy):
    px = marginal(pxy, axis=0)
    py = marginal(pxy, axis=1)
    return shannon_entropy(px) + shannon_entropy(py) - shannon_entropy(pxy)
```

### Step 4: crypto helpers

```python
def guessing_probability(pmf):
    return max(pmf.values())          # = 2^{-H_∞}

def extractable_bits(min_ent, *, security=80.0):
    return max(0.0, min_ent - 2.0 * security)  # Leftover Hash Lemma
```

Run it:

```
python3 code/main.py
```

## Use It

In production tooling:

- `scipy.stats.entropy` computes Shannon entropy (and KL with `qk=`).
- NIST SP 800-90B specifies **min-entropy** estimators for hardware RNGs —
  not Shannon. If your NIST submission reports Shannon, it is wrong.
- `secrets.token_bytes(32)` assumes the OS RNG already has `≥ 256` bits of
  min-entropy. Linux's `getrandom(2)` blocks early-boot until enough has been
  accumulated, precisely so this assumption holds.

This lesson's implementations mirror the textbook formulas — useful for
inspecting small examples and unit-testing entropy estimators.

## Attack It

Three classic entropy mistakes that have shipped:

1. **Reporting Shannon for an RNG.** Multiple early TRNG submissions claimed
   `H ≈ 0.9` bits/sample and shipped. Adversary's best guess probability is
   `2^-H_∞`, not `2^-H`. (NIST SP 800-90B fixed the spec — many products had
   to redesign.)
2. **Re-using a "high-entropy" pool past extraction.** Once you've extracted
   `L` bits via a hash, the residual min-entropy of the pool drops by `L`.
   Treating the pool as still-full is how Debian-style RNG bugs become
   key-recovery bugs.
3. **Concatenating entropies.** `H_∞(X, Y) ≤ H_∞(X) + H_∞(Y)` only with
   independence. Correlated sources double-count.

## Ship It

This lesson ships a reusable review prompt:

- `outputs/prompt-entropy-audit.md`

Use it when reviewing RNG specs, key-derivation pipelines, or any claim of
"X bits of entropy".

## Exercises

1. Easy: compute `H`, `H_2`, `H_∞` for the distribution `{a: 0.5, b: 0.25,
   c: 0.125, d: 0.125}`. Verify `H_∞ ≤ H_2 ≤ H`.
2. Medium: show analytically that `H_∞(X, Y) ≥ H_∞(X) + H_∞(Y | X)` is
   *false* in general by constructing a counterexample. (Hint: collisions.)
3. Hard: simulate a length-`n` source that outputs a fixed string with
   probability `1 - 2^-n` and a uniform `n`-bit string otherwise. Plot `H`
   vs `H_∞` as `n` grows. Which one tracks security?

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| entropy | "randomness" | depends — Shannon? min? collision? |
| Shannon entropy | "average bits" | `-Σ p log2 p` (compression bound) |
| min-entropy | "guess-first bits" | `-log2 max_x p(x)` (crypto-relevant) |
| collision entropy | "Renyi-2" | `-log2 Σ p^2` (birthday / LHL) |
| KL divergence | "distance" | not a metric; relative entropy |
| mutual information | "shared bits" | `H(X) + H(Y) - H(X, Y)` |
| leftover hash lemma | "extract a key" | `L ≤ H_∞ - 2 log2(1/ε)` |

## Test Vectors

Source: definitions of Shannon, min, collision, max entropy and KL.

Code must pass all vectors in `tests/vectors.json`.

## Further Reading

- [Shannon, *A Mathematical Theory of Communication* (1948)](https://people.math.harvard.edu/~ctm/home/text/others/shannon/entropy/entropy.pdf)
- [NIST SP 800-90B — Min-entropy estimation for RNGs](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90B.pdf)
- [Vadhan, *Pseudorandomness*, Chapter 6 — randomness extractors](https://people.seas.harvard.edu/~salil/pseudorandomness/)
- [Cover & Thomas, *Elements of Information Theory*](https://onlinelibrary.wiley.com/doi/book/10.1002/047174882X)
