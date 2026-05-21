# CKKS — Approximate FHE for Real Numbers
> Scale, multiply, rescale: you pay precision to buy depth.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 17 · 01 (What FHE Is — Levels, Schemes, Limits), Phase 17 · 02 (BGV / BFV from Scratch)
**Time:** ~120 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain why CKKS is “approximate” and why scaling is the central mental model.
- Compute quantization error from `scale` and bound the error you should expect after decrypt+decode.
- Implement a toy CKKS simulator with encode/decode, add, mul, and rescale (stdlib-only).
- Distinguish BFV/BGV (exact integers mod `t`) from CKKS (approximate reals with scale + rescale).
- Apply a practical checklist to choose `scale`, rescale schedule, and error tolerance for a real workload.

## The Problem

You want to compute on encrypted data that is inherently **real-valued**: model features, linear algebra, statistics, signal processing. If you force everything into exact modular integers (BFV/BGV), you end up spending huge circuit depth (or complex fixed-point plumbing) to approximate real arithmetic anyway.

CKKS exists because many real-world workloads are already tolerant to small error: ML inference, ranking, recommendation, aggregated analytics, filtering with thresholds that have margin. The trade you accept is explicit: **CKKS gives you fast approximate arithmetic on ciphertexts, and in exchange you must manage precision like a budget.**

Without this lesson, you can “call the CKKS API” in a library, but you can’t reason about what is going on: why your results drift, why multiplication suddenly breaks, why you need rescaling, and why parameter selection feels like tracking a modulus chain and a scale.

## The Concept

### CKKS in one invariant (the mental model)

Ignore the polynomial/ring machinery for a moment. At the “numbers” level, CKKS behaves like:

- You **encode** a real `x` as an integer `m = round(x * scale)`.
- A ciphertext is designed to decrypt to something close to `m` (not exactly): `m + noise`.
- When you **add**, scales must match; noise roughly adds.
- When you **multiply**, the scale multiplies too: if both operands are at scale `S`, the product is at scale `S^2`.
- You then **rescale** to bring the scale back down (and keep numbers bounded). Rescaling spends one “level” of the modulus chain and typically costs some precision.

CKKS system design is basically answering:

1. What `scale` do I want at each point in the circuit?
2. How many multiplies (depth) do I need?
3. How much error can I tolerate at the end?

### Quantization + noise = error

Two sources dominate in simple terms:

1. **Quantization error** from `round(x * scale)` (roughly ≤ `0.5/scale` per encode).
2. **Noise/error growth** from homomorphic operations (especially multiplication + rescale).

This lesson’s code is a *simulator* that makes those effects visible without implementing real RLWE encryption.

## Build It

### Step 1: Encode & decode (scale + rounding)
```python
def round_nearest_int(x: float) -> int:
    x = _require_finite_real("x", x)
    if x >= 0:
        return int(math.floor(x + 0.5))
    return -int(math.floor(-x + 0.5))


def ckks_encode(values: Sequence[float], *, scale: int) -> Plaintext:
    scale = _require_positive_int("scale", scale)
    slots: Slots = [round_nearest_int(_require_finite_real("value", v) * scale) for v in values]
    return Plaintext(slots=slots, scale=scale)


def ckks_decode(pt: Plaintext) -> List[float]:
    if not isinstance(pt, Plaintext):
        raise TypeError("pt must be Plaintext")
    scale = _require_positive_int("pt.scale", pt.scale)
    return [s / scale for s in pt.slots]
```
CKKS starts as “fixed-point”: you pick a `scale` (typically a power of two), multiply reals by it, and round to an integer. Decode divides by the same `scale`. The larger the scale, the smaller the quantization error — but the faster values grow during multiplies.

### Step 2: Encrypt & decrypt (noise = approximation error)
```python
def ckks_encrypt(pt: Plaintext, *, noise_bound: int, seed: int, level: int = 0) -> Ciphertext:
    if not isinstance(pt, Plaintext):
        raise TypeError("pt must be Plaintext")
    noise_bound = _require_nonnegative_int("noise_bound", noise_bound)
    seed = _require_int("seed", seed)
    level = _require_nonnegative_int("level", level)

    rng = random.Random(seed)
    noise = [rng.randint(-noise_bound, noise_bound) for _ in pt.slots]
    slots = [m + e for m, e in zip(pt.slots, noise)]
    return Ciphertext(slots=slots, noise=noise, scale=pt.scale, level=level)


def ckks_decrypt(ct: Ciphertext) -> Plaintext:
    if not isinstance(ct, Ciphertext):
        raise TypeError("ct must be Ciphertext")
    return Plaintext(slots=ct.slots[:], scale=ct.scale)
```
Real CKKS decrypts to an *approximate* scaled integer that contains error (“noise”). This simulator models that directly: encryption adds a small integer noise term per slot; decryption returns those noisy slots. You observe approximation error only after decoding back to floats.

### Step 3: Add in ciphertext space (same scale)
```python
def ckks_add(a: Ciphertext, b: Ciphertext) -> Ciphertext:
    if not isinstance(a, Ciphertext) or not isinstance(b, Ciphertext):
        raise TypeError("a and b must be Ciphertext")
    if a.scale != b.scale:
        raise ValueError("ckks_add: scale mismatch")
    if a.level != b.level:
        raise ValueError("ckks_add: level mismatch")
    _require_same_len(a.slots, b.slots, name="ckks_add")
    slots = [x + y for x, y in zip(a.slots, b.slots)]
    noise = [x + y for x, y in zip(a.noise, b.noise)]
    return Ciphertext(slots=slots, noise=noise, scale=a.scale, level=a.level)
```
Addition is the “easy” operation: you add component-wise. But you must align *both* scale and level (in real libraries: both scale and modulus parameters must be compatible). Noise adds too, so repeated adds still spend error budget.

### Step 4: Multiply + rescale (scale grows, then shrink it)
```python
def ckks_mul(a: Ciphertext, b: Ciphertext) -> Ciphertext:
    if not isinstance(a, Ciphertext) or not isinstance(b, Ciphertext):
        raise TypeError("a and b must be Ciphertext")
    if a.scale != b.scale:
        raise ValueError("ckks_mul: scale mismatch")
    if a.level != b.level:
        raise ValueError("ckks_mul: level mismatch")
    _require_same_len(a.slots, b.slots, name="ckks_mul")

    msg_a = [x - e for x, e in zip(a.slots, a.noise)]
    msg_b = [y - e for y, e in zip(b.slots, b.noise)]
    msg_prod = [x * y for x, y in zip(msg_a, msg_b)]

    slots = [x * y for x, y in zip(a.slots, b.slots)]
    noise = [c - m for c, m in zip(slots, msg_prod)]
    return Ciphertext(slots=slots, noise=noise, scale=a.scale * b.scale, level=a.level)


def round_div_int(num: int, den: int) -> int:
    num = _require_int("num", num)
    den = _require_positive_int("den", den)
    if num >= 0:
        return (num + den // 2) // den
    return -((-num + den // 2) // den)


def ckks_rescale(ct: Ciphertext, *, factor: int) -> Ciphertext:
    if not isinstance(ct, Ciphertext):
        raise TypeError("ct must be Ciphertext")
    factor = _require_positive_int("factor", factor)
    if ct.scale % factor != 0:
        raise ValueError("ckks_rescale: factor must divide ct.scale exactly in this toy model")

    slots = [round_div_int(x, factor) for x in ct.slots]
    noise = [round_div_int(e, factor) for e in ct.noise]
    return Ciphertext(slots=slots, noise=noise, scale=ct.scale // factor, level=ct.level + 1)
```
After multiplication, both the (scaled) message and the noise get multiplied, so the scale becomes `S^2`. Rescaling divides by a factor (in real CKKS: a ciphertext modulus prime), bringing the scale back down while also transforming the noise. In this toy model we rescale by an integer `factor` and bump `level` to represent consuming a modulus level.

Run it:
python3 code/main.py

## Use It

Production CKKS lives in mature libraries that implement RLWE over polynomial rings, RNS modulus chains, NTTs, key switching, and bootstrapping (sometimes).

Common choices:
- Microsoft SEAL: CKKS encoder/decoder, evaluator API, rescale/modswitch utilities.
- OpenFHE: multiple schemes including CKKS with a parameter selection layer.
- Lattigo (Go): CKKS and related approximate schemes, widely used in FHE prototyping.

What to map from this lesson to a real API:
- `scale`: CKKS ciphertext/plaintext scale you must track and align.
- `level`: where you are in the modulus chain; rescale consumes a level.
- `rescale`: the operation that brings scale back down after mul (and changes modulus).

## Pitfalls

- Treating CKKS outputs as exact: if your application needs exact equality, CKKS is the wrong tool (use BFV/BGV or bit-based TFHE, or redesign the protocol).
- Forgetting scale alignment: adding ciphertexts with different scales (or wrong modulus chain positions) silently produces nonsense in some libraries or fails at runtime.
- Not rescaling after multiplication: scale grows as `S^2`, quickly overflowing parameter headroom and causing decryption to lose most significant bits.
- Comparing against plaintext with unrealistic tolerances: evaluation should be `abs(err) <= tolerance`, where tolerance matches downstream sensitivity.
- Parameter “optimism”: choosing too small a modulus chain / poly degree so that the circuit depth fits on paper but fails under real noise growth and rotations.

## Ship It

Save `outputs/ckks-precision-and-parameter-checklist.md` somewhere you can paste into PRs.

Use it as:
- a design-time decision guide (is CKKS appropriate? what tolerance is acceptable?),
- a review checklist for “scale/level/rescale” correctness,
- a prompt to demand concrete error budgets and test cases before shipping.

## Exercises

1. Easy: Run `python3 code/main.py`. Observe how quantization error changes if you change `scale` from `2**10` to `2**15`.
2. Medium: Add a function `ckks_add_plain(ct, pt)` that adds an encoded plaintext vector to a ciphertext (same scale). Add vectors + tests for it.
3. Hard: Pick a small polynomial approximation (e.g., `x^2 + 0.5x`) and evaluate it homomorphically using `ckks_mul` + `ckks_add`, rescaling as needed. Track how error grows across the circuit.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| CKKS | “FHE for real numbers” | Approximate arithmetic where decrypt+decode returns a real value with bounded error |
| Scale | “Fixed-point precision” | The factor `S` used to map reals to integers via `round(x*S)` |
| Slot packing | “SIMD ciphertext” | One ciphertext holds a vector of values; operations apply elementwise (plus rotations for mixing) |
| Rescale | “Bring scale back down” | Dividing by a modulus prime (conceptually) to reduce scale and move down the modulus chain |
| Level | “How much depth is left” | Position in the modulus chain; rescale/modswitch consumes levels |

## Further Reading

- Cheon et al., *Homomorphic Encryption for Arithmetic of Approximate Numbers* (2017) — the original CKKS paper; defines encoding, rescaling, and error analysis.
- Microsoft SEAL Manual, *CKKS Basics* — practical guidance on scale, rescale, and parameter selection in a real library.
- OpenFHE documentation, *CKKS scheme* — engineering-oriented view of levels, rescaling, and supported ops.
