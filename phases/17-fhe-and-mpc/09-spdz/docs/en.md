# SPDZ from Scratch — Active Security with Preprocessing

> Authenticate shares, preprocess randomness, catch cheaters.

**Type:** Build  
**Languages:** Python  
**Prerequisites:** Phase 02 · 07 (Finite Fields GF(p)), Phase 17 · 08 (BGW — arithmetic secret sharing)  
**Time:** ~120 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** why SPDZ splits work into an offline “preprocessing” phase and an online “compute” phase.
- **Compute** how additive shares reconstruct a secret value in a prime field.
- **Implement** Beaver-triple multiplication over additive shares.
- **Distinguish** semi-honest safety (“privacy”) from malicious safety (“privacy + tamper detection”) in MPC.
- **Apply** authenticated shares + MAC-checked openings to evaluate a small arithmetic expression.

## The Problem

You want multiple parties to compute something *useful* on private inputs: a joint risk score, a shared fraud model update, a private auction clearing price, or a collaborative analytics query. Secret sharing gives privacy, but privacy alone is not enough in real systems.

In the real world, one party might be buggy or actively malicious: send the wrong share, reuse preprocessing material, or try to bias the result while still learning nothing about others’ inputs. If your MPC only assumes “semi-honest” behavior, a single deviating participant can silently corrupt outputs.

SPDZ-style protocols address this by *authenticating* every secret-shared value with an information-theoretic MAC under a global key **α** that no party knows in full. When you open values (or when the protocol requires opening masked values), a MAC check detects tampering and forces an abort.

## The Concept

We work over a prime field **Fₚ**. Additive secret sharing represents a secret `x` as random-looking shares `(x₁, …, xₙ)` such that:

`x = x₁ + x₂ + … + xₙ (mod p)`.

To get malicious security, SPDZ adds a global MAC key **α** (itself additively shared as `α = Σ αᵢ`) and stores, for every shared `x`, *MAC shares* `(m₁, …, mₙ)` such that:

`m₁ + … + mₙ = α · x (mod p)`.

This pair `[[x]]ᵢ = (xᵢ, mᵢ)` is an **authenticated share**.

### Opening with a MAC check

If parties reconstruct the value `x` by summing `xᵢ`, they must also verify it wasn’t tampered with.

Each party locally computes:

`δᵢ = mᵢ − αᵢ · x (mod p)`

and then the parties open `δ = Σ δᵢ`. If `δ != 0`, something is inconsistent and the protocol aborts. Intuition: a cheater who changes `x` must also change the MAC by `α·Δ`, but **α is unknown** to them, so they can’t forge the right correction except with ~`1/p` probability.

### Multiplication with preprocessing (Beaver triples)

Addition is “free” locally, but multiplication needs interaction. SPDZ uses preprocessed **Beaver triples**:

`([[a]], [[b]], [[c]])` with `c = a·b (mod p)`,

generated in the offline phase. To multiply `[[x]]·[[y]]` online, the parties open:

`d = open([[x]] − [[a]])` and `e = open([[y]] − [[b]])`

and then compute (locally, using only additions and public-scalar multiplies):

`[[x·y]] = [[c]] + d·[[b]] + e·[[a]] + d·e`.

In this lesson we simulate the math in a single process and use a “dealer” to generate authenticated shares and triples. Real implementations generate them collaboratively (e.g., with HE/OT-based preprocessing).

## Build It

### Step 1: Prime-field arithmetic + deterministic RNG
We’ll do everything modulo a prime `p`. The RNG is deterministic so `tests/vectors.json` can hardcode expected outputs.

```python
PRIME = 2_147_483_647  # 2^31 - 1 (prime)


def mod(x: int, p: int = PRIME) -> int:
    return x % p


def mod_add(a: int, b: int, p: int = PRIME) -> int:
    return (a + b) % p


def mod_sub(a: int, b: int, p: int = PRIME) -> int:
    return (a - b) % p


def mod_mul(a: int, b: int, p: int = PRIME) -> int:
    return (a * b) % p


class DeterministicRng:
    def __init__(self, seed: bytes):
        self._seed = seed
        self._ctr = 0

    def randbelow(self, n: int) -> int:
        if n <= 0:
            raise ValueError("n must be positive")
        h = hashlib.sha256(self._seed + self._ctr.to_bytes(8, "big")).digest()
        self._ctr += 1
        return int.from_bytes(h, "big") % n
```

This gives us a stable field and stable randomness for demos and tests.

### Step 2: Additive secret sharing
We share a secret `x` into `n` pieces that sum to `x (mod p)` and reconstruct by summing the shares.

```python
def additive_share(secret: int, n: int, p: int, rng: DeterministicRng) -> List[int]:
    if n < 2:
        raise ValueError("need at least 2 parties")
    secret = mod(secret, p)
    shares = [rng.randbelow(p) for _ in range(n - 1)]
    last = mod(secret - sum(shares), p)
    return shares + [last]


def reconstruct(shares: Iterable[int], p: int) -> int:
    return mod(sum(shares), p)
```

This is the basic “privacy” layer: any strict subset of shares looks random.

### Step 3: Multiply shares with Beaver triples (semi-honest)
Beaver triples turn one multiplication into two openings (`d`, `e`) plus local arithmetic. This version is *not* maliciously secure yet — it’s the stepping stone.

```python
def beaver_triple_shares(n: int, p: int, rng: DeterministicRng) -> Tuple[List[int], List[int], List[int]]:
    a = rng.randbelow(p)
    b = rng.randbelow(p)
    c = mod_mul(a, b, p)
    return (
        additive_share(a, n, p, rng),
        additive_share(b, n, p, rng),
        additive_share(c, n, p, rng),
    )


def beaver_multiply_shares(
    x_shares: Sequence[int],
    y_shares: Sequence[int],
    triple: Tuple[Sequence[int], Sequence[int], Sequence[int]],
    p: int,
) -> List[int]:
    n = len(x_shares)
    if len(y_shares) != n:
        raise ValueError("mismatched party counts")
    a_shares, b_shares, c_shares = triple
    if len(a_shares) != n or len(b_shares) != n or len(c_shares) != n:
        raise ValueError("triple party count mismatch")

    d = reconstruct((mod_sub(x_shares[i], a_shares[i], p) for i in range(n)), p)
    e = reconstruct((mod_sub(y_shares[i], b_shares[i], p) for i in range(n)), p)

    out = []
    for i in range(n):
        zi = c_shares[i]
        zi = mod_add(zi, mod_mul(d, b_shares[i], p), p)
        zi = mod_add(zi, mod_mul(e, a_shares[i], p), p)
        out.append(zi)
    out[0] = mod_add(out[0], mod_mul(d, e, p), p)
    return out
```

The `d·e` term is public, so we can add it to a single share (party `0`) to keep the sum correct.

### Step 4: Authenticated shares + MAC-checked opening
Now we add the “active security” layer: every shared value has MAC shares consistent with a global key `α = Σ αᵢ`.

```python
@dataclass(frozen=True)
class AuthShare:
    value: int
    mac: int


def spdz_setup_alpha_shares(n: int, p: int, rng: DeterministicRng) -> List[int]:
    alpha = rng.randbelow(p)
    return additive_share(alpha, n, p, rng)


def _auth_share_secret_dealer(secret: int, alpha_shares: Sequence[int], p: int, rng: DeterministicRng) -> List[AuthShare]:
    n = len(alpha_shares)
    alpha = reconstruct(alpha_shares, p)
    secret = mod(secret, p)
    mac_total = mod_mul(alpha, secret, p)
    v_shares = additive_share(secret, n, p, rng)
    m_shares = additive_share(mac_total, n, p, rng)
    return [AuthShare(value=v_shares[i], mac=m_shares[i]) for i in range(n)]


def auth_add(x: Sequence[AuthShare], y: Sequence[AuthShare], p: int) -> List[AuthShare]:
    if len(x) != len(y):
        raise ValueError("mismatched party counts")
    return [AuthShare(mod_add(x[i].value, y[i].value, p), mod_add(x[i].mac, y[i].mac, p)) for i in range(len(x))]


def auth_sub(x: Sequence[AuthShare], y: Sequence[AuthShare], p: int) -> List[AuthShare]:
    if len(x) != len(y):
        raise ValueError("mismatched party counts")
    return [AuthShare(mod_sub(x[i].value, y[i].value, p), mod_sub(x[i].mac, y[i].mac, p)) for i in range(len(x))]


def auth_mul_public(x: Sequence[AuthShare], k: int, p: int) -> List[AuthShare]:
    k = mod(k, p)
    return [AuthShare(mod_mul(s.value, k, p), mod_mul(s.mac, k, p)) for s in x]


def auth_add_public(
    x: Sequence[AuthShare],
    c: int,
    alpha_shares: Sequence[int],
    p: int,
    party_index: int = 0,
) -> List[AuthShare]:
    if len(x) != len(alpha_shares):
        raise ValueError("mismatched party counts")
    n = len(x)
    c = mod(c, p)
    out = []
    for i in range(n):
        dv = c if i == party_index else 0
        dm = mod_mul(alpha_shares[i], c, p)
        out.append(AuthShare(mod_add(x[i].value, dv, p), mod_add(x[i].mac, dm, p)))
    return out


def spdz_open(x: Sequence[AuthShare], alpha_shares: Sequence[int], p: int) -> int:
    if len(x) != len(alpha_shares):
        raise ValueError("mismatched party counts")
    opened = reconstruct((s.value for s in x), p)
    deltas = [mod_sub(x[i].mac, mod_mul(alpha_shares[i], opened, p), p) for i in range(len(x))]
    check = reconstruct(deltas, p)
    if check != 0:
        raise ValueError("MAC check failed (tampering detected)")
    return opened
```

The key point: `spdz_open()` is *not* just reconstruction — it is reconstruction **plus** a MAC check.

### Step 5: SPDZ-style multiplication + tamper detection
We upgrade Beaver triples to authenticated triples and use `spdz_open()` to open `d` and `e` safely.

```python
def beaver_triple_auth_shares(
    alpha_shares: Sequence[int],
    p: int,
    rng: DeterministicRng,
) -> Tuple[List[AuthShare], List[AuthShare], List[AuthShare]]:
    n = len(alpha_shares)
    a = rng.randbelow(p)
    b = rng.randbelow(p)
    c = mod_mul(a, b, p)
    return (
        _auth_share_secret_dealer(a, alpha_shares, p, rng),
        _auth_share_secret_dealer(b, alpha_shares, p, rng),
        _auth_share_secret_dealer(c, alpha_shares, p, rng),
    )


def spdz_multiply(
    x: Sequence[AuthShare],
    y: Sequence[AuthShare],
    triple: Tuple[Sequence[AuthShare], Sequence[AuthShare], Sequence[AuthShare]],
    alpha_shares: Sequence[int],
    p: int,
) -> List[AuthShare]:
    a, b, c = triple
    d = spdz_open(auth_sub(x, a, p), alpha_shares, p)
    e = spdz_open(auth_sub(y, b, p), alpha_shares, p)

    out = list(c)
    out = auth_add(out, auth_mul_public(b, d, p), p)
    out = auth_add(out, auth_mul_public(a, e, p), p)
    out = auth_add_public(out, mod_mul(d, e, p), alpha_shares, p, party_index=0)
    return out
```

Run it:

`python3 code/main.py`

## Use It

Production SPDZ-family MPC is not a “few functions” task — it’s a full system (networking, preprocessing, sacrifice/checking, scheduling, fixed-point, I/O, and side-channel hardening). Use a real framework:

- **MP-SPDZ**: multiple SPDZ-family protocols (prime field and 2ᵏ rings), multiple preprocessing backends, compiler + runtime.
- **SCALE-MAMBA / SPDZ-2**: research systems that popularized “SPDZ-style” offline/online structure and compiler support.

When reading production code, look for the same building blocks you implemented here:

- authenticated shares `([[x]]ᵢ = (xᵢ, mᵢ))`,
- MAC-checked openings,
- preprocessing material (triples, randoms, bits, etc.),
- “use each triple once” discipline.

## Pitfalls

- **Forgetting to MAC-check after opening**: opening without checking turns “malicious” into “semi-honest” (silently wrong outputs).
- **Reusing Beaver triples**: the masks `d = x−a` and `e = y−b` become correlated across multiplications and leak information.
- **Mixing domains**: SPDZ over a prime field (mod p) is not the same as SPDZ2k (mod 2ᵏ). Conversions are subtle.
- **Not committing before opening in real protocols**: without commit-and-open, the last sender can adapt their share to try to pass checks.
- **Concurrency bugs**: multi-threaded openings/preprocessing can accidentally skip checks or reuse state (real-world foot-guns).

## Ship It

This lesson ships a reusable review checklist:

- `outputs/spdz-review-checklist.md`

Use it when reviewing an MPC system or PR that claims “SPDZ-like malicious security”. It helps you verify that openings are always MAC-checked, preprocessing is single-use, and the offline/online boundary is respected.

## Exercises

1. **Easy.** Run `python3 code/main.py`. Observe the `tampering detected` line and explain (in one sentence) why forging the MAC is hard.
2. **Medium.** Extend the demo to compute `x*y + z` (three inputs) using one triple for the multiplication and local addition for `+ z`.
3. **Hard.** Pick a real framework (e.g., MP-SPDZ) and map each toy function to its production analog (share type, opener/MAC check, preprocessing triples).

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Additive sharing | “Split x into random parts” | Values `xᵢ` such that `Σ xᵢ = x (mod p)` |
| Authenticated share | “SPDZ share” | Pair `(xᵢ, mᵢ)` with `Σ mᵢ = α·x (mod p)` |
| Global MAC key `α` | “Nobody knows the key” | `α` is additively shared; only `αᵢ` are known individually |
| Opening | “Reveal the secret” | Reconstruct `x` **and** run a MAC check before using it |
| Beaver triple | “Preprocessed multiplication helper” | Random `a, b` with `c=a·b` shared/authenticated for fast online multiplies |
| Preprocessing | “Offline phase” | Batch-generate triples/randomness independent of actual inputs |
| Malicious security | “Detect cheaters” | Active deviations are detected (secure-with-abort) with high probability |

## Further Reading

- Damgård, Pastro, Smart, Zakarias, *Multiparty Computation from Somewhat Homomorphic Encryption* (2012) — the original SPDZ line of work.
- Keller, Rotaru, and others, *MP-SPDZ documentation* (ongoing) — practical SPDZ-family protocols and tooling.
- Keller, Orsini, Scholl, *MASCOT* (2016) — an OT-based way to generate SPDZ triples efficiently.
