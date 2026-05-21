# Shor's Algorithm (Toy) — Order-Finding Breaks Factoring

> Factoring is hard until you can find periods.

**Type:** Build
**Languages:** Python
**Prerequisites:** 01-number-theory/02-gcd-bezout-eea, 01-number-theory/06-modular-arithmetic, 01-number-theory/17-continued-fractions, 14-pq-lattice/01-why-quantum-breaks-classical
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain how factoring reduces to order finding — and why that reduction matters for RSA/ECC security.
- Compute the order `r` of `a (mod N)` and identify when `r` leads to nontrivial factors.
- Implement continued fractions and convergents to recover `r` from a measured phase `s/r`.
- Distinguish the “quantum-only” part (phase estimation) from the classical post-processing (continued fractions + gcd).
- Apply a toy Shor loop to factor small `N` and enumerate the failure cases that require repetition.

## The Problem

Public-key cryptography leans on “structured hardness”: factoring large integers (RSA) and discrete log on elliptic curves (ECDH/ECDSA) are easy to state, easy to verify, and believed to be hard to solve at scale on classical machines.

Shor’s algorithm is the reason post-quantum cryptography exists. It shows that *if you have a sufficiently large, fault-tolerant quantum computer*, then factoring and discrete log are not just “a bit faster” — they become *polynomial-time* problems. That flips long-term security planning into a migration problem: you must inventory where RSA/ECC live, decide when data needs to remain confidential, and move to schemes that do not fall to Shor (like lattice-based KEMs/signatures).

This lesson builds a **toy, stdlib-only** walkthrough of the *logic* of Shor’s algorithm: how the “quantum part” produces a fraction `s/r`, and how the “classical part” uses continued fractions and gcd to turn that into factors. The goal is to make the moving pieces concrete — not to simulate real quantum circuits.

## The Concept

### 1) Factoring → order finding

Let `N` be an odd composite you want to factor. Pick a random `a` with `1 < a < N`.

If `gcd(a, N) > 1`, you already found a factor.

Otherwise `a` is invertible mod `N`, so it has an **order** `r`:

```text
r = smallest positive integer such that a^r ≡ 1 (mod N)
```

If `r` is even, define:

```text
x = a^(r/2) mod N
```

Then:

```text
a^r - 1 ≡ 0 (mod N)
(a^(r/2) - 1)(a^(r/2) + 1) ≡ 0 (mod N)
(x - 1)(x + 1) ≡ 0 (mod N)
```

So any nontrivial gcd:

```text
gcd(x - 1, N) or gcd(x + 1, N)
```

can reveal a factor of `N`.

### 2) The quantum output is a fraction s/r

The quantum subroutine (phase estimation over modular exponentiation) produces a measurement `m` that encodes a rational approximation:

```text
m / Q ≈ s / r
```

where:

- `r` is the order we want,
- `s` is an integer in `{0, 1, ..., r-1}`,
- `Q` is a power of two (coming from the number of qubits used in phase estimation).

Crucially: the quantum computer does *not* hand you `r` directly — it hands you a number close to `s/r`.

### 3) Continued fractions recover r

Continued fractions are the machine that turns a “good rational approximation” into candidate denominators. In Shor’s classical post-processing:

1. Compute the continued fraction expansion of `m/Q`.
2. Enumerate convergents `p/q`.
3. Treat denominators `q` (and small multiples) as candidates for `r`, and test them by checking `a^r ≡ 1 (mod N)`.

You repeat the whole procedure until the algebra produces nontrivial factors.

## Build It

### Step 1: Modular primitives

```python
def gcd(a: int, b: int) -> int:
    a = abs(a)
    b = abs(b)
    while b:
        a, b = b, a % b
    return a


def mod_pow(base: int, exponent: int, modulus: int) -> int:
    if modulus <= 0:
        raise ValueError("modulus must be positive")
    if exponent < 0:
        raise ValueError("exponent must be nonnegative")

    result = 1
    base %= modulus
    e = exponent
    while e:
        if e & 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        e >>= 1
    return result
```

`gcd` is the “factor detector” (`gcd(a, N)`), and `mod_pow` is the engine behind modular exponentiation. In Shor, modular exponentiation is implemented as a reversible quantum circuit, but the *mathematical* object is the same: repeated squaring and multiplication modulo `N`.

### Step 2: Continued fractions

```python
def continued_fraction_rational(numerator: int, denominator: int) -> list[int]:
    if denominator == 0:
        raise ValueError("denominator must be nonzero")
    if numerator < 0 or denominator < 0:
        raise ValueError("numerator and denominator must be nonnegative")

    n = numerator
    d = denominator
    coefficients: list[int] = []
    while d:
        q = n // d
        coefficients.append(q)
        n, d = d, n - q * d
    return coefficients


def convergents(coefficients: list[int]) -> list[tuple[int, int]]:
    if not coefficients:
        raise ValueError("continued fraction must be non-empty")

    p0, q0 = 1, 0
    p1, q1 = coefficients[0], 1
    result: list[tuple[int, int]] = [(p1, q1)]
    for a in coefficients[1:]:
        p0, p1 = p1, a * p1 + p0
        q0, q1 = q1, a * q1 + q0
        result.append((p1, q1))
    return result
```

`continued_fraction_rational` is Euclid’s algorithm expressed as a sequence of quotients, and `convergents` turns that sequence into “best guess” fractions `p/q`. Shor’s classical post-processing inspects these denominators because the true order `r` shows up as (or divides) one of them.

### Step 3: Order finding from a phase

```python
def multiplicative_order(a: int, n: int, max_r: int | None = None) -> int:
    if n <= 1:
        raise ValueError("n must be > 1")

    base = a % n
    if gcd(base, n) != 1:
        raise ValueError("a must be coprime to n")

    limit = max_r if max_r is not None else n
    if limit <= 0:
        raise ValueError("max_r must be positive")

    x = 1
    for r in range(1, limit + 1):
        x = (x * base) % n
        if x == 1:
            return r
    raise ValueError("order not found within max_r")


def simulate_phase_measurement(s: int, r: int, Q: int) -> int:
    if r <= 0:
        raise ValueError("r must be positive")
    if Q <= 0:
        raise ValueError("Q must be positive")
    if not (0 <= s < r):
        raise ValueError("s must satisfy 0 <= s < r")

    return (s * Q + r // 2) // r


def recover_order_from_phase(
    *,
    measurement: int,
    Q: int,
    a: int,
    N: int,
    max_denominator: int | None = None,
    max_multiplier: int | None = None,
) -> int:
    if Q <= 0:
        raise ValueError("Q must be positive")
    if not (0 <= measurement < Q):
        raise ValueError("measurement must satisfy 0 <= measurement < Q")
    if N <= 1:
        raise ValueError("N must be > 1")
    if gcd(a, N) != 1:
        raise ValueError("a must be coprime to N")

    max_den = max_denominator if max_denominator is not None else N
    if max_den <= 0:
        raise ValueError("max_denominator must be positive")

    max_mult = max_multiplier if max_multiplier is not None else max(1, N)
    if max_mult <= 0:
        raise ValueError("max_multiplier must be positive")

    coeffs = continued_fraction_rational(measurement, Q)
    for _, q in convergents(coeffs):
        if q <= 0:
            continue
        if q > max_den:
            break

        for k in range(1, max_mult + 1):
            candidate = q * k
            if candidate > max_den:
                break
            if mod_pow(a, candidate, N) == 1:
                return multiplicative_order(a, N, max_r=candidate)

    raise ValueError("order not recovered from measurement")
```

The real quantum computer gives you `measurement` (an integer) and a known power-of-two `Q`. The continued-fraction step guesses a denominator `q` for `measurement/Q ≈ s/r`. When `s` shares a gcd with `r`, you often recover only a divisor of `r`, so the code tries small multiples (`q * k`) and then confirms the actual minimal order. This mirrors the “repeat until it works” nature of Shor’s post-processing.

### Step 4: Toy Shor factoring loop

```python
from math import isqrt
from random import Random


def is_perfect_square(n: int) -> bool:
    if n < 0:
        return False
    r = isqrt(n)
    return r * r == n


def shor_factor_toy(N: int, *, seed: int = 0, max_attempts: int = 25) -> tuple[int, int]:
    if N <= 3:
        raise ValueError("N must be > 3")
    if N % 2 == 0:
        return 2, N // 2
    if is_perfect_square(N):
        root = isqrt(N)
        return root, root

    rng = Random(seed)
    for _ in range(max_attempts):
        a = rng.randrange(2, N - 1)
        g = gcd(a, N)
        if 1 < g < N:
            return min(g, N // g), max(g, N // g)

        try:
            r = multiplicative_order(a, N, max_r=N)
        except ValueError:
            continue

        if r % 2 == 1:
            continue

        x = mod_pow(a, r // 2, N)
        if x in (1, N - 1):
            continue

        p = gcd(x - 1, N)
        q = gcd(x + 1, N)
        if 1 < p < N and 1 < q < N and p * q == N:
            return min(p, q), max(p, q)

    raise ValueError("no nontrivial factors found (toy shor failed)")
```

This is the “outer loop” of Shor: pick `a`, try to get an even order `r`, compute `x = a^(r/2)`, and hope that `gcd(x±1, N)` is nontrivial. In real Shor, the expensive part is using a quantum computer to estimate `r`; here we compute `r` classically (only feasible for tiny `N`) to keep the demo runnable with stdlib-only Python.

Run it:

```bash
python3 code/main.py
```

## Use It

In production you do **not** “use Shor’s algorithm” as a library call today. Shor is a *capability threat model* tied to large-scale fault-tolerant quantum computers.

Still, the concept has concrete “production equivalents”:

- Threat modeling: track where RSA/ECDH/ECDSA are used (TLS termination, firmware signing, VPNs, HSMs, PDFs, JWTs).
- Migration engineering: move key exchange to PQ KEMs (e.g., ML-KEM/Kyber) and signatures to PQ signatures (e.g., ML-DSA/Dilithium, or Falcon where appropriate) using standards guidance.
- Quantum software (research/prototyping): frameworks like Qiskit/Cirq model circuits and can run on simulators/hardware, but these are not drop-in security tools.

## Pitfalls

- Treating `q` from continued fractions as the order without verification (`a^q mod N == 1` is non-negotiable).
- Forgetting that you often recover only a **divisor** of `r` when `gcd(s, r) != 1`, so repetition (or testing small multiples) is required.
- Not checking the “easy win” case `gcd(a, N) > 1` before doing any order logic.
- Using an odd order `r` (it gives no `r/2`) or landing on `x ≡ ±1 (mod N)` (it yields trivial gcds).
- Assuming the algorithm always succeeds quickly for small `N`; even in toy form, you need retries.

## Ship It

This lesson ships a reusable **quantum risk & migration checklist** in `outputs/`.

Use it when:

- reviewing a PR that touches TLS/certificates/cryptography choices,
- planning a PQ migration project,
- doing a security inventory (“where does RSA/ECC live and how long must data remain secret?”).

Open `outputs/shor_migration_checklist.md` and paste it into a ticket or a design review.

## Exercises

1. Easy. Run `python3 code/main.py`. Observe how `measurement/Q` becomes a continued fraction and how the recovered `r` enables factoring.
2. Medium. Extend `code/main.py` to factor a list of small semiprimes (e.g., `15, 21, 33, 35`) and print how many attempts were needed per `N`.
3. Hard. Build a “crypto inventory” table (system → protocol → algorithm → key size → data lifetime), then use the checklist in `outputs/` to write a migration plan for one system.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Order `r` | “period” | Smallest `r > 0` with `a^r ≡ 1 (mod N)` when `gcd(a, N) = 1`. |
| Phase estimation | “quantum magic” | A quantum routine that outputs information about an eigenvalue as a rational `s/r` encoded in a measurement. |
| `Q` | “number of qubits” | A power of two that sets the measurement resolution; the algorithm sees `m/Q`. |
| Continued fraction | “a weird fraction form” | A structured way to enumerate best rational approximations; used to recover candidate denominators for `s/r`. |
| Nontrivial factor | “a gcd” | A value strictly between `1` and `N` that divides `N` (e.g., `gcd(x-1, N)`). |

## Further Reading

- Peter W. Shor, *Algorithms for quantum computation: discrete logarithms and factoring* (1994) — the original Shor factoring/discrete log result.
- Michael A. Nielsen & Isaac L. Chuang, *Quantum Computation and Quantum Information* (2000) — standard reference for phase estimation and the QFT.
- Michele Mosca, *Cybersecurity in an era with quantum computers* (2018) — practical “harvest now, decrypt later” framing and migration timelines.
- NIST, *Post-Quantum Cryptography Standardization* (ongoing) — standards and transition guidance for PQ KEMs/signatures.
