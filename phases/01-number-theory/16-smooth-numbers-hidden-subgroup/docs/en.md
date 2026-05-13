# Smooth Numbers & Hidden Subgroup

> Smoothness powers classical sieves; hidden periods power Shor.

**Type:** Learn
**Languages:** Python
**Prerequisites:** Phase 1 Lessons 2, 3, 12, 13, 14, 15
**Time:** ~45 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Define `B`-smooth integers and factor small examples over a prime base.
- Explain why smoothness controls the cost of Quadratic Sieve, Number Field Sieve, and index calculus.
- Recognize the Hidden Subgroup Problem (HSP) as the common shape behind period finding and discrete logs.
- Run the classical post-processing step that turns an even period into factors of `n`.
- Explain why Shor breaks RSA, finite-field DLP, and elliptic-curve DLP, while lattice schemes are not known to reduce to abelian HSP.

## The Problem

The previous lessons showed two different-looking attacks. Quadratic Sieve collects smooth values until linear algebra finds a square. Index calculus collects smooth group elements until linear algebra finds discrete logs. Smooth numbers are the quiet probability engine behind both attacks.

Quantum algorithms add a second unifying idea. Shor's algorithm does not "try factors faster." It turns factoring into period finding, and period finding is a Hidden Subgroup Problem over an abelian group. The same HSP lens also explains why finite-field DLP and elliptic-curve DLP fall to a sufficiently large fault-tolerant quantum computer.

Without these two ideas, the security landscape looks like a pile of unrelated facts: RSA needs bigger moduli, elliptic curves use different bit sizes, lattices are post-quantum, smoothness bounds appear in factoring estimates, and Shor is somehow magic. This lesson connects those facts into one map.

## The Concept

### Smooth numbers

An integer is `B`-smooth when every prime factor is at most `B`.

```text
72 = 2^3 * 3^2          3-smooth
84 = 2^2 * 3 * 7        7-smooth, not 5-smooth
97 = 97                 97-smooth, not 7-smooth
```

Smoothness is not about size. It is about the largest prime factor. A 200-digit number can be smooth if it factors into small primes; a two-digit prime is not smooth for a small bound.

Sieve algorithms choose a factor base:

```text
base B = {2, 3, 5, 7, 11, ...}
```

Then they search for values that factor completely over that base.

```text
value = 2^a * 3^b * 5^c * 7^d * ...
```

That factorization becomes a vector of exponents. Enough vectors produce a linear-algebra problem.

### The smoothness trade-off

Small `B` makes the matrix small but smooth values rare. Large `B` makes smooth values common but the matrix larger.

```text
smaller B: fewer columns, harder to find relations
larger  B: more columns, easier to find relations
```

Quadratic Sieve balances that trade-off near:

```text
B = exp(1/2 * sqrt(log n * log log n))
```

Number Field Sieve uses a more powerful polynomial setup, but it still lives on the same smoothness bargain.

### Hidden subgroup shape

The Hidden Subgroup Problem starts with a group `G`, a subgroup `H`, and a function `f` with this property:

```text
f(x) = f(y)  exactly when  x and y are in the same coset of H
```

The function hides `H`. Your job is to recover generators for `H`.

A tiny cyclic example:

```text
G = Z_12
H = {0, 4, 8}

cosets:
0 + H = {0, 4, 8}
1 + H = {1, 5, 9}
2 + H = {2, 6, 10}
3 + H = {3, 7, 11}

f(x) = x mod 4
```

The repeated labels reveal a period of `4`. The hidden subgroup is the set of shifts that do not change the label.

```text
x:    0 1 2 3 4 5 6 7 8 9 10 11
f(x): 0 1 2 3 0 1 2 3 0 1 2  3
            ^ period 4
```

### Shor as period finding

For factoring, pick a random `a` coprime to `n` and study:

```text
f(x) = a^x mod n
```

This function is periodic. If the period is `r`, then:

```text
a^r = 1 mod n
```

When `r` is even:

```text
(a^(r/2) - 1)(a^(r/2) + 1) = 0 mod n
```

If `a^(r/2)` is not `+/-1 mod n`, the two gcds reveal non-trivial factors:

```text
gcd(a^(r/2) - 1, n)
gcd(a^(r/2) + 1, n)
```

Example:

```text
n = 15, a = 2
2^4 = 1 mod 15, so r = 4
2^(4/2) = 4
gcd(4 - 1, 15) = 3
gcd(4 + 1, 15) = 5
```

The quantum part finds `r` efficiently with the Quantum Fourier Transform. The gcd step is ordinary classical arithmetic.

### DLP as HSP

Discrete log also has a hidden subgroup form. Given `h = g^x`, define:

```text
F(a, b) = g^a * h^b
```

Then:

```text
F(a, b) = F(a', b')
```

when the difference lies in a line determined by the unknown `x`. Recovering that hidden subgroup recovers the discrete log.

That is why Shor-style algorithms break finite-field DLP and elliptic-curve DLP. The group operation changes, but the HSP stays abelian.

### Why post-quantum schemes are different

Lattice, code, hash, and multivariate schemes are not secure because someone found "quantum-safe primes." They are candidates because no known efficient quantum algorithm turns their core hard problems into abelian HSP.

Some lattice problems have relationships to non-abelian HSP variants, such as dihedral HSP, but no Shor-like polynomial-time algorithm is known for the parameters used by schemes such as ML-KEM and ML-DSA.

## Build It

This is a `Learn` lesson, so the code is a runnable model rather than a primitive you would deploy. It has three pieces: smoothness checks, a toy hidden-period table, and Shor's classical factoring post-process.

### Step 1: Factor over a smoothness bound

Trial-divide by primes up to `B`. If the leftover value is `1`, every prime factor was small enough.

```python
def factor_over_bound(value: int, bound: int) -> SmoothFactorization:
    remaining = value
    exponents = {}
    for prime in primes_up_to(bound):
        exponent = 0
        while remaining % prime == 0:
            remaining //= prime
            exponent += 1
        if exponent:
            exponents[prime] = exponent
    return SmoothFactorization(value, bound, exponents, remaining)
```

For `84` and `B = 7`, the factorization is:

```text
84 = 2^2 * 3 * 7
remaining = 1
```

For `84` and `B = 5`, the leftover `7` proves it is not `5`-smooth.

### Step 2: Measure toy smoothness density

Count how many integers up to a limit are `B`-smooth.

```python
def smooth_density(limit: int, bound: int) -> float:
    return len(smooth_values(limit, bound)) / limit
```

For a tiny example:

```text
7-smooth values up to 100:
1, 2, 3, 4, 5, 6, 7, 8, 9, 10, ...
```

This is not the asymptotic Dickman function, but it gives the right instinct: as numbers grow while `B` stays small, smooth values become sparse.

### Step 3: Build a hidden-period table

In `Z_12`, the function `f(x) = x mod 4` is constant on cosets of `{0, 4, 8}`.

```python
def hidden_period_table(group_size: int, period: int) -> list[int]:
    return [x % period for x in range(group_size)]
```

Recover the smallest valid period by checking which shift leaves the whole table unchanged.

```python
def recover_hidden_period(values: list[int]) -> int:
    group_size = len(values)
    for candidate in range(1, group_size + 1):
        if group_size % candidate == 0 and is_hidden_subgroup_table(values, candidate):
            return candidate
    raise ValueError("no hidden period found")
```

The subgroup is then:

```text
{0, period, 2*period, ...}
```

### Step 4: Run the Shor post-processing step

The classical step is short once a period is known.

```python
def factor_from_period(n: int, base: int, period: int) -> tuple[int, int]:
    root = pow(base, period // 2, n)
    left = gcd(root - 1, n)
    right = gcd(root + 1, n)
    return tuple(sorted((left, right)))
```

The full demo computes the period classically because the numbers are tiny:

```python
result = shor_classical_postprocess(n=15, base=2)
print(result.period, result.factors)
```

Output:

```text
4, (3, 5)
```

## Use It

For classical number theory experiments, SageMath, PARI/GP, and SymPy can factor integers, compute multiplicative orders, and solve small algebraic problems. They are useful for checking toy examples, not for claiming security.

For quantum algorithm study, Qiskit and Cirq include tutorials for period finding and Shor-style circuits. Those circuits are pedagogical unless you have a fault-tolerant quantum computer with enough logical qubits and error correction.

For production cryptography, use audited libraries and post-quantum standards instead of from-scratch primitives. The NIST post-quantum standards are ML-KEM for key encapsulation and ML-DSA / SLH-DSA for signatures.

## Attack It

The attack lesson is conceptual:

```text
RSA and finite-field DH rely on problems with abelian-HSP structure.
Shor solves abelian HSP efficiently on a fault-tolerant quantum computer.
Therefore those schemes need migration before such computers are practical.
```

For RSA, period finding turns into factors. For finite-field and elliptic-curve DLP, hidden subgroup recovery turns into the secret discrete log.

Smoothness is the classical warning sign. Even before quantum computers, finite-field parameters must account for sub-exponential attacks such as Number Field Sieve and index calculus. Elliptic curves avoid known classical index-calculus-style attacks for well-chosen groups, but they do not avoid Shor.

## Ship It

This lesson ships `outputs/prompt-quantum-risk-triage.md`, a short review prompt for classifying a cryptographic dependency as classically fragile, quantum-fragile, or post-quantum oriented.

## Exercises

1. Easy: Factor `360`, `441`, and `1001` over bounds `7`, `11`, and `13`. Which are smooth?
2. Medium: For `G = Z_18`, build a table with hidden period `6`. List the hidden subgroup and all cosets.
3. Hard: Try bases `a = 2, 4, 5, 8, 10, 11` for `n = 21`. Which periods reveal factors, and which fail because the period is odd or the square root is trivial?

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| `B`-smooth | "A small number" | An integer whose prime factors are all at most `B`; the integer itself may be large. |
| Factor base | "The primes we divide by" | The chosen small primes used to turn smooth values into exponent vectors. |
| Hidden subgroup | "A hidden period" | A subgroup `H` where a function is constant on cosets of `H` and distinct across different cosets. |
| Abelian HSP | "The quantum trick behind Shor" | HSP where the group operation is commutative; factoring and DLP reduce to this case. |
| Dickman function | "Smoothness probability" | The asymptotic density function for `x^(1/u)`-smooth integers near `x`. |

## Test Vectors

The vectors in `tests/vectors.json` are deterministic textbook examples:

- Smoothness examples computed by trial division.
- Hidden period examples over finite cyclic groups.
- Shor post-processing examples for `15` and `21`.

They are not RFC or NIST primitive vectors because this lesson does not implement a production primitive.

## Further Reading

- [Peter W. Shor, "Algorithms for quantum computation: discrete logarithms and factoring"](https://doi.org/10.1109/SFCS.1994.365700) - the original factoring and DLP quantum algorithm.
- [Andrew Granville, "Smooth numbers: computational number theory and beyond"](https://websites.umich.edu/~wmebane/Granville_SmoothNumbers.pdf) - a readable survey of smooth numbers and their algorithmic role.
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography) - current standards and migration context.
