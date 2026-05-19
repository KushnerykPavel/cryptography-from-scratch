# Euler's Totient & Carmichael Function

> The number of invertible residues tells you when modular exponentiation must cycle.

**Type:** Build
**Languages:** Python
**Prerequisites:** 02-gcd-bezout-eea, 03-modular-inverse-and-fast-exp, 04-fermat-and-euler, 05-chinese-remainder-theorem
**Time:** ~45 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain the inclusion-exclusion product formula phi(n) = n · ∏(1 − 1/p) and why it counts invertible residues
- Compute lambda(n) from prime-power components using lcm, including the special cases for powers of two
- Implement euler_totient from prime factorization and carmichael_lambda by combining prime-power cycle lengths
- Distinguish phi(n) (group size) from lambda(n) (group exponent) and explain why lambda gives a tighter RSA private exponent
- Apply the quadratic formula attack to factor a semiprime n given a leaked phi(n)

## The Problem

Lesson 04 gave you Euler's theorem:

```text
a^phi(n) ≡ 1 (mod n)    when gcd(a, n) = 1
```

That theorem is powerful only if you can actually compute `phi(n)` for the modulus you care about. Counting coprime residues one by one works for `n = 10`. It does not work for RSA-size moduli, and it does not explain why some moduli have shorter exponent cycles than `phi(n)` suggests.

Cryptography needs both answers. RSA key generation needs the group order information behind the private exponent. Primality testing needs to understand why some composite numbers imitate primes in Fermat-style tests. Attackers care too: leaking `phi(n)` for an RSA modulus is essentially the same as leaking the factorization.

This lesson turns the counting definition into efficient formulas. You will compute `phi(n)` from the prime factorization, build Carmichael's function `lambda(n)` as the true universal cycle length for all units modulo `n`, and use both to understand what RSA really relies on.

## The Concept

### `phi(n)` counts units

Euler's totient counts the residues in `{1, ..., n}` that are coprime to `n`:

```text
phi(n) = |U(n)|
```

If

```text
n = p1^a1 * p2^a2 * ... * pk^ak
```

then every residue that is not a unit is divisible by at least one prime factor of `n`. Inclusion-exclusion gives the product formula:

```text
phi(n) = n * ∏(1 - 1/p)
```

where the product runs over distinct prime divisors `p | n`.

Example:

```text
36 = 2^2 * 3^2
phi(36) = 36 * (1 - 1/2) * (1 - 1/3) = 12
```

### `lambda(n)` is the real cycle length

`phi(n)` counts how many units there are. Carmichael's function asks a different question:

```text
lambda(n) = smallest k such that a^k ≡ 1 (mod n)
            for every a with gcd(a, n) = 1
```

So `lambda(n)` is the exponent of the group `U(n)`. It always divides `phi(n)`, and it can be much smaller.

For odd prime powers:

```text
lambda(p^a) = phi(p^a) = (p - 1)p^(a-1)
```

For powers of two there is a special case:

```text
lambda(2)   = 1
lambda(4)   = 2
lambda(2^a) = 2^(a-2)    for a >= 3
```

For general `n`, CRT lets the cycle lengths combine by least common multiple:

```text
lambda(n) = lcm(lambda(p1^a1), ..., lambda(pk^ak))
```

Example:

```text
36 = 4 * 9
lambda(4) = 2
lambda(9) = 6
lambda(36) = lcm(2, 6) = 6
```

That means every unit mod `36` satisfies `a^6 ≡ 1 (mod 36)`, even though `phi(36) = 12`.

### Why RSA cares about `lambda(n)`

For `n = p*q` with distinct primes:

```text
phi(n) = (p - 1)(q - 1)
lambda(n) = lcm(p - 1, q - 1)
```

Both support correct private-key construction, but `lambda(n)` is tighter. If

```text
e*d ≡ 1 (mod lambda(n))
```

then RSA decryption works for every invertible message residue, because `lambda(n)` is the universal cycle length of the unit group.

### Why leaking `phi(n)` is fatal

For a semiprime RSA modulus `n = p*q`:

```text
phi(n) = (p - 1)(q - 1) = pq - p - q + 1
```

So:

```text
p + q = n - phi(n) + 1
```

Once you know the sum and product of `p` and `q`, they are just the roots of:

```text
x^2 - (p + q)x + pq = 0
```

In other words:

```text
knowing phi(n)  <->  knowing the factorization
```

### Carmichael numbers

Some composite numbers fool the plain Fermat test for every coprime base. Korselt's criterion says `n` is Carmichael exactly when:

1. `n` is composite
2. `n` is square-free
3. for every prime `p | n`, we have `(p - 1) | (n - 1)`

That criterion is a clean bridge between totients, orders, and attack thinking.

## Build It

### Step 1: Factor `n`

The efficient formulas for both `phi(n)` and `lambda(n)` start from the prime factorization.

```python
def prime_factorization(n: int) -> list[tuple[int, int]]:
    if n <= 0:
        raise ValueError("n must be positive")
    if n == 1:
        return []

    factors = []
    exponent = 0
    while n % 2 == 0:
        n //= 2
        exponent += 1
    if exponent > 0:
        factors.append((2, exponent))

    p = 3
    while p * p <= n:
        exponent = 0
        while n % p == 0:
            n //= p
            exponent += 1
        if exponent > 0:
            factors.append((p, exponent))
        p += 2

    if n > 1:
        factors.append((n, 1))

    return factors
```

This is still trial division, but it is enough for classroom-size numbers and turns the later formulas into direct code instead of brute-force counting.

### Step 2: Compute `phi(n)` from distinct primes

```python
def euler_totient(n: int) -> int:
    if n <= 0:
        raise ValueError("n must be positive")
    if n == 1:
        return 1

    result = n
    for p, _ in prime_factorization(n):
        result -= result // p
    return result
```

This is the product formula in arithmetic form. Each distinct prime factor removes the fraction `1/p` of residues that cannot be units.

### Step 3: Handle prime powers for `lambda`

```python
def carmichael_prime_power(p: int, exponent: int) -> int:
    if exponent <= 0:
        raise ValueError("exponent must be positive")
    if not is_prime_naive(p):
        raise ValueError("p must be prime")

    if p == 2:
        if exponent == 1:
            return 1
        if exponent == 2:
            return 2
        return 1 << (exponent - 2)

    return (p - 1) * (p ** (exponent - 1))
```

The `2^a` branch is the only subtle one. For odd prime powers, `lambda(p^a)` equals `phi(p^a)`.

### Step 4: Combine prime-power orders with `lcm`

```python
def carmichael_lambda(n: int) -> int:
    if n <= 0:
        raise ValueError("n must be positive")
    if n == 1:
        return 1

    value = 1
    for p, exponent in prime_factorization(n):
        value = lcm(value, carmichael_prime_power(p, exponent))
    return value
```

This is CRT in action again. Each prime-power component has its own cycle length, and the whole system repeats when all components line up at once.

### Step 5: Use `lambda(n)` for exponent reduction

```python
def reduce_exponent_lambda(base: int, exp: int, n: int) -> int:
    if gcd(base, n) != 1:
        raise ValueError("base must be coprime to n")
    return pow(base, exp % carmichael_lambda(n), n)
```

This is the sharper version of Euler reduction. The condition `gcd(base, n) = 1` still matters.

### Step 6: Turn the formulas into RSA consequences

Private exponent from `lambda(n)`:

```python
def rsa_private_exponent(e: int, p: int, q: int) -> int:
    lam = carmichael_lambda(p * q)
    if gcd(e, lam) != 1:
        raise ValueError("e must be coprime to lambda(n)")
    return pow(e, -1, lam)
```

Factor `n` from a leaked `phi(n)`:

```python
def factor_semiprime_from_phi(n: int, phi_n: int) -> tuple[int, int]:
    s = n - phi_n + 1
    discriminant = s * s - 4 * n
    root = isqrt(discriminant)
    p = (s + root) // 2
    q = (s - root) // 2
    return max(p, q), min(p, q)
```

That second helper is the attack lesson hiding inside the arithmetic lesson.

Run it:

```
python3 code/main.py
```

## Use It

Production libraries do not expose `phi(n)` as a standard API call because computing it for a large RSA modulus is equivalent to already knowing the factorization. But they absolutely rely on the same formulas internally during key generation:

- choose primes `p, q`
- compute `lambda(n)` or an equivalent order condition
- invert `e` modulo that value to derive `d`
- keep the factorization secret forever

In Python, `pow(e, -1, modulus)` already performs modular inversion, and `pow(base, exp, mod)` gives the modular exponentiation primitive. The lesson code is the math that explains why those operations are the right ones in RSA setup.

## Attack It

### Leak `phi(n)`, factor `n`

If an implementation logs, caches, or otherwise exposes `phi(n)` for RSA, the modulus is gone. The recovery is not heuristic:

```text
p + q = n - phi(n) + 1
p * q = n
```

Solve the quadratic and recover both primes exactly.

### Carmichael numbers defeat naive Fermat confidence

Numbers like `561` and `1105` satisfy Fermat's congruence for every coprime base even though they are composite. That is why "passes Fermat for base 2" is not a primality proof, and why later lessons need Miller-Rabin and stronger tests.

### Smooth structure can shrink `lambda(n)`

If `p - 1` and `q - 1` share large factors, then `lambda(n) = lcm(p - 1, q - 1)` can be much smaller than `phi(n)`. That is not automatically a break, but it is a reminder that the group exponent, not just the group size, matters in cryptographic design.

## Ship It

This lesson ships `outputs/skill-totient-carmichael-auditor.md`: a small review checklist for spotting code that confuses `phi(n)` with `lambda(n)`, reduces exponents without coprimality checks, or handles RSA order data unsafely.

## Exercises

1. **Easy.** Compute `phi(84)` by hand from its factorization and check your answer against the code.
2. **Medium.** Compute `lambda(72)` from prime powers and explain why it is smaller than `phi(72)`.
3. **Hard.** Generate small RSA keys with several prime pairs and compare the private exponents obtained modulo `phi(n)` and modulo `lambda(n)`. When do they differ?

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| Euler totient `phi(n)` | "how many good residues there are" | The number of invertible residues modulo `n` |
| Carmichael `lambda(n)` | "a smaller totient" | The least universal exponent for all units modulo `n` |
| Group exponent | "the cycle length of the group" | The smallest `k` such that `a^k = 1` for every group element |
| Prime-power formula | "compute it per factor first" | Evaluate `phi` or `lambda` on `p^a` before combining factors |
| Korselt's criterion | "the Carmichael test" | A square-free divisibility rule characterizing Carmichael numbers |
| RSA order leak | "just metadata" | Any leak of `phi(n)` or equivalent order data destroys RSA secrecy |

## Test Vectors

Source: project-internal examples, the standard classroom RSA modulus `61 * 53 = 3233`, and known Carmichael numbers cross-checked against the closed-form formulas and Python's modular arithmetic.

Code must pass all cases in `tests/vectors.json`.

## Further Reading

- Boneh & Shoup, *A Graduate Course in Applied Cryptography* — clean cryptography-first treatment of totients, orders, and RSA.
- Menezes, van Oorschot, Vanstone, *Handbook of Applied Cryptography* — practical reference for number theory, RSA, and pseudoprimes.
- Richard Crandall and Carl Pomerance, *Prime Numbers: A Computational Perspective* — good source for Carmichael numbers, orders, and multiplicative structure.
