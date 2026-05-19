# RSA from Scratch — KeyGen, Encrypt, Decrypt
> RSA is just modular exponentiation — the hard part is choosing parameters so factoring is infeasible and plaintexts are safely padded.

**Type:** Build  
**Languages:** Python  
**Prerequisites:** Phase 01 · 02 (GCD/EEA), Phase 01 · 03 (Modular inverse & fast exp), Phase 01 · 10 (Miller–Rabin)  
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain RSA’s security assumption (factoring) and what it does *not* guarantee.
- Compute `n`, `φ(n)`, and a private exponent `d` from primes `p, q` and public exponent `e`.
- Implement a toy RSA key generator plus textbook encrypt/decrypt for integers and short byte strings.
- Distinguish textbook RSA (malleable, deterministic) from real RSA encryption (OAEP / padding).
- Apply a simple factoring attack to recover a toy private key and decrypt a captured ciphertext.

## The Problem

You want to send a secret to someone you’ve never met before. You can’t pre-share a symmetric key, and you can’t rely on a trusted courier. You also want anyone on the internet to be able to *verify* they’re talking to the right party (signatures), but you don’t want anyone else to decrypt the message (encryption).

RSA is the historical bridge that made “publish a public key, keep a private key” practical. It’s still everywhere: TLS certificates, PGP/GPG, secure boot, key wrapping, hardware tokens. Even if modern protocols prefer elliptic curves, you’ll keep seeing RSA in legacy systems and audits.

This lesson gives you the minimum viable RSA: generate keys from primes, encrypt/decrypt with modular exponentiation, then break your own toy key by factoring `n`. The attack is the point: RSA is only as strong as the difficulty of factoring.

## The Concept

RSA lives in the multiplicative group modulo `n = p·q` (a product of two large primes). The core identities are:

- Public key: `(n, e)`
- Private key: `(n, d)`
- Choose `d` so that: `e·d ≡ 1 (mod φ(n))`, where `φ(n) = (p-1)(q-1)`

Then encryption and decryption are just exponentiation:

- Encrypt: `c = m^e mod n`
- Decrypt: `m = c^d mod n`

Why does this work? Because with `e·d ≡ 1 (mod φ(n))`, exponentiating by `e` then `d` returns you to the original message representative `m` (for the values of `m` RSA is designed for). In other words, `d` is the modular inverse of `e` in the exponent world.

**The catch:** textbook RSA is deterministic and malleable. Real RSA encryption is RSA + padding (OAEP). Textbook RSA is still the best way to learn the math, *and* the best way to learn what breaks if you skip padding.

## Build It

### Step 1: Modular inverses (EEA)
```python
def gcd(a: int, b: int) -> int:
    a = abs(a)
    b = abs(b)
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def mod_inverse(a: int, modulus: int) -> int:
    if modulus <= 0:
        raise ValueError("modulus must be positive")
    a %= modulus
    g, x, _y = extended_gcd(a, modulus)
    if g != 1:
        raise ValueError("inverse does not exist (not coprime)")
    return x % modulus
```
RSA keygen needs one operation that feels “magic” the first time you see it: compute `d`, the modular inverse of `e` modulo `φ(n)`. The extended Euclidean algorithm gives you Bézout coefficients, and the modular inverse drops out when `gcd(e, φ(n)) = 1`.

### Step 2: Primes (Miller–Rabin)
```python
def _decompose_n_minus_1(n: int) -> tuple[int, int]:
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    return s, d


def is_probable_prime(n: int, rng: random.Random | None = None, rounds: int = 8) -> bool:
    if n < 2:
        return False
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    if n in small_primes:
        return True
    for p in small_primes:
        if n % p == 0:
            return False

    s, d = _decompose_n_minus_1(n)

    if n < (1 << 64):
        bases = (2, 325, 9375, 28178, 450775, 9780504, 1795265022)
    else:
        rng = rng or random.SystemRandom()
        bases = [rng.randrange(2, n - 1) for _ in range(max(1, rounds))]

    for a in bases:
        if a % n == 0:
            continue
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        composite = True
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                composite = False
                break
        if composite:
            return False
    return True


def random_prime(bits: int, rng: random.Random) -> int:
    if bits < 8:
        raise ValueError("bits too small for this demo (need >= 8)")
    while True:
        candidate = rng.getrandbits(bits)
        candidate |= 1
        candidate |= 1 << (bits - 1)
        if is_probable_prime(candidate, rng=rng):
            return candidate
```
RSA lives and dies by the choice of primes. Miller–Rabin is the standard fast probabilistic test. In this toy build we use a deterministic base set for 64-bit integers, and a randomized variant for larger sizes.

### Step 3: RSA key generation
```python
@dataclass(frozen=True)
class RSAKeypair:
    n: int
    e: int
    d: int
    p: int
    q: int


def rsa_keypair_from_primes(p: int, q: int, e: int = 65537) -> RSAKeypair:
    if p <= 1 or q <= 1:
        raise ValueError("p and q must be > 1")
    if p == q:
        raise ValueError("p and q must be distinct")
    if not is_probable_prime(p) or not is_probable_prime(q):
        raise ValueError("p and q must be prime")
    if e <= 1:
        raise ValueError("e must be > 1")

    n = p * q
    phi = (p - 1) * (q - 1)
    if gcd(e, phi) != 1:
        raise ValueError("e must be coprime to phi(n)")
    d = mod_inverse(e, phi)
    return RSAKeypair(n=n, e=e, d=d, p=p, q=q)


def rsa_generate_keypair(bits: int, e: int = 65537, rng: random.Random | None = None) -> RSAKeypair:
    if bits < 16:
        raise ValueError("bits too small for this demo (need >= 16)")
    rng = rng or random.Random()
    while True:
        p = random_prime(bits // 2, rng)
        q = random_prime(bits - bits // 2, rng)
        if p == q:
            continue
        try:
            return rsa_keypair_from_primes(p, q, e=e)
        except ValueError:
            continue
```
Keygen is: pick primes `p, q`, compute `n`, compute `φ(n)`, then invert `e` modulo `φ(n)` to obtain `d`. In real systems, `bits` is at least 2048 and primality testing is carefully engineered; here we keep it small so you can *see* the math and later *break* the key.

### Step 4: Textbook RSA encrypt/decrypt
```python
def mod_pow(base: int, exponent: int, modulus: int) -> int:
    if modulus <= 0:
        raise ValueError("modulus must be positive")
    if exponent < 0:
        raise ValueError("exponent must be non-negative")
    base %= modulus
    result = 1
    e = exponent
    b = base
    while e:
        if e & 1:
            result = (result * b) % modulus
        b = (b * b) % modulus
        e >>= 1
    return result


def rsa_encrypt_int(m: int, n: int, e: int) -> int:
    if m < 0:
        raise ValueError("message representative must be non-negative")
    if m >= n:
        raise ValueError("message representative must be < n")
    return mod_pow(m, e, n)


def rsa_decrypt_int(c: int, n: int, d: int) -> int:
    if c < 0:
        raise ValueError("ciphertext representative must be non-negative")
    if c >= n:
        raise ValueError("ciphertext representative must be < n")
    return mod_pow(c, d, n)


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big", signed=False)


def int_to_bytes(x: int, length: int) -> bytes:
    if x < 0:
        raise ValueError("x must be non-negative")
    if length < 0:
        raise ValueError("length must be non-negative")
    if length == 0:
        if x != 0:
            raise ValueError("x does not fit in the requested length")
        return b""
    if x >= (1 << (8 * length)):
        raise ValueError("x does not fit in the requested length")
    return x.to_bytes(length, byteorder="big", signed=False)


def rsa_encrypt_bytes_textbook(message: bytes, n: int, e: int) -> int:
    m = bytes_to_int(message)
    return rsa_encrypt_int(m, n, e)


def rsa_decrypt_bytes_textbook(ciphertext: int, n: int, d: int, out_len: int) -> bytes:
    m = rsa_decrypt_int(ciphertext, n, d)
    return int_to_bytes(m, out_len)
```
Textbook RSA treats a message as an integer `m` and applies exponentiation. That’s enough to demonstrate the math and to build intuition for why padding exists: if you can guess `m`, you can encrypt it and compare ciphertexts (determinism), and you can manipulate ciphertexts to manipulate plaintexts (malleability).

### Step 5: Break toy RSA by factoring n
```python
def factor_semiprime_trial(n: int) -> tuple[int, int]:
    if n <= 1:
        raise ValueError("n must be > 1")
    if n % 2 == 0:
        return 2, n // 2
    limit = int(math.isqrt(n))
    f = 3
    while f <= limit:
        if n % f == 0:
            return f, n // f
        f += 2
    raise ValueError("n does not look like a small semiprime (trial division failed)")


def recover_private_exponent_from_factoring(n: int, e: int) -> tuple[int, int, int]:
    p, q = factor_semiprime_trial(n)
    phi = (p - 1) * (q - 1)
    d = mod_inverse(e, phi)
    return p, q, d
```
This is the “why key sizes matter” demo. If an attacker can factor `n`, they can recompute `φ(n)` and recover `d`. With toy key sizes, trial division works. With real key sizes, factoring is believed to be infeasible (for now).

Run it:
`python3 code/main.py`

## Use It

In real systems, you almost never implement RSA yourself:

- **Python `cryptography`**: RSA-OAEP for encryption; RSA-PSS for signatures; safe defaults, constant-time implementations.
- **PyCryptodome**: RSA keygen + OAEP/PSS; useful for experiments but still prefer `cryptography` for new code.
- **OpenSSL / BoringSSL**: what most TLS stacks actually call under the hood.

Rule of thumb: **RSA encryption == RSA-OAEP**, **RSA signatures == RSA-PSS**. Textbook RSA is for learning and for attacks.

## Pitfalls

- **Textbook RSA encryption.** Deterministic and malleable; a real system must use OAEP (encryption) and PSS (signatures).
- **Too-small keys.** The factoring demo is trivial at 32 bits; production keys are typically 2048 or 3072 bits.
- **Bad randomness in keygen.** Predictable primes break everything; use the OS CSPRNG and audited keygen.
- **Reusing primes across keys.** If two moduli share a prime, `gcd(n1, n2)` instantly recovers it.
- **Wrong API boundary.** “RSA encrypt bytes” is not a primitive; you must define an encoding/padding scheme or use a library that does it.

## Ship It

Save the reusable checklist in `outputs/rsa-review-checklist.md`. Use it when:

- Reviewing PRs that add “RSA encryption/signing”
- Auditing a protocol that wraps/unwraps keys with RSA
- Triaging incidents involving RSA padding, key sizes, or certificate issues

The checklist is designed to be pasted into an LLM, a code review, or a security ticket as a concrete decision guide.

## Exercises

1. Easy. Run `python3 code/main.py`. Observe that factoring `n=3233` recovers `d` and decrypts the ciphertext.
2. Medium. Extend `code/main.py` to add RSA “sign/verify” on integers (`sig = m^d mod n`, verify via `sig^e mod n`) and show one failure mode if you “sign” a raw message instead of a hash.
3. Hard. In a separate scratch script, use `cryptography` to encrypt the same plaintext with RSA-OAEP and explain why your textbook RSA ciphertexts don’t have semantic security.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| `n` (modulus) | “the RSA key” | The product `p·q` that defines the arithmetic ring; factoring it breaks RSA. |
| `e` | “public exponent” | The exponent used for encryption/verification; commonly `65537`. |
| `d` | “private exponent” | The modular inverse of `e` modulo `φ(n)` (or `λ(n)`); enables decryption/signing. |
| `φ(n)` | “Euler totient” | For RSA with distinct primes, `φ(n) = (p-1)(q-1)`; counts invertible residues mod `n`. |
| OAEP | “RSA padding” | A randomized encoding that makes RSA encryption semantically secure (under assumptions). |

## Further Reading

- Rivest, Shamir, Adleman, *A Method for Obtaining Digital Signatures and Public-Key Cryptosystems* (1978) — the original RSA paper.
- Boneh, *Twenty Years of Attacks on the RSA Cryptosystem* (1999) — survey of what goes wrong in practice.
- Kaliski, *PKCS #1: RSA Cryptography Specifications* (v2.2, 2012) — defines OAEP/PSS and encoding rules.
