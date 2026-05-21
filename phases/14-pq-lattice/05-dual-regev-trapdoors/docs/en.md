# Dual Regev Trapdoors (Gadget-Style)
> A decryption key is “just” a short preimage \(x\) such that \(Ax=y \pmod q\).

**Type:** Build
**Languages:** Python
**Prerequisites:** `14-pq-lattice/04-regev-encryption`
**Time:** ~80 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** why Dual-Regev secret keys are short preimages \(x\) with \(Ax=y \pmod q\)
- **Compute** gadget decompositions \(G^{-1}(y)\) via bit decomposition for power-of-two \(q\)
- **Implement** an MP12-style gadget trapdoor \(A=[A' \mid G-A'R]\) and trapdoor matrix \(T=[R;I]\)
- **Distinguish** deterministic preimages (leaky) from randomized Gaussian preimage sampling (safe)
- **Apply** the trapdoor to generate a Dual-Regev decryption key for an arbitrary public target \(y\)

## The Problem

In “Dual Regev” encryption, the public key is a matrix/vector pair \((A, y)\) over \(\mathbb{Z}_q\), and the decryption key is a *short* vector \(x\) such that \(Ax=y \pmod q\). Decryption works because the ciphertext contains an LWE sample “with respect to \(A\)”, and multiplying by \(x\) turns it into an LWE sample “with respect to \(y\)”, plus a small error term.

But there’s a catch: given a random-looking \(A\) and a random-looking \(y\), finding a *short* \(x\) with \(Ax=y \pmod q\) is believed to be hard (that hardness is a feature — it’s connected to SIS/LWE). So if you want a system where *you* can generate decryption keys (IBE/ABE, signatures, revocation, key delegation), you need a trapdoor: extra secret information that makes “find a short preimage” easy for the key generator, while staying hard for everyone else.

This lesson implements a tiny, runnable version of a standard gadget-trapdoor idea: build \(A\) with hidden structure so that it’s indistinguishable from random to outsiders, but *you* can invert \(x \mapsto Ax \bmod q\) on any target \(y\).

## The Concept

### Dual Regev in one equation

Dual Regev encrypts a bit \(b \in \{0,1\}\) as:

- \(c_1 = s^T A + e^T \in \mathbb{Z}_q^m\)
- \(c_2 = s^T y + e' + b \cdot \lfloor q/2 \rfloor \in \mathbb{Z}_q\)

If the secret key is any *short* \(x \in \mathbb{Z}^m\) such that \(Ax=y \pmod q\), then:

\[
c_2 - c_1^T x
= (s^T y + e' + b\lfloor q/2 \rfloor) - (s^T A + e^T)x
= b\lfloor q/2 \rfloor + (e' - e^T x) \pmod q
\]

As long as the “noise” term \(e' - e^T x\) stays much smaller than \(q/4\), decoding the bit is just rounding to “near 0” vs “near \(q/2\)”.

### Gadget matrix \(G\): easy to invert

Pick a power-of-two modulus \(q=2^k\). Define the gadget vector \(g=(1,2,4,\dots,2^{k-1})\). The gadget matrix is a block diagonal matrix:

\[
G = I_n \otimes g \in \mathbb{Z}_q^{n \times nk}.
\]

For any \(y \in \mathbb{Z}_q^n\), bit decomposition gives a *binary* vector \(x' = G^{-1}(y) \in \{0,1\}^{nk}\) such that \(Gx' = y \pmod q\).

### Gadget trapdoor \(T\): reduce inversion of \(A\) to inversion of \(G\)

Micciancio–Peikert-style trapdoors (MP12) build:

- choose random \(A' \in \mathbb{Z}_q^{n \times m'}\)
- choose *short* \(R \in \mathbb{Z}^{m' \times nk}\) (entries like \(-1,0,1\))
- set \(A = [A' \mid G - A'R] \in \mathbb{Z}_q^{n \times (m'+nk)}\)
- define the trapdoor matrix \(T = \begin{pmatrix} R \\ I \end{pmatrix}\)

Then \(AT = G \pmod q\). So for any target \(y\), you can get a (structured) short preimage:

1. \(x' = G^{-1}(y)\) via bit decomposition
2. \(x = T x'\)
3. \(Ax = ATx' = Gx' = y \pmod q\)

Important: this deterministic \(x\) leaks structure. Real schemes *randomize* preimage sampling (typically discrete Gaussians + convolution tricks) so outputs don’t reveal the trapdoor.

## Build It

### Step 1: Gadget matrix (G) and bit decomposition (G^{-1})
These functions build \(G\) for power-of-two \(q\), decompose a vector into bits, and compose it back. This is the “publicly invertible” part we’ll reduce to.

```python
Matrix = List[List[int]]


def _is_power_of_two(q: int) -> bool:
    return q > 0 and (q & (q - 1)) == 0


def _log2_int(q: int) -> int:
    if not _is_power_of_two(q):
        raise ValueError("this toy implementation assumes q is a power of 2")
    return q.bit_length() - 1


def gadget_matrix(n: int, q: int) -> Matrix:
    k = _log2_int(q)
    g = [1 << i for i in range(k)]
    out: Matrix = [[0 for _ in range(n * k)] for _ in range(n)]
    for row in range(n):
        for i, gi in enumerate(g):
            out[row][row * k + i] = gi % q
    return out


def bit_decompose_element(x: int, q: int) -> List[int]:
    k = _log2_int(q)
    x = x % q
    return [(x >> i) & 1 for i in range(k)]


def bit_decompose_vec(v: Sequence[int], q: int) -> List[int]:
    bits: List[int] = []
    for x in v:
        bits.extend(bit_decompose_element(x, q))
    return bits


def gadget_compose_vec(bits: Sequence[int], q: int) -> List[int]:
    k = _log2_int(q)
    if len(bits) % k != 0:
        raise ValueError("bit vector length must be a multiple of k")
    n = len(bits) // k
    out: List[int] = []
    for i in range(n):
        chunk = bits[i * k : (i + 1) * k]
        out.append(sum(int(b) * (1 << j) for j, b in enumerate(chunk)) % q)
    return out
```

### Step 2: Trapdoor generation A = [A' | G - A'R]
This constructs a “random-looking” matrix \(A\) together with a trapdoor \(T=[R;I]\) such that \(AT=G \pmod q\).

```python
@dataclass(frozen=True)
class Trapdoor:
    q: int
    A: Matrix
    A_prime: Matrix
    R: Matrix
    T: Matrix


def mat_dims(A: Matrix) -> Tuple[int, int]:
    if not A:
        return (0, 0)
    return (len(A), len(A[0]))


def mat_mul_mod(A: Matrix, B: Matrix, q: int) -> Matrix:
    n, m = mat_dims(A)
    m2, p = mat_dims(B)
    if m != m2:
        raise ValueError("matrix dimension mismatch")
    out: Matrix = [[0 for _ in range(p)] for _ in range(n)]
    for i in range(n):
        for k in range(m):
            aik = A[i][k]
            if aik == 0:
                continue
            for j in range(p):
                out[i][j] = (out[i][j] + aik * B[k][j]) % q
    return out


def mat_hcat(left: Matrix, right: Matrix) -> Matrix:
    n1, _m1 = mat_dims(left)
    n2, _m2 = mat_dims(right)
    if n1 != n2:
        raise ValueError("row mismatch for horizontal concatenation")
    return [left[i] + right[i] for i in range(n1)]


def identity_matrix(n: int) -> Matrix:
    out: Matrix = [[0 for _ in range(n)] for _ in range(n)]
    for i in range(n):
        out[i][i] = 1
    return out


def trapdoor_generate(A_prime: Matrix, R: Matrix, q: int) -> Trapdoor:
    n, m_prime = mat_dims(A_prime)
    m_r, nk = mat_dims(R)
    if m_r != m_prime:
        raise ValueError("R must have shape (m_prime, n*k)")
    k = _log2_int(q)
    if nk != n * k:
        raise ValueError("R must have width n*k where k=log2(q)")

    G = gadget_matrix(n, q)
    AprimeR = mat_mul_mod(A_prime, R, q)
    right: Matrix = [[(G[i][j] - AprimeR[i][j]) % q for j in range(nk)] for i in range(n)]
    A = mat_hcat(A_prime, right)

    I = identity_matrix(nk)
    T: Matrix = [row[:] for row in R] + I
    return Trapdoor(q=q, A=A, A_prime=A_prime, R=R, T=T)
```

### Step 3: Preimage sampling x = T * G^{-1}(y)
Given any target \(y \in \mathbb{Z}_q^n\), we deterministically compute a short-ish \(x\) such that \(Ax=y \pmod q\). This is the exact “trapdoor inversion” operation Dual Regev needs for its decryption key.

```python
def mat_vec_mul_int(A: Matrix, x: Sequence[int]) -> List[int]:
    n, m = mat_dims(A)
    if len(x) != m:
        raise ValueError("matrix/vector dimension mismatch")
    return [sum(A[i][j] * x[j] for j in range(m)) for i in range(n)]


def trapdoor_preimage(trap: Trapdoor, y: Sequence[int]) -> List[int]:
    n, _m = mat_dims(trap.A)
    if len(y) != n:
        raise ValueError("y must have length n")
    yq = [yi % trap.q for yi in y]
    x_prime = bit_decompose_vec(yq, trap.q)
    return mat_vec_mul_int(trap.T, x_prime)
```

### Step 4: Toy Dual-Regev using sk = short preimage x (Ax=y)
This is a minimal Dual-Regev encrypt/decrypt using the “short preimage” secret key. It’s intentionally tiny: we sample small integer errors from a bounded range rather than a discrete Gaussian.

```python
def dual_regev_encrypt(
    A: Matrix,
    y: Sequence[int],
    q: int,
    message_bit: int,
    rng: random.Random,
    error_bound: int,
) -> Tuple[List[int], int]:
    n, m = mat_dims(A)
    if len(y) != n:
        raise ValueError("y must have length n")
    if message_bit not in (0, 1):
        raise ValueError("message_bit must be 0 or 1")

    s = [rng.randrange(q) for _ in range(n)]
    e = [rng.randint(-error_bound, error_bound) for _ in range(m)]
    e_prime = rng.randint(-error_bound, error_bound)

    ct1 = []
    for j in range(m):
        val = sum(s[i] * A[i][j] for i in range(n)) + e[j]
        ct1.append(val % q)

    ct2 = (dot(s, y) + e_prime + message_bit * (q // 2)) % q
    return (ct1, ct2)


def decode_bit_from_mod_q(value: int, q: int) -> int:
    value = value % q

    def circ_dist(a: int, b: int) -> int:
        d = (a - b) % q
        return min(d, q - d)

    d0 = circ_dist(value, 0)
    d1 = circ_dist(value, q // 2)
    return 0 if d0 <= d1 else 1


def dual_regev_decrypt(ct1: Sequence[int], ct2: int, sk_x: Sequence[int], q: int) -> Tuple[int, int]:
    if len(ct1) != len(sk_x):
        raise ValueError("ciphertext/key dimension mismatch")
    inner = dot_mod(ct1, sk_x, q)
    raw = (ct2 - inner) % q
    return (decode_bit_from_mod_q(raw, q), raw)
```

Run it:

```bash
python3 code/main.py
```

## Use It

In real cryptosystems, the “trapdoor inversion” operation is **Gaussian preimage sampling** (not the deterministic `x = T * G^{-1}(y)` we used here). You usually see it inside:

- **GPV-style signatures:** sign by hashing to \(y\), then sampling a short \(x\) with \(Ax=y \pmod q\)
- **Dual-Regev-based IBE/ABE:** secret keys are short preimages \(x\) for identity-/policy-derived targets \(y\)
- **FHE key switching / gadget decomposition:** “gadget ideas” show up even when you don’t explicitly talk about trapdoors

If you’re writing production code, use a vetted lattice library and audited parameters. This lesson is only to make the algebra concrete.

## Pitfalls

- Using a non-power-of-two \(q\) with the same bit decomposition: your `G^{-1}` is no longer a true inverse.
- Shipping deterministic preimages: the structure of \(x\) can leak the trapdoor. Real schemes randomize (discrete Gaussian + perturbation).
- Losing track of shapes/transposes: Dual Regev is extremely sensitive to whether you use \(s^T A\) vs \(A^T s\).
- Letting \(R\) (or \(x\)) get large: the decryption noise term includes an \(e^T x\) inner product.
- Mis-decoding mod-\(q\) values: decoding is on a circle; “close to 0” should treat \(q-1\) as close to 0.

## Ship It

Save `outputs/dual-regev-trapdoor-checklist.md` and use it as a review checklist when you:

- implement gadget decomposition / key switching / “trapdoor-like” matrix constructions
- review papers or PRs that claim “a secret key is a short preimage \(x\) with \(Ax=y\)”
- sanity-check that decryption noise stays below \(q/4\) under your parameter choices

## Exercises

1. **Easy:** Run `python3 code/main.py`. Observe that Step 3 always prints `A x mod q = y`.
2. **Medium:** Increase `error_bound` in `step_4_dual_regev` from 1 up to 5. Find the smallest bound where decryption starts failing (and explain why).
3. **Hard:** Modify the scheme to encrypt 8 bits at once by setting `ct2` to a length-8 vector and decoding each coordinate separately. Keep the same secret key `x`.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Gadget matrix \(G\) | “A special matrix that makes inversion easy” | A structured matrix where every target has a short (often binary) preimage via decomposition |
| Bit decomposition \(G^{-1}\) | “Write in binary” | A deterministic map \(y \mapsto x'\) such that \(Gx'=y \pmod q\) when \(q=2^k\) |
| Trapdoor | “Secret info” | Extra data that lets you find short preimages under a public function \(x \mapsto Ax \bmod q\) |
| Preimage sampling | “Invert \(Ax\)” | Find a short \(x\) such that \(Ax=y \pmod q\), usually with a distribution that hides the trapdoor |
| Dual Regev | “Regev but dual” | An LWE encryption variant where the secret key is a short preimage \(x\) for a public target \(y\) |

## Further Reading

- Micciancio, Peikert, *Trapdoors for Lattices: Simpler, Tighter, Faster, Smaller* (2012) — MP12 trapdoor construction and preimage sampling.
- Wu (course notes), *CS 395T: Topics in Cryptography — Dual Regev* (2024) — concise presentation of Dual Regev and its role in ABE.
- Huang, *Lattice Gadget Trapdoors* (2025) — approachable derivation of \(A=[A' \mid G-A'R]\) and \(AT=G\).
