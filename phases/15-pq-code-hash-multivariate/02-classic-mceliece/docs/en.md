# Classic McEliece (Toy) — Hide a Decoder Behind a Random Matrix
> A public key that looks random; a secret key that can decode.

**Type:** Build
**Languages:** Python
**Prerequisites:** `phases/06-coding-theory/01-linear-codes/`, `phases/06-coding-theory/03-hamming-codes/`, `phases/15-pq-code-hash-multivariate/01-mceliece/`
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain McEliece’s “trapdoor decoding” idea in one sentence
- Compute how `G_pub = S * G_base * P` hides structure over GF(2)
- Implement a tiny linear-code encoder/decoder over GF(2) (Hamming(7,4))
- Distinguish “textbook McEliece PKE” from “Classic McEliece KEM” packaging
- Apply basic implementation checks (dimensions, invertibility, error weight `t`)

## The Problem
You want post-quantum public-key encryption built on a *different hardness assumption* than lattices. Code-based crypto is one of the oldest candidates: it turns “decoding a random linear code with errors” into the hard problem.

But there’s a catch: decoding is only fast for *structured* codes (like binary Goppa codes). If you publish that structure, attackers decode too. So the engineering question becomes: **how do you publish something that looks like a random code while keeping a private decoder as a trapdoor?**

This lesson builds a toy “Classic McEliece–style” scheme end-to-end so you can reason about (1) key generation as “hide the decoder”, (2) encryption as “encode + add a fixed-weight error”, and (3) decryption as “undo permutation + decode + undo scrambler”.

## The Concept
McEliece lives in binary linear codes. A code of length `n` and dimension `k` can be described by a `k×n` generator matrix `G`. A message `m` (a `k`-bit row vector) encodes to a codeword:

`c = m * G`  (all arithmetic is mod 2 / XOR).

To make encryption probabilistic, you add an error vector `e` of small Hamming weight:

`ct = c ⊕ e`.

Decoding “given `ct`, find the closest codeword” is hard for a random code — that hardness is what we want publicly. But the legitimate receiver keeps a structured code with a fast decoder as a trapdoor:

- Choose a decodable base code with generator matrix `G_base` (in real Classic McEliece: a binary Goppa code).
- Sample an invertible `k×k` binary matrix `S` (“scrambler”).
- Sample a permutation of the `n` columns `P` (“shuffle columns”).
- Publish `G_pub = S * G_base * P`.

Then:
- Encrypt with `G_pub`.
- Decrypt by undoing the permutation (so the decoder sees the base code again), decoding, and undoing `S`.

In this lesson, we use **Hamming(7,4)** as `G_base` so we can decode with only XORs and a tiny brute-force nearest-codeword decoder. This is *not* secure (tiny parameters), but it makes the mechanics visible.

## Build It

### Step 1: GF(2) linear algebra (matrices, inverses, permutations)
```python
def _assert_bit(x: int) -> None:
    if x not in (0, 1):
        raise ValueError("bit must be 0 or 1")


def assert_bits(v: list[int], *, length: int | None = None) -> None:
    if length is not None and len(v) != length:
        raise ValueError(f"expected {length} bits, got {len(v)}")
    for b in v:
        _assert_bit(b)


def assert_matrix(m: list[list[int]], *, rows: int | None = None, cols: int | None = None) -> None:
    if rows is not None and len(m) != rows:
        raise ValueError(f"expected {rows} rows, got {len(m)}")
    if len(m) == 0:
        if cols not in (None, 0):
            raise ValueError("empty matrix has 0 columns")
        return
    width = len(m[0])
    if cols is not None and width != cols:
        raise ValueError(f"expected {cols} cols, got {width}")
    for r in m:
        if len(r) != width:
            raise ValueError("ragged matrix")
        assert_bits(r)


def hamming_weight(v: list[int]) -> int:
    assert_bits(v)
    return sum(v)


def gf2_identity(n: int) -> list[list[int]]:
    if n < 0:
        raise ValueError("n must be non-negative")
    return [[1 if i == j else 0 for j in range(n)] for i in range(n)]


def gf2_row_vec_mul_mat(v: list[int], m: list[list[int]]) -> list[int]:
    assert_bits(v)
    assert_matrix(m)
    if len(m) != len(v):
        raise ValueError("dimension mismatch for row_vec_mul_mat")
    if len(m) == 0:
        return []
    out = [0] * len(m[0])
    for i, vi in enumerate(v):
        if vi == 0:
            continue
        row = m[i]
        for j, aij in enumerate(row):
            out[j] ^= aij
    return out


def gf2_mat_vec_mul(m: list[list[int]], v: list[int]) -> list[int]:
    assert_matrix(m)
    assert_bits(v)
    if len(m) == 0:
        return []
    if len(m[0]) != len(v):
        raise ValueError("dimension mismatch for mat_vec_mul")
    out = []
    for row in m:
        acc = 0
        for aij, vj in zip(row, v, strict=True):
            acc ^= (aij & vj)
        out.append(acc)
    return out


def gf2_mat_mul(a: list[list[int]], b: list[list[int]]) -> list[list[int]]:
    assert_matrix(a)
    assert_matrix(b)
    if len(a) == 0:
        return []
    if len(b) == 0:
        raise ValueError("cannot multiply by empty matrix with unknown column count")
    if len(a[0]) != len(b):
        raise ValueError("dimension mismatch for mat_mul")

    rows = len(a)
    inner = len(b)
    cols = len(b[0])
    out = [[0] * cols for _ in range(rows)]
    for i in range(rows):
        for k in range(inner):
            if a[i][k] == 0:
                continue
            bk = b[k]
            for j in range(cols):
                out[i][j] ^= bk[j]
    return out


def gf2_matrix_inv(a: list[list[int]]) -> list[list[int]]:
    assert_matrix(a)
    n = len(a)
    if n == 0:
        return []
    if len(a[0]) != n:
        raise ValueError("matrix must be square to invert")

    left = [row[:] for row in a]
    right = gf2_identity(n)

    col = 0
    for row in range(n):
        pivot = None
        for r in range(row, n):
            if left[r][col] == 1:
                pivot = r
                break
        while pivot is None:
            col += 1
            if col >= n:
                raise ValueError("matrix is not invertible over GF(2)")
            for r in range(row, n):
                if left[r][col] == 1:
                    pivot = r
                    break

        if pivot != row:
            left[row], left[pivot] = left[pivot], left[row]
            right[row], right[pivot] = right[pivot], right[row]

        for r in range(n):
            if r == row:
                continue
            if left[r][col] == 1:
                for j in range(n):
                    left[r][j] ^= left[row][j]
                    right[r][j] ^= right[row][j]

        col += 1

    if left != gf2_identity(n):
        raise ValueError("matrix inversion failed")
    return right


def invert_permutation(perm: list[int]) -> list[int]:
    n = len(perm)
    inv = [0] * n
    seen = [False] * n
    for i, p in enumerate(perm):
        if not (0 <= p < n):
            raise ValueError("permutation entries must be in range")
        if seen[p]:
            raise ValueError("permutation has duplicates")
        seen[p] = True
        inv[p] = i
    return inv


def apply_permutation(v: list[int], perm: list[int]) -> list[int]:
    assert_bits(v)
    if len(v) != len(perm):
        raise ValueError("dimension mismatch for apply_permutation")
    return [v[p] for p in perm]


def apply_permutation_to_columns(m: list[list[int]], perm: list[int]) -> list[list[int]]:
    assert_matrix(m)
    if len(m) == 0:
        return []
    if len(m[0]) != len(perm):
        raise ValueError("dimension mismatch for apply_permutation_to_columns")
    out = []
    for row in m:
        out.append([row[p] for p in perm])
    return out
```
This is the “plumbing”: XOR-only linear algebra over GF(2), plus a concrete permutation convention we’ll use for both vectors and generator-matrix columns.

### Step 2: A tiny decodable code (Hamming(7,4))
```python
HAMMING74_G: list[list[int]] = [
    [1, 1, 1, 0, 0, 0, 0],
    [1, 0, 0, 1, 1, 0, 0],
    [0, 1, 0, 1, 0, 1, 0],
    [1, 1, 0, 1, 0, 0, 1],
]

HAMMING74_H: list[list[int]] = [
    [1, 0, 1, 0, 1, 0, 1],
    [0, 1, 1, 0, 0, 1, 1],
    [0, 0, 0, 1, 1, 1, 1],
]


def hamming74_encode(msg: list[int]) -> list[int]:
    assert_bits(msg, length=4)
    return gf2_row_vec_mul_mat(msg, HAMMING74_G)


def hamming74_syndrome(word: list[int]) -> list[int]:
    assert_bits(word, length=7)
    return gf2_mat_vec_mul(HAMMING74_H, word)


def _syndrome_to_position(syndrome: list[int]) -> int:
    assert_bits(syndrome, length=3)
    return syndrome[0] + 2 * syndrome[1] + 4 * syndrome[2]


def hamming_distance(a: list[int], b: list[int]) -> int:
    assert_bits(a)
    assert_bits(b)
    if len(a) != len(b):
        raise ValueError("dimension mismatch for hamming_distance")
    return sum((x ^ y) for x, y in zip(a, b, strict=True))


def hamming74_decode_nearest(received: list[int], *, t: int = 1) -> list[int]:
    assert_bits(received, length=7)
    if t < 0:
        raise ValueError("t must be non-negative")

    best_msg: list[int] | None = None
    best_dist: int | None = None
    ties = 0
    for m in range(16):
        msg = [(m >> 3) & 1, (m >> 2) & 1, (m >> 1) & 1, m & 1]
        codeword = hamming74_encode(msg)
        dist = hamming_distance(codeword, received)
        if best_dist is None or dist < best_dist:
            best_dist = dist
            best_msg = msg
            ties = 1
        elif dist == best_dist:
            ties += 1

    if best_msg is None or best_dist is None:
        raise ValueError("decode failed")
    if ties != 1:
        raise ValueError("decode is ambiguous")
    if best_dist > t:
        raise ValueError("too many errors to correct")
    return best_msg
```
Hamming(7,4) gives us a compact, fully decodable base code. In real Classic McEliece the base code is a much larger binary Goppa code with an efficient decoder; here we use nearest-codeword decoding only because `k=4` is tiny.

### Step 3: Key generation (scramble + permute the generator matrix)
```python
@dataclass(frozen=True)
class PublicKey:
    k: int
    n: int
    t: int
    g_pub: list[list[int]]


@dataclass(frozen=True)
class PrivateKey:
    k: int
    n: int
    t: int
    g_base: list[list[int]]
    s: list[list[int]]
    s_inv: list[list[int]]
    perm: list[int]
    perm_inv: list[int]


def _random_invertible_matrix(k: int, rng: Random) -> list[list[int]]:
    if k <= 0:
        raise ValueError("k must be positive")
    for _attempt in range(10_000):
        m = [[rng.randrange(2) for _ in range(k)] for _ in range(k)]
        try:
            gf2_matrix_inv(m)
        except ValueError:
            continue
        return m
    raise ValueError("failed to sample an invertible matrix")


def classic_mceliece_keygen_hamming74(*, rng: Random | None = None) -> tuple[PublicKey, PrivateKey]:
    if rng is None:
        rng = Random()

    g_base = [row[:] for row in HAMMING74_G]
    k = 4
    n = 7
    t = 1

    s = _random_invertible_matrix(k, rng)
    s_inv = gf2_matrix_inv(s)
    perm = list(range(n))
    rng.shuffle(perm)
    perm_inv = invert_permutation(perm)

    g_scrambled = gf2_mat_mul(s, g_base)
    g_pub = apply_permutation_to_columns(g_scrambled, perm)

    pub = PublicKey(k=k, n=n, t=t, g_pub=g_pub)
    priv = PrivateKey(k=k, n=n, t=t, g_base=g_base, s=s, s_inv=s_inv, perm=perm, perm_inv=perm_inv)
    return pub, priv


def classic_mceliece_keygen_hamming74_with_secrets(
    *, s: list[list[int]], perm: list[int]
) -> tuple[PublicKey, PrivateKey]:
    k = 4
    n = 7
    t = 1
    assert_matrix(s, rows=k, cols=k)
    if len(perm) != n:
        raise ValueError("bad permutation length")

    s_inv = gf2_matrix_inv(s)
    perm_inv = invert_permutation(perm)
    g_base = [row[:] for row in HAMMING74_G]
    g_scrambled = gf2_mat_mul(s, g_base)
    g_pub = apply_permutation_to_columns(g_scrambled, perm)

    pub = PublicKey(k=k, n=n, t=t, g_pub=g_pub)
    priv = PrivateKey(k=k, n=n, t=t, g_base=g_base, s=s, s_inv=s_inv, perm=perm, perm_inv=perm_inv)
    return pub, priv
```
This is the heart of McEliece: `G_pub` is just a scrambled-and-permuted generator matrix. Without the hidden decoder, `G_pub` should look like a random code.

### Step 4: Encrypt and decrypt (encode + add errors; undo + decode)
```python
def classic_mceliece_encrypt(pub: PublicKey, msg: list[int], err: list[int]) -> list[int]:
    assert_bits(msg, length=pub.k)
    assert_bits(err, length=pub.n)
    if hamming_weight(err) > pub.t:
        raise ValueError("error weight exceeds decoder capability t")
    codeword = gf2_row_vec_mul_mat(msg, pub.g_pub)
    return [c ^ e for c, e in zip(codeword, err, strict=True)]


def classic_mceliece_decrypt(priv: PrivateKey, ct: list[int]) -> list[int]:
    assert_bits(ct, length=priv.n)
    ct_unperm = apply_permutation(ct, priv.perm_inv)
    u = hamming74_decode_nearest(ct_unperm, t=priv.t)
    msg = gf2_row_vec_mul_mat(u, priv.s_inv)
    assert_bits(msg, length=priv.k)
    return msg
```
Encryption is “linear codeword + small error”. Decryption reverses the public-key scrambling and applies the private decoder; if `t` is exceeded, you should expect decryption to output garbage (real Classic McEliece wraps this in a CCA-secure KEM and does consistency checks).

Run it:
python3 code/main.py

## Use It
- **Classic McEliece (real):** a code-based KEM built around binary Goppa codes, constant-time decapsulation checks, and large public keys. Use an audited implementation (e.g., the Classic McEliece project’s published code and integrations) rather than rolling your own.
- **What to compare to this toy:**
  - Real parameter sizes (`n`, `k`, `t`) are *huge* vs `(7,4,1)`.
  - Real decoders are algebraic and constant-time; ours brute-forces 16 candidates.
  - Real systems are KEMs with CCA transforms; ours is textbook PKE.

## Pitfalls
- **Mixing conventions:** “row-vector times `k×n` matrix” vs “`n×k` times column-vector” silently breaks everything unless you lock a convention and test it.
- **Assuming you can detect “too many errors”:** plain Hamming(7,4) decoding will happily output *some* message even for 2-bit corruption; real KEMs include consistency checks to avoid key mismatch.
- **Non-constant-time decoding:** decoding is the hottest side-channel surface. Branches on secret-dependent data can leak the private key structure.
- **Bad randomness / wrong error distribution:** Classic McEliece uses fixed-weight errors and careful RNG; sloppy sampling can destroy security or break decapsulation.
- **Key-size blindness:** code-based schemes buy different security assumptions, but the trade-off is big public keys; you must plan for bandwidth/storage.

## Ship It
Create a reusable review artifact at `outputs/classic-mceliece-review-checklist.md`. Use it when:
- reviewing PRs that add Classic McEliece (or any code-based KEM) to an app,
- writing a threat model for “decoder-as-trapdoor” systems,
- sanity-checking parameters, key sizes, RNG, and constant-time constraints.

## Exercises
1. Easy. Run `python3 code/main.py`. Observe how `perm_inv` is used in decryption and how a 1-bit error is corrected.
2. Medium. Extend `code/main.py` to add a “SECDED” variant: append an overall parity bit to make an (8,4) extended Hamming code and demonstrate that some 2-bit corruptions are detected (rejected) instead of silently miscorrected.
3. Hard. Production integration: evaluate a real Classic McEliece KEM implementation in a small demo app. Record public key size, ciphertext size, and decapsulation behavior under fault injection (bit flips) to see how CCA transforms prevent silent key mismatch.

## Key Terms
| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Linear code | “A set of valid codewords” | A `k`-dimensional subspace of `{0,1}^n` described by a generator matrix |
| Generator matrix `G` | “The code” | A `k×n` matrix whose rows span the code; encoding is `m*G` |
| Decoder (trapdoor) | “The secret sauce” | An efficient algorithm for finding the closest codeword for a structured code |
| Scrambler `S` | “Hide the code” | An invertible `k×k` matrix that re-bases the message space, hiding structure |
| Permutation `P` | “Shuffle bits” | A column permutation that preserves Hamming weight while hiding the base code’s layout |

## Further Reading
- Robert J. McEliece, *A Public-Key Cryptosystem Based on Algebraic Coding Theory* (1978) — the original code-based PKE proposal.
- Daniel J. Bernstein et al., *Classic McEliece* (2019–2022) — submission documents and rationale for the modern parameter sets.
- NIST, *Announcing PQC Candidates to be Standardized, Plus Fourth Round Candidates* (2022) — why Classic McEliece continued into Round 4.
