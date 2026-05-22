# Build a PQ-Secure Messenger

> Combine a lattice KEM, a lattice signature, and HMAC-AEAD into one end-to-end secure channel that survives a quantum computer.

**Type:** Build
**Languages:** Python
**Prerequisites:** LWE/MLWE lattices, Kyber KEM concept, Dilithium signature concept, HKDF, AEAD
**Time:** ~90 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain how Regev LWE encryption encapsulates a shared secret bit-by-bit and why small errors do not break correctness
- Construct a hybrid KEM that is secure if either the classical DH or the lattice KEM is broken
- Implement a Fiat-Shamir lattice signature and understand why the verification equation A·z - c·t = w holds
- Build HMAC-based AEAD with domain-separated subkeys and a length-prefixed MAC input
- Demonstrate a one-step key ratchet and articulate what forward secrecy it provides

## The Problem

Post-quantum cryptography standards (NIST FIPS 203/204/205) were finalised in 2024, but deploying them naively creates new risks. A pure ML-KEM channel is only safe if the underlying lattice assumption holds — and those assumptions have not had decades of real-world scrutiny. A hybrid approach — classical DH plus lattice KEM, combined through a KDF — inherits the security of whichever component remains unbroken, letting you migrate gradually without betting everything on one algorithm.

Authentication is a separate concern. A quantum adversary running Shor's algorithm breaks ECDSA and RSA signatures, enabling man-in-the-middle attacks even if the key exchange is PQ-safe. You need a PQ-safe signature scheme alongside the PQ KEM. Dilithium (now ML-DSA, FIPS 204) is the NIST standard; this lesson builds a conceptually equivalent toy version from first principles.

Finally, key material derived from any KEM is only as safe as the AEAD that uses it. We build an HMAC-based authenticated encryption scheme from scratch so that every component — from the lattice maths to the ciphertext format — is visible and auditable.

## The Concept

### LWE key encapsulation

The Learning With Errors (LWE) problem: given a random matrix A and a vector b = As + e mod q (where s is a secret and e is a small error vector), find s. The noise term makes direct inversion hard.

To send one secret bit m ∈ {0, 1}:

| Step | Who | Operation |
|------|-----|-----------|
| KeyGen | Alice | Sample A, s, e; compute b = As + e mod q; publish (A, b) |
| Encaps | Bob | Sample r, e', e''; compute u = A^T r + e', v = b^T r + e'' + (q/2)·m |
| Decaps | Alice | w = v - s^T u mod q; decide m=0 if w near 0, m=1 if w near q/2 |

Correctness: `v - s^T u = (b^T r + e'' + (q/2)m) - s^T(A^T r + e') = e^T r - s^T e' + e'' + (q/2)m`. With small errors from chi = {-1, 0, +1} and n=8, the noise sum is well below q/4 = 64, so the rounding decision is always correct.

### Hybrid KEM

```
session_key = HKDF(salt, lwe_secret || dh_secret, info, 32)
```

Breaking the session key requires breaking both components simultaneously.

### Fiat-Shamir lattice signature

The scheme: commit to randomness y via w = A·y; hash to get a scalar challenge c; respond with z = y + c·s. Verification: A·z - c·t = A·(y + c·s) - c·(A·s) = A·y = w. Rejection sampling ensures z leaks nothing about s.

### HMAC-AEAD

Two subkeys derived via HKDF with distinct `info` labels prevent cross-use between the keystream PRF and the authentication tag. The MAC input is length-prefixed to prevent canonicalization attacks.

### Key ratchet

After each message direction, advance: `k_next = HKDF(k_curr, b"pq-messenger-ratchet", 32)`. Compromise of k_next cannot reverse to k_curr.

## Build It

### Step 1: Toy LWE KEM

```python
LWE_N = 8        # dimension
LWE_Q = 257      # modulus (prime, fits in uint16)
LWE_HALF = LWE_Q // 2  # 128 — used for bit encoding


def _mod_q(v: int) -> int:
    return v % LWE_Q


def _inner(a, b) -> int:
    return _mod_q(sum(x * y for x, y in zip(a, b)))


def _matvec(M, v) -> list:
    """Matrix-vector product mod q."""
    return [_mod_q(sum(M[i][j] * v[j] for j in range(LWE_N))) for i in range(LWE_N)]


def _vec_add(a, b) -> list:
    return [_mod_q(x + y) for x, y in zip(a, b)]


def _vec_sub(a, b) -> list:
    return [_mod_q(x - y) for x, y in zip(a, b)]


def _sample_chi(rng) -> int:
    return (rng.randbelow(3) - 1) % LWE_Q  # maps -1 -> q-1


def _sample_chi_vec(rng, n: int = LWE_N) -> list:
    return [_sample_chi(rng) for _ in range(n)]


def _sample_uniform_vec(rng, n: int = LWE_N) -> list:
    return [rng.randbelow(LWE_Q) for _ in range(n)]


def _sample_uniform_matrix(rng, rows: int = LWE_N, cols: int = LWE_N) -> list:
    return [[rng.randbelow(LWE_Q) for _ in range(cols)] for _ in range(rows)]


@dataclass
class LWEPublicKey:
    A: list   # n×n matrix
    b: list   # n-vector


@dataclass
class LWEPrivateKey:
    s: list   # n-vector (secret)


@dataclass
class LWECiphertext:
    # Each element: (u_i, v_i) for bit i
    pairs: list


def lwe_keygen(rng=None):
    """Generate LWE keypair."""
    if rng is None:
        rng = _secure_rng()
    A = _sample_uniform_matrix(rng)
    s = _sample_chi_vec(rng)
    e = _sample_chi_vec(rng)
    b = _vec_add(_matvec(A, s), e)
    return LWEPublicKey(A=A, b=b), LWEPrivateKey(s=s)


def lwe_encaps(pk: LWEPublicKey, shared_secret_bits: bytes, rng=None) -> LWECiphertext:
    """
    Encrypt each bit of *shared_secret_bits* (32 bytes = 256 bits).
    Returns ciphertext carrying those bits.
    """
    if rng is None:
        rng = _secure_rng()
    if len(shared_secret_bits) != 32:
        raise ValueError("shared_secret_bits must be 32 bytes")

    A = pk.A
    # Precompute A^T
    AT = [[A[j][i] for j in range(LWE_N)] for i in range(LWE_N)]

    pairs = []
    for byte_val in shared_secret_bits:
        for bit_pos in range(8):
            m = (byte_val >> bit_pos) & 1
            r = _sample_chi_vec(rng)
            e_prime = _sample_chi_vec(rng)
            e_double_prime = _sample_chi(rng)
            u = _vec_add(_matvec(AT, r), e_prime)
            v = _mod_q(_inner(pk.b, r) + e_double_prime + LWE_HALF * m)
            pairs.append((u, v))
    return LWECiphertext(pairs=pairs)


def lwe_decaps(sk: LWEPrivateKey, ct: LWECiphertext) -> bytes:
    """
    Decrypt 256 bits from ciphertext, return 32 bytes.
    Decision: if (v - <s,u>) mod q is closer to 0 than to q/2, bit=0 else bit=1.
    """
    bits = []
    for u, v in ct.pairs:
        w = _mod_q(v - _inner(sk.s, u))
        # Distance to 0 or to LWE_HALF
        d0 = min(w, LWE_Q - w)
        d1 = min(abs(w - LWE_HALF), LWE_Q - abs(w - LWE_HALF))
        bits.append(0 if d0 < d1 else 1)
    # Pack bits into bytes (LSB first per byte)
    result = bytearray()
    for i in range(0, 256, 8):
        byte_val = sum(bits[i + j] << j for j in range(8))
        result.append(byte_val)
    return bytes(result)
```

The key insight: `v - s^T u` collapses the LWE error terms to a small noise value. Rounding to the nearest of {0, q/2} recovers the original bit. With n=8 and chi = {-1,0,+1}, the worst-case noise magnitude is 3×8 = 24, well below q/4 = 64.

### Step 2: HKDF and hybrid KEM

```python
def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)."""
    if not salt:
        salt = b"\x00" * 32
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand: produce *length* bytes of keying material."""
    if length > 255 * 32:
        raise ValueError("HKDF-Expand output too long")
    out = bytearray()
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return bytes(out[:length])


def hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    """Single-call HKDF."""
    prk = hkdf_extract(salt, ikm)
    return hkdf_expand(prk, info, length)


def hybrid_combine(lwe_secret: bytes, dh_secret: bytes, salt: bytes, info: bytes) -> bytes:
    """Combine two raw secrets into a 32-byte session key using HKDF."""
    ikm = lwe_secret + dh_secret
    return hkdf(salt, ikm, info, 32)
```

HKDF separates extraction (absorbing potentially biased raw material into a PRK) from expansion (stretching the PRK into uniform key bytes). The `info` label binds the output to its intended purpose and prevents key reuse across contexts.

### Step 3: Toy lattice signature (Fiat-Shamir)

```python
@dataclass
class SigPublicKey:
    A_sig: list
    t_sig: list   # A·s


@dataclass
class SigPrivateKey:
    s_sig: list
    A_sig: list


@dataclass
class Signature:
    z: list
    c_scalar: int   # challenge as scalar in Z_q


def _hash_to_challenge(w: list, message: bytes) -> int:
    """Hash (w, message) into a scalar challenge c ∈ Z_q."""
    w_bytes = b"".join(v.to_bytes(2, "little") for v in w)
    digest = hashlib.sha256(w_bytes + message).digest()
    return int.from_bytes(digest[:2], "little") % LWE_Q


def sig_keygen(rng=None):
    """Generate signature keypair."""
    if rng is None:
        rng = _secure_rng()
    A_sig = _sample_uniform_matrix(rng)
    s_sig = _sample_chi_vec(rng)
    t_sig = _matvec(A_sig, s_sig)
    return SigPublicKey(A_sig=A_sig, t_sig=t_sig), SigPrivateKey(s_sig=s_sig, A_sig=A_sig)


def sig_sign(sk: SigPrivateKey, message: bytes, rng=None) -> Signature:
    """Sign *message* with *sk*. Retries until rejection sampling passes."""
    if rng is None:
        rng = _secure_rng()
    A_sig = sk.A_sig
    for _attempt in range(1000):
        y = _sample_uniform_vec(rng)
        w = _matvec(A_sig, y)
        # scalar Fiat-Shamir challenge
        c = _hash_to_challenge(w, message)
        # z = y + c * s mod q  (c is a scalar; z is a vector)
        z = [_mod_q(y[i] + c * sk.s_sig[i]) for i in range(LWE_N)]
        # Rejection: keep z away from the "wrap" region (near 0 or q-1)
        B = LWE_Q // 4
        if all(z[i] < B or z[i] > LWE_Q - B for i in range(LWE_N)):
            continue  # reject
        return Signature(z=z, c_scalar=c)
    raise RuntimeError("sig_sign: too many rejections (should not happen with n=8)")


def sig_verify(pk: SigPublicKey, message: bytes, sig: Signature) -> bool:
    """Verify *sig* over *message* with *pk*."""
    A_sig = pk.A_sig
    c = sig.c_scalar
    # w' = A·z - c·t mod q  (c is scalar: multiply every component of t by c)
    Az = _matvec(A_sig, sig.z)
    ct_vec = [_mod_q(c * pk.t_sig[i]) for i in range(LWE_N)]
    w_prime = _vec_sub(Az, ct_vec)
    expected_c = _hash_to_challenge(w_prime, message)
    return expected_c == c
```

The scalar challenge is critical: with `c` scalar, `A·z - c·t = A·(y+c·s) - c·(A·s) = A·y = w`. If `c` were a vector applied element-wise, the identity would not hold.

### Step 4: HMAC-AEAD

```python
def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def _keystream(enc_key: bytes, nonce: bytes, length: int) -> bytes:
    """Generate *length* bytes of keystream using HMAC-SHA256 as a PRF."""
    out = bytearray()
    block = 0
    while len(out) < length:
        blk = _hmac_sha256(enc_key, nonce + struct.pack(">Q", block))
        out += blk
        block += 1
    return bytes(out[:length])


def _aead_mac_input(nonce: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    """Canonical MAC input: nonce || len(aad) [4B] || aad || len(ct) [4B] || ct."""
    return (
        nonce
        + struct.pack(">I", len(aad))
        + aad
        + struct.pack(">I", len(ciphertext))
        + ciphertext
    )


def hmac_aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes):
    """
    Encrypt *plaintext* with HMAC-based AEAD.
    Returns (ciphertext, tag).
    """
    enc_key = hkdf(nonce, key, b"pq-messenger-enc", 32)
    mac_key = hkdf(nonce, key, b"pq-messenger-mac", 32)
    ks = _keystream(enc_key, nonce, len(plaintext))
    ciphertext = bytes(p ^ k for p, k in zip(plaintext, ks))
    tag = _hmac_sha256(mac_key, _aead_mac_input(nonce, aad, ciphertext))
    return ciphertext, tag


def hmac_aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes) -> bytes:
    """
    Decrypt, verifying the tag first.
    Raises ValueError on authentication failure.
    """
    enc_key = hkdf(nonce, key, b"pq-messenger-enc", 32)
    mac_key = hkdf(nonce, key, b"pq-messenger-mac", 32)
    expected_tag = _hmac_sha256(mac_key, _aead_mac_input(nonce, aad, ciphertext))
    if not hmac.compare_digest(expected_tag, tag):
        raise ValueError("AEAD authentication failed")
    ks = _keystream(enc_key, nonce, len(ciphertext))
    return bytes(c ^ k for c, k in zip(ciphertext, ks))
```

Always verify the tag before decrypting. `hmac.compare_digest` prevents timing attacks on the tag comparison. Length prefixes on the MAC input prevent splice attacks where an adversary reorders or concatenates AAD and ciphertext.

### Step 5: Key ratchet and Alice-Bob exchange

```python
def ratchet_key(current_key: bytes) -> bytes:
    """Derive next session key: KDF(current_key, 'ratchet')."""
    return hkdf(b"", current_key, b"pq-messenger-ratchet", 32)
```

In the messenger demo, Alice generates the LWE keypair; Bob encapsulates a random 32-byte value under her public key; both parties combine the LWE secret and the DH shared secret via HKDF. Alice authenticates her DH public key with a lattice signature to prevent MITM. After Alice's first message, both advance to a ratcheted key before Bob replies.

Run it:
```
python3 code/main.py
```

## Use It

In production, replace each toy component with its NIST-standardised equivalent:

| Toy component | Production replacement | Standard |
|---------------|----------------------|----------|
| Toy LWE KEM (n=8, q=257) | ML-KEM-768 | NIST FIPS 203 |
| Tiny DH over M_127 | X25519 or P-256 (hybrid) | RFC 7748 / NIST SP 800-186 |
| Toy Fiat-Shamir signature | ML-DSA-65 | NIST FIPS 204 |
| HMAC-AEAD | AES-256-GCM or ChaCha20-Poly1305 | NIST SP 800-38D / RFC 8439 |
| Single ratchet | Signal Double Ratchet | https://signal.org/docs/specifications/doubleratchet/ |

Python libraries: `cryptography` (PyCA) for AES-GCM and X25519; `pqcrypto` or `liboqs-python` for ML-KEM and ML-DSA.

## Pitfalls

- Reusing a nonce with the same key under HMAC-AEAD leaks the XOR of two plaintexts, exactly as with AES-CTR. Increment the nonce counter for every message.
- Omitting the length prefixes from the MAC input opens a canonicalization attack: an adversary can swap bytes between AAD and ciphertext, producing a different (AAD', CT') pair with the same tag.
- Using the same key for both enc_key and mac_key makes it possible to relate the keystream output to the tag. Always domain-separate keys via distinct HKDF info labels.
- The toy signature's rejection rate depends on the "danger zone" threshold B. If B is too tight, signing loops forever; if too loose, the response z leaks information about s. Real Dilithium uses carefully chosen bounds.
- A single forward-hash ratchet does not provide break-in recovery: an adversary who steals k_curr can compute all future keys. The Signal Double Ratchet interleaves DH steps to limit the damage window.

## Ship It

Save the PQ migration decision guide to `outputs/pq-migration-guide.md`. It documents the primitive-by-primitive migration map, a hybrid KEM construction template, and a timeline for deprecating classical-only cipher suites.

## Exercises

1. Easy. Run `python3 code/main.py`. Confirm all five steps complete and both messages decrypt correctly.
2. Medium. Modify `lwe_encaps` / `lwe_decaps` to use n=16 and q=521 and verify that the KEM still round-trips. How does the ciphertext size change?
3. Hard. Implement a two-step Double Ratchet: after each exchange, both parties perform a new DH step, derive the next root key via HKDF, and advance the sending/receiving chain keys. Show that an adversary who learns one chain key cannot recover the root key or future chain keys.

## Key Terms

| Term | What people say | What it actually means |
|------|-----------------|------------------------|
| LWE | "A lattice problem" | Given (A, As+e) find s; believed hard classically and quantum-mechanically |
| KEM | "A key exchange algorithm" | Key Encapsulation Mechanism: encapsulate a random secret under a public key, decapsulate with the private key |
| Hybrid KEM | "Belt and suspenders crypto" | Session key derived from both a classical and a PQ shared secret; secure if either component holds |
| Fiat-Shamir | "Turning interactive proofs into signatures" | Hash the commitment to produce a non-interactive challenge; security relies on the random-oracle assumption |
| AEAD | "Authenticated encryption" | Encryption scheme that simultaneously provides confidentiality and integrity; any tampering is detected |
| Key ratchet | "Forward secrecy via key evolution" | Deterministically advance a key forward; past traffic is protected even if the current key is compromised |
| HNDL | "Harvest now, decrypt later" | Adversaries record encrypted traffic today to decrypt once a CRQC exists; motivates urgent PQ KEM migration |

## Further Reading

- Regev, "On Lattices, Learning With Errors, Random Linear Codes, and Cryptography" (2005) — the foundational LWE paper
- NIST FIPS 203 (2024) — ML-KEM (production Kyber): https://csrc.nist.gov/pubs/fips/203/final
- NIST FIPS 204 (2024) — ML-DSA (production Dilithium): https://csrc.nist.gov/pubs/fips/204/final
- Lyubashevsky, "Lattice Signatures Without Trapdoors" (2012) — the Fiat-Shamir-with-aborts construction this lesson simplifies
- Marlinspike & Perrin, "The Double Ratchet Algorithm" (2016) — https://signal.org/docs/specifications/doubleratchet/
- Krawczyk & Eronen, RFC 5869 — HKDF: https://www.rfc-editor.org/rfc/rfc5869
