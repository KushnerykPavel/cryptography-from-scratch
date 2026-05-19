# RSA Padding — PKCS#1 v1.5, OAEP, PSS

> Padding turns RSA from “math” into a protocol: it adds structure, randomness, and checks that remove whole classes of attacks.

**Type:** Build  
**Languages:** Python  
**Prerequisites:** Phase 08 · 01 (RSA), Phase 07 · hashing basics  
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain why textbook RSA is unsafe for encryption and signatures.
- Distinguish PKCS#1 v1.5 vs OAEP vs PSS by purpose and properties.
- Implement OAEP encoding/decoding and use it for RSA encryption.
- Implement PSS encoding/verification and use it for RSA signatures.
- Apply a padding choice checklist to real-world library usage and audits.

## The Problem

You generate an RSA keypair and do the obvious thing: turn your message into an integer `m`, compute `c = m^e mod n`, and send `c`. It “works”: the receiver computes `m = c^d mod n` and recovers the plaintext.

Then production breaks you.

Textbook RSA encryption is deterministic (same plaintext → same ciphertext), malleable (an attacker can transform a ciphertext into a related ciphertext without knowing the key), and has no integrity. Textbook RSA signatures are equally brittle: without a carefully structured, hash-bound encoding, signatures become forgeries and weird parsing bugs.

Padding is the missing piece: it makes RSA probabilistic for encryption (OAEP), gives signatures an unambiguous encoding (PKCS#1 v1.5) and a modern randomized variant (PSS), and defines what “valid” decrypted blocks look like so implementations can reject malformed inputs safely.

## The Concept

RSA is a trapdoor permutation on integers modulo `n`:

- Encrypt (public): `c = m^e mod n`
- Decrypt (private): `m = c^d mod n`

The problems start because “any integer < n” is a gigantic space with no structure. Padding schemes solve this by defining a byte-level *encoded message* `EM` of fixed length `k = ceil(log256(n))` and only allowing `EM` that follow a strict format.

Three schemes you must recognize:

| Scheme | Used for | Randomized? | What it buys you |
|--------|----------|-------------|------------------|
| **PKCS#1 v1.5 (encryption)** | legacy encryption (`RSAES-PKCS1-v1_5`) | yes | simple structure, but has serious chosen-ciphertext pitfalls; avoid for new designs |
| **OAEP (encryption)** | modern encryption (`RSAES-OAEP`) | yes | IND-CCA-style safety goal when implemented correctly; the default choice for RSA encryption |
| **PSS (signatures)** | modern signatures (`RSASSA-PSS`) | yes | tight security proofs and robust encoding; recommended signature padding |

Two recurring building blocks:

- `I2OSP/OS2IP`: integer ↔ bytes conversion of *exactly* `k` bytes.
- `MGF1`: a mask generation function (`MGF1(seed, L)`) built from a hash, used to “spread” randomness across the whole block.

OAEP summary (for `k` bytes, hash output length `hLen`):

1. Build `DB = lHash || PS || 0x01 || M` where `lHash = Hash(label)` and `PS` is zero bytes.
2. Choose random `seed` (`hLen` bytes).
3. `maskedDB = DB XOR MGF1(seed, k - hLen - 1)`
4. `maskedSeed = seed XOR MGF1(maskedDB, hLen)`
5. `EM = 0x00 || maskedSeed || maskedDB`

PSS summary (for `emBits = nBits - 1`):

1. Hash message: `mHash = Hash(M)`.
2. Choose random `salt`.
3. Hash: `H = Hash(0x00..00(8) || mHash || salt)`.
4. Build `DB = PS || 0x01 || salt` and mask it with `MGF1(H, ...)`.
5. `EM = maskedDB || H || 0xbc` with a “leftmost bits must be zero” rule.

These aren’t “implementation details”. They define what is *valid*. Attackers live in invalid inputs.

## Build It

### Step 1: Bytes and masks (I2OSP/OS2IP, XOR, MGF1)

```python
import hashlib


def i2osp(x: int, x_len: int) -> bytes:
    if x < 0:
        raise ValueError("i2osp: negative integer")
    if x >= 256**x_len:
        raise ValueError("i2osp: integer too large")
    return x.to_bytes(x_len, "big")


def os2ip(x: bytes) -> int:
    return int.from_bytes(x, "big")


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor_bytes: length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))


def mgf1(seed: bytes, mask_len: int, hash_name: str = "sha256") -> bytes:
    h_len = hashlib.new(hash_name).digest_size
    if mask_len < 0:
        raise ValueError("mgf1: negative length")
    if mask_len > (2**32) * h_len:
        raise ValueError("mgf1: mask too long")

    out = bytearray()
    for counter in range(0, -(-mask_len // h_len)):
        c = counter.to_bytes(4, "big")
        out.extend(hashlib.new(hash_name, seed + c).digest())
    return bytes(out[:mask_len])
```

RSA padding is byte-oriented. Everything downstream assumes “fixed length `k` bytes” and uses `MGF1` as a hash-based expander so a short random seed can mask a whole block.

### Step 2: PKCS#1 v1.5 encryption padding (legacy)

```python
import secrets


def eme_pkcs1_v1_5_encode(
    message: bytes,
    k: int,
    *,
    ps: bytes | None = None,
    rng: secrets.SystemRandom | None = None,
) -> bytes:
    if len(message) > k - 11:
        raise ValueError("eme_pkcs1_v1_5_encode: message too long")

    ps_len = k - len(message) - 3
    if ps is None:
        rng = rng or secrets.SystemRandom()
        ps_buf = bytearray()
        while len(ps_buf) < ps_len:
            b = rng.randrange(1, 256)
            ps_buf.append(b)
        ps = bytes(ps_buf)

    if len(ps) != ps_len:
        raise ValueError("eme_pkcs1_v1_5_encode: bad PS length")
    if any(b == 0 for b in ps):
        raise ValueError("eme_pkcs1_v1_5_encode: PS must be nonzero")

    return b"\x00\x02" + ps + b"\x00" + message


def eme_pkcs1_v1_5_decode(em: bytes) -> bytes:
    if len(em) < 11:
        raise ValueError("eme_pkcs1_v1_5_decode: decryption error")
    if em[0] != 0x00 or em[1] != 0x02:
        raise ValueError("eme_pkcs1_v1_5_decode: decryption error")

    try:
        sep = em.index(b"\x00", 2)
    except ValueError as exc:
        raise ValueError("eme_pkcs1_v1_5_decode: decryption error") from exc

    if sep < 10:
        raise ValueError("eme_pkcs1_v1_5_decode: decryption error")
    if any(b == 0 for b in em[2:sep]):
        raise ValueError("eme_pkcs1_v1_5_decode: decryption error")
    return em[sep + 1 :]
```

This is the historical RSA encryption padding: `00 02 || PS(nonzero) || 00 || M`. It is randomized, but decryption-oracle behavior (how you reject malformed blocks) has a long history of catastrophic attacks, so modern protocols prefer OAEP.

### Step 3: OAEP encode/decode (encryption padding)

```python
import hashlib
import secrets


def oaep_encode(
    message: bytes,
    k: int,
    *,
    label: bytes = b"",
    hash_name: str = "sha256",
    seed: bytes | None = None,
    rng: secrets.SystemRandom | None = None,
) -> bytes:
    h_len = hashlib.new(hash_name).digest_size
    if k < 2 * h_len + 2:
        raise ValueError("oaep_encode: modulus too short")
    if len(message) > k - 2 * h_len - 2:
        raise ValueError("oaep_encode: message too long")

    l_hash = hashlib.new(hash_name, label).digest()
    ps = b"\x00" * (k - len(message) - 2 * h_len - 2)
    db = l_hash + ps + b"\x01" + message

    if seed is None:
        rng = rng or secrets.SystemRandom()
        seed = bytes(rng.randrange(0, 256) for _ in range(h_len))
    if len(seed) != h_len:
        raise ValueError("oaep_encode: bad seed length")

    db_mask = mgf1(seed, k - h_len - 1, hash_name)
    masked_db = xor_bytes(db, db_mask)
    seed_mask = mgf1(masked_db, h_len, hash_name)
    masked_seed = xor_bytes(seed, seed_mask)
    return b"\x00" + masked_seed + masked_db


def oaep_decode(
    em: bytes,
    k: int,
    *,
    label: bytes = b"",
    hash_name: str = "sha256",
) -> bytes:
    h_len = hashlib.new(hash_name).digest_size
    if len(em) != k:
        raise ValueError("oaep_decode: decryption error")
    if k < 2 * h_len + 2:
        raise ValueError("oaep_decode: decryption error")
    if em[0] != 0x00:
        raise ValueError("oaep_decode: decryption error")

    masked_seed = em[1 : 1 + h_len]
    masked_db = em[1 + h_len :]
    seed_mask = mgf1(masked_db, h_len, hash_name)
    seed = xor_bytes(masked_seed, seed_mask)
    db_mask = mgf1(seed, k - h_len - 1, hash_name)
    db = xor_bytes(masked_db, db_mask)

    l_hash = hashlib.new(hash_name, label).digest()
    if db[:h_len] != l_hash:
        raise ValueError("oaep_decode: decryption error")

    rest = db[h_len:]
    one_pos = rest.find(b"\x01")
    if one_pos == -1:
        raise ValueError("oaep_decode: decryption error")
    if any(b != 0 for b in rest[:one_pos]):
        raise ValueError("oaep_decode: decryption error")
    return rest[one_pos + 1 :]
```

OAEP takes a short random `seed` and mixes it into the entire `EM`. The decoder re-derives masks, unmasks, and then validates a very specific structure (`lHash`, zero padding, then a single `0x01` separator). “Reject malformed blocks” is part of the design, not an afterthought.

### Step 4: RSA-OAEP encrypt/decrypt + RSA-PSS sign/verify

```python
import hashlib
import secrets


def rsaep(n: int, e: int, m: int) -> int:
    if m < 0 or m >= n:
        raise ValueError("rsaep: message representative out of range")
    return pow(m, e, n)


def rsadp(n: int, d: int, c: int) -> int:
    if c < 0 or c >= n:
        raise ValueError("rsadp: ciphertext representative out of range")
    return pow(c, d, n)


def rsaes_oaep_encrypt(
    message: bytes,
    n: int,
    e: int,
    *,
    label: bytes = b"",
    hash_name: str = "sha256",
    seed: bytes | None = None,
) -> bytes:
    k = (n.bit_length() + 7) // 8
    em = oaep_encode(message, k, label=label, hash_name=hash_name, seed=seed)
    c = rsaep(n, e, os2ip(em))
    return i2osp(c, k)


def rsaes_oaep_decrypt(
    ciphertext: bytes,
    n: int,
    d: int,
    *,
    label: bytes = b"",
    hash_name: str = "sha256",
) -> bytes:
    k = (n.bit_length() + 7) // 8
    if len(ciphertext) != k:
        raise ValueError("rsaes_oaep_decrypt: decryption error")
    m = rsadp(n, d, os2ip(ciphertext))
    em = i2osp(m, k)
    return oaep_decode(em, k, label=label, hash_name=hash_name)


def pss_encode(
    message_hash: bytes,
    em_bits: int,
    *,
    hash_name: str = "sha256",
    salt: bytes | None = None,
    salt_len: int | None = None,
    rng: secrets.SystemRandom | None = None,
) -> bytes:
    h_len = hashlib.new(hash_name).digest_size
    if len(message_hash) != h_len:
        raise ValueError("pss_encode: bad hash length")

    if salt is None:
        salt_len = h_len if salt_len is None else salt_len
        rng = rng or secrets.SystemRandom()
        salt = bytes(rng.randrange(0, 256) for _ in range(salt_len))

    s_len = len(salt)
    em_len = (em_bits + 7) // 8
    if em_len < h_len + s_len + 2:
        raise ValueError("pss_encode: encoding error")

    m_prime = b"\x00" * 8 + message_hash + salt
    h = hashlib.new(hash_name, m_prime).digest()
    ps = b"\x00" * (em_len - s_len - h_len - 2)
    db = ps + b"\x01" + salt
    db_mask = mgf1(h, em_len - h_len - 1, hash_name)
    masked_db = bytearray(xor_bytes(db, db_mask))

    left = 8 * em_len - em_bits
    if left:
        masked_db[0] &= 0xFF >> left

    return bytes(masked_db) + h + b"\xbc"


def pss_verify(
    message_hash: bytes,
    em: bytes,
    em_bits: int,
    *,
    hash_name: str = "sha256",
    salt_len: int | None = None,
) -> bool:
    h_len = hashlib.new(hash_name).digest_size
    if len(message_hash) != h_len:
        return False

    em_len = (em_bits + 7) // 8
    salt_len = h_len if salt_len is None else salt_len
    if len(em) != em_len:
        return False
    if em_len < h_len + salt_len + 2:
        return False
    if em[-1] != 0xBC:
        return False

    masked_db = em[: em_len - h_len - 1]
    h = em[em_len - h_len - 1 : em_len - 1]

    left = 8 * em_len - em_bits
    if left and (masked_db[0] & (0xFF << (8 - left))) != 0:
        return False

    db_mask = mgf1(h, em_len - h_len - 1, hash_name)
    db = bytearray(xor_bytes(masked_db, db_mask))
    if left:
        db[0] &= 0xFF >> left

    ps_len = em_len - h_len - salt_len - 2
    if any(b != 0 for b in db[:ps_len]):
        return False
    if db[ps_len] != 0x01:
        return False

    salt = bytes(db[-salt_len:])
    m_prime = b"\x00" * 8 + message_hash + salt
    h2 = hashlib.new(hash_name, m_prime).digest()
    return h == h2


def rsassa_pss_sign(
    message: bytes,
    n: int,
    d: int,
    *,
    hash_name: str = "sha256",
    salt: bytes | None = None,
    salt_len: int | None = None,
) -> bytes:
    k = (n.bit_length() + 7) // 8
    em_bits = n.bit_length() - 1
    m_hash = hashlib.new(hash_name, message).digest()
    em = pss_encode(m_hash, em_bits, hash_name=hash_name, salt=salt, salt_len=salt_len)
    s = rsadp(n, d, os2ip(em))
    return i2osp(s, k)


def rsassa_pss_verify(
    message: bytes,
    signature: bytes,
    n: int,
    e: int,
    *,
    hash_name: str = "sha256",
    salt_len: int | None = None,
) -> bool:
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    em_bits = n.bit_length() - 1
    m_hash = hashlib.new(hash_name, message).digest()
    m = rsaep(n, e, os2ip(signature))
    em = i2osp(m, (em_bits + 7) // 8)
    return pss_verify(m_hash, em, em_bits, hash_name=hash_name, salt_len=salt_len)
```

Padding schemes are defined over `EM` bytes, but RSA works over integers. The wrappers bridge that gap: encode to `EM`, convert to an integer, apply RSA, convert back, and decode/verify. For signatures, PSS defines `EM` and RSA exponentiation binds it to the key.

### Step 5: Why raw RSA breaks (determinism + malleability)

```python
def rsaep(n: int, e: int, m: int) -> int:
    if m < 0 or m >= n:
        raise ValueError("rsaep: message representative out of range")
    return pow(m, e, n)


def rsadp(n: int, d: int, c: int) -> int:
    if c < 0 or c >= n:
        raise ValueError("rsadp: ciphertext representative out of range")
    return pow(c, d, n)
```

Textbook RSA has no randomness and is multiplicatively homomorphic: `Enc(m1) * Enc(m2) mod n = Enc(m1*m2 mod n)`. That single algebraic fact is enough to build practical attacks when RSA is used without the right padding and validation rules.

Run it:

```bash
python3 code/main.py
```

## Use It

Production code should not implement padding by hand. Use audited libraries that already implement RSA-OAEP and RSA-PSS correctly.

- **Python (`cryptography`)**
  - Encryption: `padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)`
  - Signatures: `padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)`
- **OpenSSL**
  - `openssl pkeyutl -encrypt -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 ...`
  - `openssl pkeyutl -sign -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:-1 ...`
- **libsodium**
  - Prefer *not* using RSA; use X25519/Ed25519/KEMs. If you must interop with RSA, use a high-level library that wraps OpenSSL.

## Pitfalls

1. **Using PKCS#1 v1.5 for encryption in new designs.** OAEP exists for a reason; v1.5 decryption behavior has a deep history of padding-oracle vulnerabilities (Bleichenbacher-style).
2. **Treating “decrypt succeeded” as an oracle.** Any difference in error messages, timing, or retry behavior can leak padding validity.
3. **Mixing up encryption padding and signature padding.** OAEP is for encryption; PSS (or PKCS#1 v1.5 signatures) is for signatures. Swapping them is a real bug class.
4. **Wrong parameter coupling.** OAEP and PSS both tie security to `Hash` and `MGF1(Hash)`. “SHA-256 hash but MGF1-SHA1” is a common interop footgun.
5. **Assuming textbook RSA “adds secrecy”.** Without a scheme (OAEP) that defines randomness + validity checks, RSA is just a math function that attackers can algebraically manipulate.

## Ship It

Save and reuse the decision guide in `outputs/rsa-padding-decision-guide.md`:

- Use it as a PR review checklist when you see “RSA encryption” or “RSA signatures”.
- Paste it into an incident doc to quickly triage: “Are we using OAEP? Are we using PSS? Any v1.5 encryption paths exposed?”
- Use it as an interop spec for cross-language projects: parameters (`SHA-256`, `MGF1-SHA256`, salt length policy) become explicit.

## Exercises

1. Easy. Run `python3 code/main.py`. Observe that raw RSA is deterministic and malleable, while OAEP/PSS introduce structure and checks.
2. Medium. Modify `main()` to encrypt the same message with two different OAEP `seed` values and print both ciphertexts; confirm they differ while decrypting to the same plaintext.
3. Hard. In a real library (`cryptography` or OpenSSL), produce an RSA-OAEP ciphertext and an RSA-PSS signature with SHA-256, then verify your parameters match the guide in `outputs/`.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Textbook RSA | “raw RSA encryption/signature” | RSA without an encoding scheme; deterministic and algebraically malleable |
| `k` | “RSA key size in bytes” | `k = ceil(log256(n))`, the encoded message length for padding schemes |
| OAEP | “RSA padding for encryption” | randomized encoding with validity checks built from `Hash` and `MGF1` |
| PSS | “RSA padding for signatures” | randomized signature encoding with strict structure and a final `0xbc` trailer byte |
| MGF1 | “mask generation function” | hash-based expander used to mask/unmask blocks deterministically from a seed |

## Further Reading

- RSA Laboratories, *PKCS #1 v2.2: RSA Cryptography Standard* (2012) — the canonical spec for OAEP and PSS (RFC 8017).
- Daniel Bleichenbacher, *Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1* (1998) — why v1.5 encryption error behavior matters.
- Victor Shoup, *OAEP Reconsidered* (2001) — nuances of OAEP security models and implementation constraints.
