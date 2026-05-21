# Merkle Signatures (MSS) from Scratch
> One-time signatures become many-time when you pin them to a Merkle root.

**Type:** Build  
**Languages:** Python  
**Prerequisites:** `phases/15-pq-code-hash-multivariate/03-lamport/`, `phases/15-pq-code-hash-multivariate/04-winternitz/`  
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** why Merkle signatures turn a one-time primitive into a many-time scheme.
- **Compute** a Merkle root and an authentication path for a chosen leaf.
- **Implement** a minimal MSS signer/verifier using Lamport OTS + a Merkle tree.
- **Distinguish** OTS security (one-time) from MSS security (many-time) and where state comes from.
- **Apply** a review checklist to catch real-world MSS/XMSS/LMS integration bugs.

## The Problem
You have a signature scheme that is “post-quantum friendly” because it only relies on hashes (e.g., Lamport/Winternitz OTS). Great — except it’s **one-time**: reuse the key and you leak enough material to enable forgeries.

In real systems you need to sign *many* messages with a single “public key handle”. Merkle signatures solve this by committing to **many** OTS public keys at once via a Merkle root. Each signature then proves (1) “this leaf public key is in the committed set” and (2) “this leaf public key validates the OTS signature on the message”.

Without MSS, you’re forced into awkward key rotation (“new public key every message”), brittle operational workflows, and verification logic that’s hard to audit. With MSS, you get a clean abstraction: one stable public root, many signatures, and simple verification.

## The Concept
Think of MSS as:

| Layer | What it does | What you send in a signature |
|------|--------------|------------------------------|
| OTS (Lamport/Winternitz) | Signs **one** message | OTS signature + leaf OTS public key |
| Merkle tree | Commits to **many** OTS public keys | Leaf index + auth path (siblings) |

### Merkle tree mental model
- Leaves: `leaf[i] = H(OTS_public_key[i])`
- Internal node: `node = H(left || right)`
- Root: one 32-byte value that commits to all leaves

### Authentication path
To prove leaf `i` is in the tree, include the sibling hash at each level:
- level 0 sibling: `leaf[i ^ 1]`
- level 1 sibling: the sibling of `parent(i)`  
… up to the root.

Given `(leaf_hash, i, auth_path)`, a verifier recomputes the root and checks it matches the public root.

## Build It

### Step 1: Lamport OTS
```python
def sha256(data: bytes) -> Hash:
    return hashlib.sha256(data).digest()


def h(label: bytes, *parts: bytes) -> Hash:
    return sha256(label + b"".join(parts))


def prg(seed: bytes, label: bytes, out_len: int) -> bytes:
    """
    Deterministic byte generator based on SHA-256(seed || label || counter).

    Educational PRG: good enough for determinism in this lesson, not a DRBG spec.
    """
    if out_len < 0:
        raise ValueError("out_len must be non-negative")
    out = bytearray()
    counter = 0
    while len(out) < out_len:
        block = sha256(seed + label + counter.to_bytes(4, "big"))
        out.extend(block)
        counter += 1
    return bytes(out[:out_len])


def bytes_to_bits_be(data: bytes) -> List[int]:
    bits: List[int] = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def lamport_keygen(seed: bytes) -> Tuple[LamportSecretKey, LamportPublicKey]:
    """
    Lamport OTS key generation.

    - Secret key: 256 pairs of 32-byte strings
    - Public key: SHA-256 of each secret string
    """
    raw = prg(seed, b"LAMPORT_SK", 256 * 2 * 32)
    sk: LamportSecretKey = []
    pk: LamportPublicKey = []
    off = 0
    for _ in range(256):
        s0 = raw[off : off + 32]
        s1 = raw[off + 32 : off + 64]
        off += 64
        sk.append((s0, s1))
        pk.append((sha256(s0), sha256(s1)))
    return sk, pk


def lamport_pk_hash(pk: LamportPublicKey) -> Hash:
    """
    Compress a Lamport public key to a single 32-byte hash (the Merkle-tree leaf).
    """
    flat = b"".join(x for pair in pk for x in pair)
    return h(b"LAMPORT_PK", flat)


def lamport_sign(sk: LamportSecretKey, message: bytes) -> LamportSignature:
    """
    Sign a message with Lamport OTS.

    We sign the 256-bit digest SHA-256(message). For each digest bit, reveal
    one of the two corresponding secret values.
    """
    digest = sha256(message)
    bits = bytes_to_bits_be(digest)
    sig: LamportSignature = []
    for i, bit in enumerate(bits):
        s0, s1 = sk[i]
        sig.append(s1 if bit else s0)
    return sig


def lamport_verify(pk: LamportPublicKey, message: bytes, sig: LamportSignature) -> bool:
    if len(sig) != 256:
        return False
    digest = sha256(message)
    bits = bytes_to_bits_be(digest)
    for i, bit in enumerate(bits):
        expected = pk[i][bit]
        if sha256(sig[i]) != expected:
            return False
    return True


def lamport_signature_fingerprint(sig: LamportSignature) -> Hash:
    """
    Compact, deterministic fingerprint for a Lamport signature (for tests/logging).
    """
    return h(b"LAMPORT_SIG", b"".join(sig))
```
Lamport OTS is the simplest hash-based signature: for each digest bit you reveal one secret. It verifies by hashing each revealed secret and comparing to the corresponding public hash.

### Step 2: Merkle tree of OTS public keys
```python
def merkle_parent(left: Hash, right: Hash) -> Hash:
    return h(b"MERKLE_NODE", left, right)


def _is_power_of_two(n: int) -> bool:
    return n > 0 and (n & (n - 1)) == 0


def merkle_build(leaves: Sequence[Hash]) -> List[List[Hash]]:
    """
    Build a full binary Merkle tree.

    Returns levels bottom-up: levels[0] are leaves, levels[-1][0] is the root.
    """
    if not _is_power_of_two(len(leaves)):
        raise ValueError("number of leaves must be a power of two")
    if any(len(x) != 32 for x in leaves):
        raise ValueError("all leaves must be 32-byte hashes")

    levels: List[List[Hash]] = [list(leaves)]
    cur = list(leaves)
    while len(cur) > 1:
        nxt: List[Hash] = []
        for i in range(0, len(cur), 2):
            nxt.append(merkle_parent(cur[i], cur[i + 1]))
        levels.append(nxt)
        cur = nxt
    return levels


def merkle_root(leaves: Sequence[Hash]) -> Hash:
    return merkle_build(leaves)[-1][0]


def merkle_auth_path(levels: Sequence[Sequence[Hash]], leaf_index: int) -> List[Hash]:
    """
    Authentication path for a leaf: list of sibling hashes from leaf-level up.
    """
    if leaf_index < 0 or leaf_index >= len(levels[0]):
        raise IndexError("leaf_index out of range")
    path: List[Hash] = []
    idx = leaf_index
    for level in levels[:-1]:
        sib = idx ^ 1
        path.append(level[sib])
        idx //= 2
    return path


def merkle_verify_path(leaf: Hash, leaf_index: int, auth_path: Sequence[Hash], root: Hash) -> bool:
    if leaf_index < 0:
        return False
    if any(len(x) != 32 for x in auth_path):
        return False
    acc = leaf
    idx = leaf_index
    for sib in auth_path:
        if idx & 1:
            acc = merkle_parent(sib, acc)
        else:
            acc = merkle_parent(acc, sib)
        idx //= 2
    return acc == root
```
This is the “membership proof” engine. An MSS signature doesn’t send the whole tree — it sends just the `auth_path` for the chosen leaf.

### Step 3: Merkle signature (OTS + auth path)
```python
def mss_leaf_seed(master_seed: bytes, leaf_index: int) -> bytes:
    return h(b"MSS_LEAF_SEED", master_seed, leaf_index.to_bytes(4, "big"))


@dataclass(frozen=True)
class MerklePublicKey:
    height: int
    root: Hash


@dataclass(frozen=True)
class MerklePrivateKey:
    height: int
    master_seed: bytes


@dataclass(frozen=True)
class MerkleSignature:
    leaf_index: int
    lamport_pk_hash: Hash
    lamport_pk: LamportPublicKey
    lamport_sig: LamportSignature
    auth_path: List[Hash]


def mss_keygen(master_seed: bytes, height: int) -> Tuple[MerklePrivateKey, MerklePublicKey, List[List[Hash]]]:
    """
    Generate an MSS keypair with 2^height Lamport leaves.

    Returns (sk, pk, merkle_levels). Keeping levels is convenient for signing.
    """
    if height < 1 or height > 20:
        raise ValueError("height must be between 1 and 20 for this demo")
    leaf_count = 1 << height
    leaves: List[Hash] = []
    for i in range(leaf_count):
        seed_i = mss_leaf_seed(master_seed, i)
        _, pk_i = lamport_keygen(seed_i)
        leaves.append(lamport_pk_hash(pk_i))
    levels = merkle_build(leaves)
    root = levels[-1][0]
    return MerklePrivateKey(height=height, master_seed=master_seed), MerklePublicKey(height=height, root=root), levels


def mss_sign(sk: MerklePrivateKey, merkle_levels: Sequence[Sequence[Hash]], leaf_index: int, message: bytes) -> MerkleSignature:
    if leaf_index < 0 or leaf_index >= (1 << sk.height):
        raise IndexError("leaf_index out of range")
    if len(merkle_levels[0]) != (1 << sk.height):
        raise ValueError("merkle_levels do not match sk.height")

    seed_i = mss_leaf_seed(sk.master_seed, leaf_index)
    lamport_sk, lamport_pk = lamport_keygen(seed_i)
    lpkh = lamport_pk_hash(lamport_pk)
    if lpkh != merkle_levels[0][leaf_index]:
        raise ValueError("leaf mismatch: lamport_pk_hash does not match Merkle tree")

    ots_sig = lamport_sign(lamport_sk, message)
    path = merkle_auth_path(merkle_levels, leaf_index)
    return MerkleSignature(
        leaf_index=leaf_index,
        lamport_pk_hash=lpkh,
        lamport_pk=lamport_pk,
        lamport_sig=ots_sig,
        auth_path=path,
    )


def mss_verify(pk: MerklePublicKey, message: bytes, sig: MerkleSignature) -> bool:
    if sig.leaf_index < 0 or sig.leaf_index >= (1 << pk.height):
        return False
    if len(sig.auth_path) != pk.height:
        return False
    if sig.lamport_pk_hash != lamport_pk_hash(sig.lamport_pk):
        return False
    if not lamport_verify(sig.lamport_pk, message, sig.lamport_sig):
        return False
    return merkle_verify_path(sig.lamport_pk_hash, sig.leaf_index, sig.auth_path, pk.root)


def mss_signature_fingerprint(sig: MerkleSignature) -> Hash:
    """
    Compact fingerprint for the whole MSS signature object (for tests/logging).
    """
    pk_flat = b"".join(x for pair in sig.lamport_pk for x in pair)
    return h(
        b"MSS_SIG",
        sig.leaf_index.to_bytes(4, "big"),
        sig.lamport_pk_hash,
        pk_flat,
        b"".join(sig.lamport_sig),
        b"".join(sig.auth_path),
    )
```
This wrapper is the essence of MSS: “an OTS signature” + “a Merkle membership proof” under a single stable public root.

### Step 4: Why OTS must be one-time
```python
def _demo_step_4() -> None:
    print("=== Step 4: Why OTS must be one-time ===")
    seed = b"\x33" * 32
    sk, pk = lamport_keygen(seed)
    m1 = b"message one"
    m2 = b"message two"
    s1 = lamport_sign(sk, m1)
    s2 = lamport_sign(sk, m2)
    leaked = sum(1 for a, b in zip(s1, s2) if a != b)
    print("Two signatures with the same Lamport key leak secrets.")
    print("revealed_positions_with_different_secrets:", leaked, "/ 256")
    print("verify(m1):", lamport_verify(pk, m1, s1))
    print("verify(m2):", lamport_verify(pk, m2, s2))
    print()
```
Each Lamport signature reveals one secret per digest bit. If you sign twice with the same key, you reveal secrets from *both* sides for many positions. That’s the core “don’t reuse OTS keys” rule that MSS must enforce with leaf state.

Run it:
`python3 code/main.py`

## Use It
In practice you don’t ship “raw MSS”; you use standardized descendants:
- **XMSS / XMSS^MT** (stateful) — standardized hash-based signatures using Winternitz OTS and Merkle trees.
- **LMS / HSS** (stateful) — another standardized Merkle-tree signature family.
- **SPHINCS+** (stateless) — avoids state by using many randomized trees; much larger signatures.

Integration rule of thumb:
- If you can safely manage state (never reuse a leaf index), use XMSS/LMS.
- If you can’t (distributed signers, backups, crashes), prefer stateless designs like SPHINCS+.

## Pitfalls
- Reusing an OTS leaf (state bugs, concurrency, rollback after crash) — the most common catastrophic failure.
- Missing domain separation between “leaf hashing” and “internal node hashing” (or between protocols) — can enable weird cross-protocol attacks.
- Not validating signature structure (wrong auth path length, index out of range, malformed public key).
- Treating “root” as enough without pinning parameters (tree height, hash function, address/labeling).
- Underestimating signature size and verification cost (Lamport is huge; real schemes optimize with Winternitz and other tricks).

## Ship It
Save and reuse the checklist in `outputs/merkle-signature-audit-checklist.md`:
- Paste it into a PR review when someone proposes XMSS/LMS/SPHINCS+.
- Use it as an acceptance gate for “post-quantum signatures” that claim to be “just hashes”.

## Exercises
1. **Easy:** Run `python3 code/main.py`. Observe how the Merkle root stays constant while different leaf indices sign different messages.
2. **Medium:** Extend `mss_sign` to enforce “one-time”: keep a set of used indices (in-memory) and raise if an index is reused. Demonstrate the failure by signing twice with the same index.
3. **Hard:** Replace Lamport OTS leaves with your Winternitz OTS from the previous lesson and compare (a) signature size and (b) verification time (roughly, using `time.perf_counter()`).

## Key Terms
| Term | What people say | What it actually means |
|------|------------------|------------------------|
| One-time signature (OTS) | “A PQ signature primitive” | A signature scheme where security only holds if each key signs at most one message. |
| Merkle tree | “A hash tree” | A commitment to many leaves where you can prove membership with an auth path. |
| Authentication path | “Merkle proof” | The list of sibling hashes needed to recompute the root from a leaf. |
| Leaf index | “Which key did you use?” | The position of the OTS key inside the tree; must never repeat in stateful schemes. |
| MSS | “Merkle signatures” | OTS + Merkle membership proof under a single public root. |

## Further Reading
- Ralph Merkle, *A Certified Digital Signature* (1979) — the original Merkle signature idea.
- RFC 8391, *XMSS: eXtended Merkle Signature Scheme* (2018) — stateful Merkle-tree signatures built for the real world.
- RFC 8554, *Leighton-Micali Hash-Based Signatures (LMS/HSS)* (2019) — an alternative stateful Merkle-tree signature standard.
- NIST, *SPHINCS+* (finalist/standardization docs) — a stateless hash-based signature design.

