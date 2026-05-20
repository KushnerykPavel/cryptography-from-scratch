# Lookup Arguments — Plookup, Halo2 Lookups
> Prove “this came from the table” without boolean pain.

**Type:** Build  
**Languages:** Python  
**Prerequisites:** [PLONK — Universal SNARKs](../06-plonk-overview/docs/en.md), [PLONK from Scratch](../07-plonk-implement/docs/en.md)  
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** lookup arguments — what they prove and why circuits use them.
- **Compute** a multiset difference `table \ witness` (duplicates matter).
- **Implement** a toy lookup argument via Fiat–Shamir + a random-point product check.
- **Distinguish** single-column lookups vs multi-column (row-compressed) lookups.
- **Apply** the pattern to a small “allowed pairs” table.

## The Problem
You want a circuit to enforce statements like:
“this value is in `[0..2^16)`”, “this byte went through an S-box”, or “this opcode/flag pair is valid”.
Naively, you can encode membership with a giant disjunction (value equals one of N constants) or with many boolean constraints. It works… but it explodes proof size and prover time.

Lookup arguments are the escape hatch: instead of baking “membership logic” into constraints, you prove that the witness values you used are drawn from a pre-defined table. This is exactly the kind of thing ZK circuits do constantly: range checks, limb decompositions, bit/byte tables, fixed function tables, and custom gates implemented as lookup tables.

## The Concept
At the core, a lookup argument is a *multiset* membership statement:

- Public table `T = [t0, t1, ...]`
- Witness lookup values `W = [w0, w1, ...]`
- Claim: `W ⊆ T` as **multisets** (if `3` appears twice in `W`, it must appear at least twice in `T`)

One clean way to *think* about this is with a “roots product” polynomial:

- `P_T(X) = ∏(X - t_i)`
- `P_W(X) = ∏(X - w_j)`

If `W ⊆ T`, then `P_T(X) = P_W(X) · P_R(X)` for some remainder multiset `R = T \\ W`.
Checking polynomial divisibility is hard directly, but a classic trick is:
pick a random challenge `r` and check the equality *at that point*:

`P_T(r) ?= P_W(r) · P_R(r)`

In real systems, you can’t just send `P_W(r)` as a number; you must also prove it matches a committed polynomial (that’s what polynomial commitments and opening proofs are for). In this lesson, we keep it stdlib-only and show a toy, **non-ZK** version where the “proof” contains the witness values directly, but the *shape* matches what Plookup/Halo2 do.

Finally, real circuits often look up **rows** `(a, b, c)` not just scalars.
The standard move is **row compression**:

`compress(a, b, c) = a + θ·b + θ^2·c`

for a random challenge `θ` (Fiat–Shamir). If `θ` is unpredictable, collisions are overwhelmingly unlikely in a large field, so “row membership” reduces to “scalar membership”.

## Build It

### Step 1: Field + transcript helpers
We’ll work in a prime field `F_p` and implement a tiny transcript that gives us Fiat–Shamir challenges (hash → field element).

```python
MODULUS = 2**61 - 1  # a convenient Mersenne prime for toy finite-field arithmetic


def inv_mod(a: int, p: int = MODULUS) -> int:
    a %= p
    if a == 0:
        raise ZeroDivisionError("inverse of 0 does not exist")
    return pow(a, p - 2, p)


def _u64be(x: int) -> bytes:
    if x < 0:
        raise ValueError("expected non-negative int")
    return x.to_bytes(8, "big", signed=False)


def _hash256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _hash_list(label: str, xs: Sequence[int]) -> bytes:
    h = hashlib.sha256()
    h.update(b"list-v1\x00")
    h.update(label.encode("utf-8"))
    h.update(b"\x00")
    h.update(_u64be(len(xs)))
    for x in xs:
        h.update(_u64be(x % MODULUS))
    return h.digest()


def _hash_rows(label: str, rows: Sequence[Sequence[int]]) -> bytes:
    h = hashlib.sha256()
    h.update(b"rows-v1\x00")
    h.update(label.encode("utf-8"))
    h.update(b"\x00")
    h.update(_u64be(len(rows)))
    for row in rows:
        h.update(_u64be(len(row)))
        for v in row:
            h.update(_u64be(v % MODULUS))
    return h.digest()


class Transcript:
    def __init__(self, label: str):
        self._state = _hash256(b"transcript-v1\x00" + label.encode("utf-8"))

    def append(self, label: str, data: bytes) -> None:
        self._state = _hash256(self._state + b"\x00" + label.encode("utf-8") + b"\x00" + data)

    def challenge(self, label: str, p: int = MODULUS) -> int:
        out = _hash256(self._state + b"\x00" + label.encode("utf-8"))
        c = int.from_bytes(out, "big") % p
        self.append(f"challenge:{label}", out)
        return c
```

### Step 2: Multiset remainder + roots product evaluation
We’ll compute `R = T \\ W` (multiset difference) and evaluate `∏(r - value)` for any list. This is the algebraic core of the lookup check.

```python
def poly_product_at(roots: Sequence[int], x: int, p: int = MODULUS) -> int:
    acc = 1 % p
    x %= p
    for r in roots:
        acc = (acc * ((x - (r % p)) % p)) % p
    return acc


def multiset_difference(table: Sequence[int], witness: Sequence[int]) -> list[int]:
    """
    Returns a multiset difference table - witness as a sorted list.

    Raises ValueError if witness is not a multiset subset of table.
    """
    counts: dict[int, int] = {}
    for t in table:
        counts[t] = counts.get(t, 0) + 1

    for w in witness:
        c = counts.get(w, 0)
        if c <= 0:
            raise ValueError(f"witness value not in table (or too many copies): {w}")
        if c == 1:
            del counts[w]
        else:
            counts[w] = c - 1

    remainder: list[int] = []
    for v, c in counts.items():
        remainder.extend([v] * c)
    remainder.sort()
    return remainder
```

### Step 3: Prove/verify the toy lookup membership
We mimic the NIZK flow: “commit” (hash) → derive challenge `r` → check the product identity at `r`. The proof includes witness/remainder (so it’s **not** zero-knowledge), but verification is real.

```python
@dataclass(frozen=True)
class ToyLookupProof:
    """
    A *non-ZK* proof object:
    - we include witness and remainder directly (so verification is meaningful without commitments)
    - we still mimic the Fiat–Shamir flow and the “check at a random point” product test
    """

    witness: tuple[int, ...]
    remainder: tuple[int, ...]
    r: int
    eval_witness: int
    eval_remainder: int
    commit_witness: str
    commit_remainder: str

    def to_json(self) -> dict:
        return {
            "witness": list(self.witness),
            "remainder": list(self.remainder),
            "r": self.r,
            "eval_witness": self.eval_witness,
            "eval_remainder": self.eval_remainder,
            "commit_witness": self.commit_witness,
            "commit_remainder": self.commit_remainder,
        }

    @staticmethod
    def from_json(obj: dict) -> "ToyLookupProof":
        return ToyLookupProof(
            witness=tuple(obj["witness"]),
            remainder=tuple(obj["remainder"]),
            r=int(obj["r"]),
            eval_witness=int(obj["eval_witness"]),
            eval_remainder=int(obj["eval_remainder"]),
            commit_witness=str(obj["commit_witness"]),
            commit_remainder=str(obj["commit_remainder"]),
        )


def prove_lookup_membership(
    *,
    table: Sequence[int],
    witness: Sequence[int],
    p: int = MODULUS,
    label: str = "toy-lookup-v1",
) -> ToyLookupProof:
    remainder = multiset_difference(table, witness)

    cw = _hash_list("witness", list(witness)).hex()
    cr = _hash_list("remainder", remainder).hex()
    ct = _hash_list("table", list(table)).hex()

    tr = Transcript(label)
    tr.append("commit_table", bytes.fromhex(ct))
    tr.append("commit_witness", bytes.fromhex(cw))
    tr.append("commit_remainder", bytes.fromhex(cr))
    r = tr.challenge("r", p=p)

    eval_w = poly_product_at(witness, r, p=p)
    eval_r = poly_product_at(remainder, r, p=p)

    return ToyLookupProof(
        witness=tuple(witness),
        remainder=tuple(remainder),
        r=r,
        eval_witness=eval_w,
        eval_remainder=eval_r,
        commit_witness=cw,
        commit_remainder=cr,
    )


def verify_lookup_membership(
    *,
    table: Sequence[int],
    proof: ToyLookupProof,
    p: int = MODULUS,
    label: str = "toy-lookup-v1",
) -> bool:
    try:
        if _hash_list("witness", list(proof.witness)).hex() != proof.commit_witness:
            return False
        if _hash_list("remainder", list(proof.remainder)).hex() != proof.commit_remainder:
            return False

        ct = _hash_list("table", list(table)).hex()
        tr = Transcript(label)
        tr.append("commit_table", bytes.fromhex(ct))
        tr.append("commit_witness", bytes.fromhex(proof.commit_witness))
        tr.append("commit_remainder", bytes.fromhex(proof.commit_remainder))
        r = tr.challenge("r", p=p)
        if r != proof.r % p:
            return False

        eval_w = poly_product_at(proof.witness, r, p=p)
        eval_r = poly_product_at(proof.remainder, r, p=p)
        if eval_w != proof.eval_witness % p:
            return False
        if eval_r != proof.eval_remainder % p:
            return False

        eval_t = poly_product_at(table, r, p=p)
        return (eval_w * eval_r) % p == eval_t
    except Exception:
        return False
```

### Step 4: Multi-column lookups via row compression (theta)
To support “lookup rows”, compress each row into a single field element using a challenge `θ`. Then you can reuse the scalar lookup machinery unchanged.

```python
def compress_row(row: Sequence[int], theta: int, p: int = MODULUS) -> int:
    """
    Compresses a multi-column row into one field element:
      row[0] + theta*row[1] + theta^2*row[2] + ...
    """
    theta %= p
    acc = 0
    power = 1
    for v in row:
        acc = (acc + (v % p) * power) % p
        power = (power * theta) % p
    return acc


def compress_rows(rows: Sequence[Sequence[int]], theta: int, p: int = MODULUS) -> list[int]:
    return [compress_row(r, theta=theta, p=p) for r in rows]
```

Run it:

python3 code/main.py

## Use It
- **Halo2** (Rust): lookup arguments are a first-class feature of the PLONKish arithmetization; multi-column lookups use row compression and permutation/grand-product-style checks.
- **Plookup (PLONK)**: introduces efficient lookups by sorting and enforcing multiset relations between looked-up values and a table.
- **STARKs**: table arguments often appear as “permutation arguments” or “cross-table lookups” between traces.

## Pitfalls
- Treating a lookup as a *set* instead of a **multiset** (duplicates are the common footgun).
- Not binding the table (or table id) into the transcript — “prove membership” becomes meaningless if the prover can swap the table after seeing challenges.
- Reusing challenges across different lookup “domains” (no domain separation) — you can accidentally let one check satisfy another.
- Row compression with a fixed/guessable `θ` — you lose the “collision is unlikely” guarantee.
- Hashing/encoding mismatches (endianness, lengths) — prover and verifier can derive different challenges silently.

## Ship It
Save `outputs/lookup-argument-review-checklist.md` and use it as a PR review checklist for circuits that add or modify lookups:
- what’s being looked up (scalar vs rows),
- how the table is defined and bound,
- how challenges are derived and domain-separated,
- and what the failure modes look like (duplicates, collisions, table swaps).

## Exercises
1. Easy. Run `python3 code/main.py`. Observe how tampering `eval_witness` makes verification fail.
2. Medium. Extend `code/main.py` to batch two independent lookup sets by concatenating their witness lists and reusing `prove_lookup_membership`.
3. Hard. Sketch how you would make this toy proof *actually hiding* by replacing `witness`/`remainder` in the proof with polynomial commitments + opening proofs (no need to implement).

## Key Terms
| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Lookup argument | “Range check / membership gadget” | A proof that some witness values come from an allowed table (as a multiset). |
| Table | “A list of allowed values” | Public fixed data the circuit is allowed to reference (often fixed columns). |
| Multiset | “Set with duplicates” | Membership where counts matter (two lookups of `3` require two `3`s in the table). |
| Grand product | “Permutation/product argument” | A technique that turns equality of multisets into a product identity checked with challenges. |
| Row compression | “Combine columns with θ” | Reduce multi-column row membership to scalar membership via a random linear combination. |

## Further Reading
- Ariel Gabizon, Zachary J. Williamson, Oana Ciobotaru, *PLONK with Lookups* (2020) — introduces Plookup-style lookups for PLONKish systems.
- Electric Coin Company / Zcash, *The Halo2 Book* (ongoing) — practical PLONKish lookups and circuit engineering details.
