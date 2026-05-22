# Build a ZK Voting System

> Encrypt every vote, tally homomorphically, and prove each ballot is valid — without revealing who voted for what.

**Type:** Build
**Languages:** Python
**Prerequisites:** ElGamal encryption, Pedersen commitments, Schnorr proofs, Fiat-Shamir transform
**Time:** ~90 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain how ElGamal's multiplicative homomorphism lets you tally encrypted votes without decrypting individual ballots
- Compute a disjunctive Chaum-Pedersen or-proof showing a ciphertext encrypts 0 or 1
- Implement Fiat-Shamir to convert the interactive sigma-protocol into a non-interactive proof
- Distinguish ballot privacy (individual votes hidden) from verifiability (tally provably correct)
- Apply a bulletin-board architecture to produce an end-to-end verifiable election

## The Problem

You need to run an election where no one — not the server, not other voters, not auditors — can learn how any individual voted, yet anyone can verify that the final tally is correct and that no one cast an invalid ballot (e.g., voted "2" in a yes/no election). Naively encrypting votes with a symmetric key just shifts trust to whoever holds the key. Publishing votes in plaintext destroys ballot privacy.

The standard fix is to give each voter a keypair, publish encrypted votes on a public bulletin board, and use homomorphic tallying: multiplying all the ciphertexts together produces an encryption of the sum. One authority (or a threshold quorum) decrypts only the aggregate — never touching individual ballots. Ballot validity is enforced by attaching a zero-knowledge proof to each ciphertext proving the encrypted value is in {0, 1} without revealing which.

This is the architecture behind real systems like Helios (Adida, 2008) and Belenios. The math is the same as what you learned in the ElGamal and Schnorr phases; here you assemble those pieces into a complete protocol.

## The Concept

### Group setup

Work in the prime-order subgroup of Z*_p of order q, where p = 2q + 1 (safe prime). Every non-identity element of this subgroup has order exactly q, so discrete-log-based hardness assumptions hold cleanly.

| Symbol | Meaning |
|--------|---------|
| p      | Safe prime (p = 2q + 1) |
| q      | Subgroup order (prime) |
| g      | Generator of the order-q subgroup |
| x      | Election authority's private key (x ∈ [1, q-1]) |
| h      | Election public key (h = g^x mod p) |

### ElGamal encryption

To encrypt a vote v ∈ {0, 1}:

```
r  ← random in [1, q-1]
C1 = g^r mod p
C2 = h^r · g^v mod p
```

The ciphertext is (C1, C2). Decryption requires knowing x:

```
s    = C1^x mod p          (shared secret)
g^v  = C2 · s^{-1} mod p
v    = discrete log of g^v  (brute-force: only 0 or 1 possible)
```

### Multiplicative homomorphism

If Enc(v1) = (C1_a, C2_a) and Enc(v2) = (C1_b, C2_b), then:

```
(C1_a · C1_b mod p,  C2_a · C2_b mod p) = Enc(v1 + v2)
```

Multiplying all N ciphertext pairs gives an encryption of the total vote count. Decrypt once to reveal the tally.

### Disjunctive or-proof (Cramer et al.)

The prover must show: "I know r such that (C1 = g^r and C2 = h^r) OR (C1 = g^r and C2/g = h^r)." This is a Chaum-Pedersen equality-of-discrete-logs proof composed with the "or" trick.

**Protocol (non-interactive via Fiat-Shamir):**

1. Simulate the false branch: pick c_false, z_false at random. Back-compute the commitment:
   ```
   A_false = g^{z_false} · C1^{-c_false} mod p
   B_false = h^{z_false} · target^{-c_false} mod p
   ```
2. Commit for the real branch with fresh nonce k:
   ```
   A_real = g^k mod p
   B_real = h^k mod p
   ```
3. Apply Fiat-Shamir (branches in canonical order v=0, v=1):
   ```
   c_total = H(p, g, h, C1, C2, A0, B0, A1, B1) mod q
   ```
4. Split the challenge: `c_real = c_total - c_false mod q`
5. Respond: `z_real = k + c_real · r mod q`

**Verification:** check `(c0 + c1) mod q = c_total`, then verify both branches:
```
g^z0 = A0 · C1^{c0}        and   h^z0 = B0 · C2^{c0}       (branch v=0)
g^z1 = A1 · C1^{c1}        and   h^z1 = B1 · (C2/g)^{c1}   (branch v=1)
```

### Bulletin board

Each voter submits (voter_id, ciphertext, or-proof). The board is public and append-only. Anyone can verify every proof. The authority tallies by multiplying all ciphertexts, then decrypts once.

## Build It

### Step 1: Group parameters and helpers

```python
import hashlib
import secrets
from dataclasses import dataclass
from typing import List, Optional, Tuple

P: int = 1019
Q: int = 509
G: int = 4

assert (P - 1) // 2 == Q
assert pow(G, Q, P) == 1
assert G != 1

MAX_VOTERS: int = 1000


def _modinv(a: int, m: int) -> int:
    return pow(a, m - 2, m)


def _sha256_int(*parts: object) -> int:
    h = hashlib.sha256()
    for part in parts:
        h.update(str(part).encode())
        h.update(b"|")
    return int(h.hexdigest(), 16)
```

We use a safe prime p=1019 with subgroup order q=509 and generator g=4. g=4 = 2² mod p; every quadratic residue mod a safe prime has order q or 1 and g ≠ 1 so g has order exactly q. The group is tiny by design so the brute-force tally decode is instant. Real systems use 2048-bit or larger groups.

### Step 2: ElGamal key generation and encryption

```python
def keygen() -> Tuple[int, int]:
    x = secrets.randbelow(Q - 1) + 1
    h = pow(G, x, P)
    return x, h


@dataclass
class Ciphertext:
    c1: int
    c2: int


def elgamal_encrypt(vote: int, pk: int, r: Optional[int] = None) -> Tuple[Ciphertext, int]:
    if vote not in (0, 1):
        raise ValueError("vote must be 0 or 1")
    if r is None:
        r = secrets.randbelow(Q - 1) + 1
    c1 = pow(G, r, P)
    c2 = (pow(pk, r, P) * pow(G, vote, P)) % P
    return Ciphertext(c1, c2), r


def elgamal_decrypt(ct: Ciphertext, sk: int, max_tally: int = MAX_VOTERS) -> int:
    s = pow(ct.c1, sk, P)
    s_inv = _modinv(s, P)
    gv = (ct.c2 * s_inv) % P
    for v in range(max_tally + 1):
        if pow(G, v, P) == gv:
            return v
    raise ValueError(f"decrypted G^v not found in [0, {max_tally}]")
```

`elgamal_encrypt` returns both the ciphertext and the randomness r so the prover can attach a validity proof without re-encrypting. `elgamal_decrypt` brute-forces the discrete log of g^v — this is only feasible because v ∈ [0, num_voters]; for a real election with millions of voters the authority would use baby-step giant-step instead.

### Step 3: Homomorphic tally

```python
def homomorphic_tally(ciphertexts: List[Ciphertext]) -> Ciphertext:
    if not ciphertexts:
        raise ValueError("need at least one ciphertext")
    tc1 = 1
    tc2 = 1
    for ct in ciphertexts:
        tc1 = (tc1 * ct.c1) % P
        tc2 = (tc2 * ct.c2) % P
    return Ciphertext(tc1, tc2)
```

Multiplying C1 components gives g^(r1+r2+…) and multiplying C2 components gives h^(r1+r2+…) · g^(v1+v2+…). The product ciphertext encrypts the sum of votes under the same public key, so a single decryption reveals the tally.

### Step 4: Disjunctive or-proof

```python
@dataclass
class OrProof:
    a0: int
    b0: int
    a1: int
    b1: int
    c0: int
    c1: int
    z0: int
    z1: int


def prove_vote(ct: Ciphertext, vote: int, r: int, pk: int) -> OrProof:
    if vote not in (0, 1):
        raise ValueError("vote must be 0 or 1")

    c2_b0 = ct.c2
    c2_b1 = (ct.c2 * _modinv(G, P)) % P

    c_false = secrets.randbelow(Q)
    z_false = secrets.randbelow(Q)

    k = secrets.randbelow(Q - 1) + 1
    a_real = pow(G, k, P)
    b_real = pow(pk, k, P)

    if vote == 0:
        target_false = c2_b1
        a_false = (pow(G, z_false, P) * pow(ct.c1, Q - c_false, P)) % P
        b_false = (pow(pk, z_false, P) * pow(target_false, Q - c_false, P)) % P
        a0, b0 = a_real, b_real
        a1, b1 = a_false, b_false
    else:
        target_false = c2_b0
        a_false = (pow(G, z_false, P) * pow(ct.c1, Q - c_false, P)) % P
        b_false = (pow(pk, z_false, P) * pow(target_false, Q - c_false, P)) % P
        a0, b0 = a_false, b_false
        a1, b1 = a_real, b_real

    c_total = _sha256_int(P, G, pk, ct.c1, ct.c2, a0, b0, a1, b1) % Q
    c_real = (c_total - c_false) % Q
    z_real = (k + c_real * r) % Q

    if vote == 0:
        return OrProof(a0=a0, b0=b0, a1=a1, b1=b1, c0=c_real, c1=c_false, z0=z_real, z1=z_false)
    else:
        return OrProof(a0=a0, b0=b0, a1=a1, b1=b1, c0=c_false, c1=c_real, z0=z_false, z1=z_real)


def verify_vote_proof(ct: Ciphertext, proof: OrProof, pk: int) -> bool:
    c2_b0 = ct.c2
    c2_b1 = (ct.c2 * _modinv(G, P)) % P

    c_total = _sha256_int(P, G, pk, ct.c1, ct.c2, proof.a0, proof.b0, proof.a1, proof.b1) % Q

    if (proof.c0 + proof.c1) % Q != c_total % Q:
        return False

    lhs0_a = pow(G, proof.z0, P)
    rhs0_a = (proof.a0 * pow(ct.c1, proof.c0, P)) % P
    if lhs0_a != rhs0_a:
        return False

    lhs0_b = pow(pk, proof.z0, P)
    rhs0_b = (proof.b0 * pow(c2_b0, proof.c0, P)) % P
    if lhs0_b != rhs0_b:
        return False

    lhs1_a = pow(G, proof.z1, P)
    rhs1_a = (proof.a1 * pow(ct.c1, proof.c1, P)) % P
    if lhs1_a != rhs1_a:
        return False

    lhs1_b = pow(pk, proof.z1, P)
    rhs1_b = (proof.b1 * pow(c2_b1, proof.c1, P)) % P
    if lhs1_b != rhs1_b:
        return False

    return True
```

The proof always stores branches in canonical order (v=0 first, v=1 second) so the verifier is symmetric. The Fiat-Shamir hash binds the commitments to the statement, making the proof non-interactive and non-transferable.

### Step 5: Bulletin board and election

```python
@dataclass
class BallotEntry:
    voter_id: str
    ct: Ciphertext
    proof: OrProof


def submit_ballot(
    board: List[BallotEntry],
    voter_id: str,
    vote: int,
    pk: int,
) -> BallotEntry:
    ct, r = elgamal_encrypt(vote, pk)
    proof = prove_vote(ct, vote, r, pk)
    entry = BallotEntry(voter_id=voter_id, ct=ct, proof=proof)
    board.append(entry)
    return entry


def verify_board(board: List[BallotEntry], pk: int) -> bool:
    return all(verify_vote_proof(entry.ct, entry.proof, pk) for entry in board)
```

Each ballot entry is a triple (voter_id, ciphertext, proof) posted publicly. `verify_board` is the universal verifiability check: any observer can confirm every vote is well-formed without decrypting any individual ballot.

Run it:
```
python3 code/main.py
```

## Use It

| What this lesson builds | Real-world equivalent |
|-------------------------|-----------------------|
| ElGamal encryption | `cryptography` library: `hazmat.primitives.asymmetric.ec` with ECDH; or the `elgamal` PyPI package |
| Homomorphic tally | Helios voting system (open-source Python): `helios-server` on GitHub |
| Disjunctive or-proof | `python-bulletproofs`, `zkpy`, or Circom/SnarkJS circuits |
| Fiat-Shamir transform | Built into every non-interactive ZK library (e.g., `py_ecc`, `gnark`) |
| Bulletin board | Helios, Belenios, or any append-only transparency log (e.g., Trillian) |
| Threshold decryption | `tss-lib` (Go), `frost-dalek` (Rust), or Belenios trustees |

## Pitfalls

- **Reusing randomness r across votes.** If two ballots share the same r, an observer can deduce both votes by dividing the C2 values. Always draw r freshly from secrets.randbelow.
- **Verifying proofs after tallying instead of before.** Invalid ballots must be rejected before they enter the tally; checking proofs afterwards does not undo their effect on the product ciphertext.
- **Leaking the vote through the proof's false-branch challenge.** If c_false is chosen predictably (e.g., always 0), a verifier can factor out the real branch and learn the vote. Use secrets.randbelow for c_false.
- **Omitting the voter-id from the Fiat-Shamir hash.** Without binding the proof to the voter, an attacker can copy a valid ballot from one election and replay it in another (cross-election replay).
- **Single-authority key.** If one authority holds the full private key, they can decrypt individual ballots. Real elections use threshold decryption: the key is split across k-of-n trustees; the individual ballot is mathematically undecryptable unless k trustees collude.

## Ship It

Save a reusable security checklist for auditing ZK voting systems: `outputs/zk-voting-audit-checklist.md`. This checklist covers the categories an auditor should verify when reviewing any e-voting system built on homomorphic encryption and ZK proofs.

## Exercises

1. Easy: Run `python3 code/main.py`. Observe that Alice and Carol vote Yes (1) and Bob votes No (0), the tally correctly returns 2, and the tampered ballot is rejected.
2. Medium: Extend the demo to run 10 voters with randomly assigned votes and measure how many or-proof verification calls occur. Add a timing print to verify_board.
3. Hard: Implement threshold decryption: split the secret key x into 2-of-3 Shamir shares, have each trustee produce a partial decryption g^(x_i * r), and combine the partial decryptions to recover the tally without any single trustee learning x.

## Key Terms

| Term | What people say | What it actually means |
|------|-----------------|------------------------|
| Homomorphic encryption | "Compute on encrypted data" | Enc(a) op Enc(b) = Enc(a+b); for ElGamal the operation is multiplication of ciphertexts |
| Or-proof | "Zero-knowledge disjunction" | A sigma protocol that proves "A or B" without revealing which; the prover simulates the false branch and the verifier cannot distinguish real from simulated |
| Fiat-Shamir transform | "Non-interactive ZK" | Replace the verifier's random challenge with H(transcript) so the proof can be verified offline without interaction |
| Bulletin board | "Public ledger of votes" | An append-only authenticated list of (ciphertext, proof) pairs visible to all; enables universal verifiability |
| Ballot validity | "Vote is well-formed" | An or-proof showing the ciphertext encrypts 0 or 1; prevents voters from stuffing the tally with vote=100 |
| Threshold decryption | "No single key holder" | Secret key split across trustees; tally decryption requires k-of-n partial decryptions; individual ballots stay encrypted |
| Universal verifiability | "Anyone can check the tally" | Any observer can re-verify every proof on the bulletin board and re-multiply the ciphertexts to confirm the announced result |

## Further Reading

- Cramer, Damgård, Schoenmakers, "Proofs of Partial Knowledge and Simplified Design of Witness Hiding Protocols" (Crypto 1994) — the or-proof construction used here
- Adida, "Helios: Web-based Open-Audit Voting" (USENIX Security 2008) — the first widely-deployed system using these exact primitives
- Bernhard et al., "How not to Prove Yourself: Pitfalls of the Fiat-Shamir Heuristic and Applications to Helios" (Asiacrypt 2012) — shows why binding voter-id into the hash matters
- Chaum & Pedersen, "Wallet Databases with Observers" (Crypto 1992) — the Chaum-Pedersen equality-of-discrete-logs proof that forms each branch of the or-proof
