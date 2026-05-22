"""
Mini ZK Rollup demo (educational).

Run:
  python3 code/main.py

This lesson builds a simplified ZK rollup:
  1. State = Merkle tree of 4 account balances.
  2. Transactions = HMAC-signed token transfers.
  3. A simplified validity proof shows each sender had sufficient balance,
     using balance commitments and revealed openings.
  4. L1 submission = (old_root, new_root, validity_proof, compressed_txs).

Warning: Educational only. Not constant-time. Not real ZK. Not production-safe.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Tuple


# ---------------------------------------------------------------------------
# 1. Merkle tree over account balances
# ---------------------------------------------------------------------------

def merkle_hash(left: bytes, right: bytes) -> bytes:
    """Combine two 32-byte nodes into a parent node via SHA-256."""
    return hashlib.sha256(left + right).digest()


def merkle_root(leaves: List[bytes]) -> bytes:
    """Build a complete binary Merkle tree and return the root.

    The number of leaves must be a power of two.
    """
    n = len(leaves)
    if n == 0:
        raise ValueError("merkle_root requires at least one leaf")
    if n & (n - 1) != 0:
        raise ValueError("merkle_root requires a power-of-two number of leaves")
    layer = list(leaves)
    while len(layer) > 1:
        next_layer = []
        for i in range(0, len(layer), 2):
            next_layer.append(merkle_hash(layer[i], layer[i + 1]))
        layer = next_layer
    return layer[0]


def merkle_proof(leaves: List[bytes], index: int) -> List[bytes]:
    """Return the sibling-hash path (proof) for the leaf at *index*.

    The proof is ordered from the leaf level up to (but not including)
    the root -- i.e., proof[0] is the sibling of the leaf.
    """
    n = len(leaves)
    if n == 0 or n & (n - 1) != 0:
        raise ValueError("merkle_proof requires a power-of-two number of leaves")
    if index < 0 or index >= n:
        raise ValueError("index out of range")
    path: List[bytes] = []
    layer = list(leaves)
    idx = index
    while len(layer) > 1:
        sibling = idx ^ 1  # XOR with 1 flips between even/odd
        path.append(layer[sibling])
        next_layer = []
        for i in range(0, len(layer), 2):
            next_layer.append(merkle_hash(layer[i], layer[i + 1]))
        layer = next_layer
        idx //= 2
    return path


def merkle_verify(root: bytes, leaf: bytes, proof: List[bytes], index: int) -> bool:
    """Verify that *leaf* at *index* is included under *root*.

    Returns True iff the proof recomputes to the given root.
    """
    current = leaf
    idx = index
    for sibling in proof:
        if idx % 2 == 0:
            current = merkle_hash(current, sibling)
        else:
            current = merkle_hash(sibling, current)
        idx //= 2
    return current == root


# ---------------------------------------------------------------------------
# 2. Account state
# ---------------------------------------------------------------------------

@dataclass
class Account:
    """An account identified by a 4-byte integer address with a balance."""

    address: int   # fits in 4 bytes (uint32)
    balance: int   # non-negative integer

    def leaf_hash(self) -> bytes:
        """Canonical leaf hash: SHA-256(address_BE_4 || balance_BE_8)."""
        raw = struct.pack(">I", self.address) + struct.pack(">Q", self.balance)
        return hashlib.sha256(raw).digest()


State = List[Account]


def state_root(state: State) -> bytes:
    """Return the Merkle root of the current account balances."""
    return merkle_root([acc.leaf_hash() for acc in state])


# ---------------------------------------------------------------------------
# 3. Transactions and signatures
# ---------------------------------------------------------------------------

@dataclass
class Transaction:
    """A signed token transfer from *sender* to *receiver*."""

    sender: int      # address (uint32)
    receiver: int    # address (uint32)
    amount: int      # transfer amount (uint64)
    nonce: int       # replay-protection counter (uint16, low 16 bits used)
    sig: bytes = field(default=b"", repr=False)


def _tx_payload(tx: Transaction) -> bytes:
    """Canonical serialisation of the transaction fields (excluding sig)."""
    return struct.pack(
        ">IIQH",
        tx.sender,
        tx.receiver,
        tx.amount,
        tx.nonce & 0xFFFF,
    )


def sign_tx(sk: bytes, tx: Transaction) -> bytes:
    """Sign a transaction with a 32-byte secret key using HMAC-SHA256.

    The signature is an HMAC tag over the canonical payload.
    Warning: Demo only -- not a real ECDSA signature.
    """
    return hmac.new(sk, _tx_payload(tx), hashlib.sha256).digest()


def verify_tx(pk: bytes, tx: Transaction, sig: bytes) -> bool:
    """Verify a transaction signature."""
    expected = hmac.new(pk, _tx_payload(tx), hashlib.sha256).digest()
    return hmac.compare_digest(expected, sig)


# ---------------------------------------------------------------------------
# 4. State transition
# ---------------------------------------------------------------------------

def _find_account(state: State, address: int) -> Tuple[int, Account]:
    for i, acc in enumerate(state):
        if acc.address == address:
            return i, acc
    raise ValueError(f"address {address} not found in state")


def apply_tx(state: State, tx: Transaction, sk_map: Dict[int, bytes]) -> State:
    """Apply a single transaction to a copy of the state.

    Checks:
    - sender exists with balance >= amount
    - signature is valid (using sk_map: address -> secret key bytes)
    Returns the updated state (new Account list, not mutated in place).
    Raises ValueError on any failure.
    """
    sk = sk_map.get(tx.sender)
    if sk is None:
        raise ValueError(f"no secret key for address {tx.sender}")
    if not verify_tx(sk, tx, tx.sig):
        raise ValueError("invalid transaction signature")

    send_idx, sender = _find_account(state, tx.sender)
    recv_idx, _ = _find_account(state, tx.receiver)

    if sender.balance < tx.amount:
        raise ValueError(
            f"insufficient balance: {sender.balance} < {tx.amount}"
        )

    new_state = [Account(a.address, a.balance) for a in state]
    new_state[send_idx].balance -= tx.amount
    new_state[recv_idx].balance += tx.amount
    return new_state


def apply_batch(
    state: State, txs: List[Transaction], sk_map: Dict[int, bytes]
) -> State:
    """Apply a list of transactions sequentially, returning the final state."""
    current = state
    for tx in txs:
        current = apply_tx(current, tx, sk_map)
    return current


# ---------------------------------------------------------------------------
# 5. Simplified validity proof (NOT real ZK)
# ---------------------------------------------------------------------------

def _commitment_randomness(seed: bytes, slot: int) -> bytes:
    """Deterministic per-commitment randomness: SHA-256(seed || slot_BE4)."""
    return hashlib.sha256(seed + struct.pack(">I", slot)).digest()


def _commit(value: int, randomness: bytes) -> bytes:
    """Simplified hiding commitment: SHA-256(value_BE8 || randomness).

    Warning: Not a real Pedersen commitment -- this is a hash-based stand-in.
    """
    return hashlib.sha256(struct.pack(">Q", value) + randomness).digest()


@dataclass
class TxProofData:
    """Per-transaction disclosure data for the simplified validity proof.

    NOTE: Revealing balance and randomness breaks zero-knowledge completely.
    This is educational scaffolding to show the structure, not real ZK.
    """

    tx_index: int
    old_balance: int
    amount: int
    balance_minus_amount: int       # must be >= 0
    commitment_old: bytes           # H(old_balance || r_old)
    commitment_new: bytes           # H(new_balance || r_new)
    randomness_old: bytes           # revealed (breaks ZK -- demo only)
    randomness_new: bytes           # revealed (breaks ZK -- demo only)


def generate_validity_proof(
    old_state: State,
    new_state: State,
    txs: List[Transaction],
    seed: bytes,
) -> Tuple[bytes, List[TxProofData]]:
    """Generate a simplified validity proof for a batch of transactions.

    For each transaction i:
    - Commit to sender's balance just before tx[i]:  C_old = H(pre_balance || r_old)
    - Commit to sender's balance just after  tx[i]:  C_new = H(post_balance || r_new)
      where post_balance = pre_balance - amount.
    - Reveal balance_minus_amount = pre_balance - amount  (must be >= 0)

    The final validity_proof is:
        SHA-256(old_root || new_root || C_old_0 || C_new_0 || ... )

    Warning: Not zero-knowledge (balance and randomness are revealed).
    Warning: Not succinct (size grows with batch size).
    Educational scaffolding to demonstrate commitment structure only.
    """
    old_root = state_root(old_state)
    new_root = state_root(new_state)

    disclosures: List[TxProofData] = []

    # Walk through intermediate states so we capture the sender's balance
    # *just before* each individual transaction is applied.
    intermediate = old_state
    for i, tx in enumerate(txs):
        _, pre_acc = _find_account(intermediate, tx.sender)
        pre_balance = pre_acc.balance
        post_balance = pre_balance - tx.amount

        if post_balance < 0:
            raise ValueError("bug: state transition should have caught this")

        r_old = _commitment_randomness(seed, 2 * i)
        r_new = _commitment_randomness(seed, 2 * i + 1)

        c_old = _commit(pre_balance,  r_old)
        c_new = _commit(post_balance, r_new)

        disclosures.append(TxProofData(
            tx_index=i,
            old_balance=pre_balance,
            amount=tx.amount,
            balance_minus_amount=post_balance,
            commitment_old=c_old,
            commitment_new=c_new,
            randomness_old=r_old,
            randomness_new=r_new,
        ))

        # Advance the intermediate state (no signature check needed here --
        # apply_batch already validated everything before we reach proof gen).
        next_state = [Account(a.address, a.balance) for a in intermediate]
        si, _ = _find_account(intermediate, tx.sender)
        ri, _ = _find_account(intermediate, tx.receiver)
        next_state[si].balance -= tx.amount
        next_state[ri].balance += tx.amount
        intermediate = next_state

    h = hashlib.sha256()
    h.update(old_root)
    h.update(new_root)
    for d in disclosures:
        h.update(d.commitment_old)
        h.update(d.commitment_new)
    validity_proof = h.digest()

    return validity_proof, disclosures


def verify_validity_proof(
    old_root: bytes,
    new_root: bytes,
    validity_proof: bytes,
    disclosures: List[TxProofData],
) -> bool:
    """Verify the simplified validity proof.

    Checks:
    1. Each balance_minus_amount >= 0 (sender had enough funds).
    2. Each commitment opens correctly to the revealed balance.
    3. The validity_proof hash recomputes from old_root, new_root, commitments.
    """
    h = hashlib.sha256()
    h.update(old_root)
    h.update(new_root)

    for d in disclosures:
        if d.balance_minus_amount < 0:
            return False

        expected_c_old = _commit(d.old_balance, d.randomness_old)
        if expected_c_old != d.commitment_old:
            return False

        new_balance = d.old_balance - d.amount
        expected_c_new = _commit(new_balance, d.randomness_new)
        if expected_c_new != d.commitment_new:
            return False

        h.update(d.commitment_old)
        h.update(d.commitment_new)

    return h.digest() == validity_proof


# ---------------------------------------------------------------------------
# 6. L1 submission
# ---------------------------------------------------------------------------

@dataclass
class L1Submission:
    """Compressed rollup batch posted to L1."""

    old_root: bytes
    new_root: bytes
    validity_proof: bytes
    compressed_txs: bytes   # JSON-encoded list of tx payloads (hex)


def compress_txs(txs: List[Transaction]) -> bytes:
    """Serialize transaction list to JSON bytes for L1 posting."""
    records = [
        {
            "sender": tx.sender,
            "receiver": tx.receiver,
            "amount": tx.amount,
            "nonce": tx.nonce,
            "sig": tx.sig.hex(),
        }
        for tx in txs
    ]
    return json.dumps(records, separators=(",", ":")).encode()


def build_l1_submission(
    old_state: State,
    new_state: State,
    txs: List[Transaction],
    validity_proof: bytes,
) -> L1Submission:
    """Build the L1 submission bundle."""
    return L1Submission(
        old_root=state_root(old_state),
        new_root=state_root(new_state),
        validity_proof=validity_proof,
        compressed_txs=compress_txs(txs),
    )


# ---------------------------------------------------------------------------
# Main demo
# ---------------------------------------------------------------------------

def main():
    # --- Setup: 4 accounts with fixed addresses and balances ---
    print("=== Step 1: Initial L2 state (Merkle tree of balances) ===")

    ADDR_ALICE = 0x00000001
    ADDR_BOB   = 0x00000002
    ADDR_CAROL = 0x00000003
    ADDR_DAVE  = 0x00000004

    # Fixed "secret keys" -- deterministic for demo
    SK_ALICE = hashlib.sha256(b"sk:alice").digest()
    SK_BOB   = hashlib.sha256(b"sk:bob").digest()
    SK_CAROL = hashlib.sha256(b"sk:carol").digest()
    SK_DAVE  = hashlib.sha256(b"sk:dave").digest()

    sk_map: Dict[int, bytes] = {
        ADDR_ALICE: SK_ALICE,
        ADDR_BOB:   SK_BOB,
        ADDR_CAROL: SK_CAROL,
        ADDR_DAVE:  SK_DAVE,
    }

    initial_state: State = [
        Account(ADDR_ALICE, 1000),
        Account(ADDR_BOB,    500),
        Account(ADDR_CAROL,  750),
        Account(ADDR_DAVE,   250),
    ]

    old_root = state_root(initial_state)
    print("initial balances:", [(hex(a.address), a.balance) for a in initial_state])
    print("old_root:", old_root.hex())

    # Merkle inclusion proof for Alice (index 0)
    leaves = [a.leaf_hash() for a in initial_state]
    proof_alice = merkle_proof(leaves, 0)
    ok = merkle_verify(old_root, leaves[0], proof_alice, 0)
    print("merkle_verify(alice, old_root):", ok)

    # --- Step 2: Build a batch of 3 transactions ---
    print("\n=== Step 2: Build and sign transactions ===")

    tx1 = Transaction(sender=ADDR_ALICE, receiver=ADDR_BOB,   amount=100, nonce=1)
    tx2 = Transaction(sender=ADDR_BOB,   receiver=ADDR_CAROL, amount=50,  nonce=1)
    tx3 = Transaction(sender=ADDR_CAROL, receiver=ADDR_DAVE,  amount=200, nonce=1)

    tx1.sig = sign_tx(SK_ALICE, tx1)
    tx2.sig = sign_tx(SK_BOB,   tx2)
    tx3.sig = sign_tx(SK_CAROL, tx3)

    for tx in [tx1, tx2, tx3]:
        print(
            f"  tx: {hex(tx.sender)} -> {hex(tx.receiver)}, "
            f"amount={tx.amount}, sig={tx.sig.hex()[:16]}..."
        )

    # --- Step 3: Apply batch and get new state ---
    print("\n=== Step 3: Apply batch, compute new Merkle root ===")
    txs = [tx1, tx2, tx3]
    new_state = apply_batch(initial_state, txs, sk_map)
    new_root = state_root(new_state)

    print("new balances:", [(hex(a.address), a.balance) for a in new_state])
    print("new_root:", new_root.hex())

    # --- Step 4: Generate simplified validity proof ---
    print("\n=== Step 4: Generate validity proof ===")
    PROOF_SEED = b"rollup-demo-seed-v1"
    validity_proof, disclosures = generate_validity_proof(
        initial_state, new_state, txs, PROOF_SEED
    )
    print("validity_proof:", validity_proof.hex())
    for d in disclosures:
        print(
            f"  tx[{d.tx_index}]: old_bal={d.old_balance}, amount={d.amount}, "
            f"remainder={d.balance_minus_amount}, "
            f"c_old={d.commitment_old.hex()[:16]}..."
        )

    # --- Step 5: Verify the proof ---
    print("\n=== Step 5: Verify validity proof ===")
    ok = verify_validity_proof(old_root, new_root, validity_proof, disclosures)
    print("proof_valid:", ok)

    # Tamper check: flip one commitment byte
    d0 = disclosures[0]
    bad_d0 = TxProofData(
        tx_index=d0.tx_index,
        old_balance=d0.old_balance,
        amount=d0.amount,
        balance_minus_amount=d0.balance_minus_amount,
        commitment_old=bytes([d0.commitment_old[0] ^ 0xFF]) + d0.commitment_old[1:],
        commitment_new=d0.commitment_new,
        randomness_old=d0.randomness_old,
        randomness_new=d0.randomness_new,
    )
    bad_disclosures = [bad_d0] + disclosures[1:]
    bad_ok = verify_validity_proof(old_root, new_root, validity_proof, bad_disclosures)
    print("tampered_proof_valid:", bad_ok)

    # --- Step 6: L1 submission ---
    print("\n=== Step 6: L1 submission ===")
    submission = build_l1_submission(initial_state, new_state, txs, validity_proof)
    print("old_root      :", submission.old_root.hex())
    print("new_root      :", submission.new_root.hex())
    print("validity_proof:", submission.validity_proof.hex())
    print("compressed_txs (first 60 chars):", submission.compressed_txs[:60].decode())
    print(
        "L1 submission size:",
        len(submission.compressed_txs) + 32 + 32 + 32,
        "bytes (approx)",
    )


if __name__ == "__main__":
    main()
