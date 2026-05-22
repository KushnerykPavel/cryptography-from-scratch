# Build a Mini ZK Rollup

> Compress a thousand L2 transactions into one 32-byte root and a proof no one can fake.

**Type:** Build
**Languages:** Python
**Prerequisites:** Merkle trees, ZK proof systems (R1CS/PLONK concepts), hash functions, digital signatures
**Time:** ~90 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain how a ZK rollup separates L2 execution from L1 settlement
- Build a Merkle tree of account balances and generate inclusion proofs
- Implement signed token transfers with canonical serialization
- Apply sequential state transitions to a batch of transactions
- Construct and verify a commitment-based validity proof that shows senders had sufficient balance

## The Problem

Ethereum can process roughly 15 transactions per second. That ceiling exists because every full node must re-execute every transaction to verify the chain. You cannot simply trust that a batch of transactions is valid without checking — and checking takes computation and block space.

ZK rollups break that bottleneck. The idea is to move execution off-chain: an operator batches thousands of L2 transactions, updates an L2 state (a Merkle tree of account balances), and then produces a cryptographic proof that all state transitions were valid. Only the old state root, the new state root, and the proof get posted to L1. Ethereum validators check the proof — a single cheap operation — rather than re-executing every transaction.

The proof is the key primitive. It must convince the L1 that (a) every sender had enough balance to cover their transfer, and (b) the new root is the correct result of applying those transfers to the old state. In production, systems like StarkWare and zkSync use real ZK proof systems (STARKs, SNARKs) to make the proof succinct and truly zero-knowledge. This lesson builds the same conceptual pipeline using hash-based commitments so you can see every moving part without a circuit-compilation toolchain.

## The Concept

**L2 state as a Merkle tree.** Four accounts hold token balances. Each account's leaf is `SHA-256(address_BE4 || balance_BE8)`. The Merkle root is `SHA-256(left_child || right_child)` recursively up the tree. The root is a fingerprint of the entire balance sheet: change any balance by one token and the root changes unpredictably.

**Transactions.** A transfer specifies sender, receiver, amount, and a nonce (replay protection). The sender signs the payload with their secret key — here HMAC-SHA256 for simplicity. The operator verifies the signature before applying any transfer.

**State transitions.** Applying a transaction to the state produces a new state (immutable copy). A batch is applied sequentially: each transaction sees the state left by the previous one. The final new root summarises all changes.

**Validity proof structure (simplified).** For each transaction in the batch, the operator:
1. Records the sender's balance *just before* that transaction (`pre_balance`).
2. Commits to `pre_balance` with randomness: `C_old = SHA-256(pre_balance_BE8 || r_old)`.
3. Commits to `post_balance = pre_balance - amount`: `C_new = SHA-256(post_balance_BE8 || r_new)`.
4. Records `balance_minus_amount = pre_balance - amount`, which must be >= 0.

The overall `validity_proof` is `SHA-256(old_root || new_root || C_old_0 || C_new_0 || ...)`.

The verifier reopens each commitment and checks: (a) `balance_minus_amount >= 0`, (b) `C_old` opens to `old_balance`, (c) `C_new` opens to `old_balance - amount`, and (d) the final hash matches `validity_proof`.

**What this is not.** Revealing `old_balance` and `randomness` during verification destroys zero-knowledge. A real system uses a ZK proof (Groth16, PLONK, or a STARK) so the verifier learns nothing about individual balances. The commitment structure here is identical in shape; only the hiding property is missing.

**L1 submission.** The operator posts `(old_root, new_root, validity_proof, compressed_txs)` to a smart contract. The contract checks that `old_root` matches its stored state, verifies the proof, and updates its state to `new_root`.

## Build It

### Step 1: Merkle tree over account balances

```python
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
```

The Merkle tree is the rollup's state representation. With 4 leaves (accounts) the tree has two levels of internal nodes plus the root — a depth-2 tree. An inclusion proof is just two sibling hashes. The `index ^ 1` trick picks the sibling: even index pairs with the node to its right, odd index pairs with the node to its left.

### Step 2: Account state and leaf encoding

```python
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
```

Each leaf hashes both the address and the balance together. If you hashed only the balance, two accounts with the same balance would produce identical leaves, which breaks the tree's collision resistance. Using big-endian fixed-width encoding (`struct.pack`) guarantees a canonical byte representation with no ambiguity.

### Step 3: Transactions and signatures

```python
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
```

`_tx_payload` produces a fixed 18-byte canonical encoding: 4 bytes sender + 4 bytes receiver + 8 bytes amount + 2 bytes nonce. This same encoding drives both signing and the compressed L1 representation. Using `hmac.compare_digest` prevents timing side-channels during verification.

### Step 4: State transition

```python
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
```

`apply_tx` returns a fresh copy of the state — no mutation. This matters when the validity proof generator needs to inspect intermediate states. `apply_batch` threads those copies sequentially: each transaction receives the state produced by the previous one.

### Step 5: Simplified validity proof

```python
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
```

The proof walks intermediate states rather than the final new state. If Bob receives tokens in tx[0] and spends them in tx[1], the "old balance" for tx[1] must reflect the credit from tx[0], not Bob's original balance. The `intermediate` variable tracks that step-by-step.

Run it:
```
python3 code/main.py
```

## Use It

Production ZK rollups replace the hash-based commitment with a real ZK proof system:

- **StarkWare (StarkEx, StarkNet)**: uses STARKs. The prover compiles state transition logic to an algebraic intermediate representation, runs the STARK prover, and posts a ~100 KB proof to L1. Verification costs ~200k gas regardless of batch size.
- **zkSync / Polygon zkEVM**: uses SNARKs (PLONK or Groth16). Smaller proof (~300 bytes), slightly higher proving cost, trusted setup required for Groth16.
- **Aztec**: focuses on privacy — uses UltraPlonk and shielded accounts so balances are never revealed on-chain (true zero-knowledge, unlike this demo).

The structural pipeline — state root, batch of transactions, proof, L1 submission — is identical to what you built here. The difference is that in production the verifier never sees individual balances; it only sees the proof.

## Pitfalls

- **Using the final new state for commitments instead of intermediate states.** If Alice sends Bob 100 in tx[0] and Bob sends Carol 50 in tx[1], Bob's balance in `new_state` already reflects both operations. Committing to that balance for tx[1] will make the proof verify against the wrong number. Walk intermediate states per transaction.
- **Mutable state in place.** `apply_tx` must return a fresh copy. If you mutate the input list, you corrupt the state used for proof generation.
- **Non-canonical leaf encoding.** If you use `str(balance)` instead of `struct.pack(">Q", balance)`, different Python versions or locales could produce different bytes for the same integer. Always use fixed-width big-endian.
- **Timing leak in signature verification.** Use `hmac.compare_digest`, not `==`, when comparing MACs or signatures.
- **Revealing randomness in a real system.** In this demo, `randomness_old` is disclosed to the verifier to open the commitment. In a real ZK rollup, the prover proves the commitment opens correctly *inside the circuit* — the randomness never leaves the prover.

## Ship It

Save a reusable ZK rollup architecture guide for your team: `outputs/rollup-architecture-guide.md`. It covers the five structural decisions every rollup implementation must make: state representation, transaction format, proof system choice, L1 submission format, and sequencer trust model.

## Exercises

1. Easy. Run `python3 code/main.py`. Confirm `proof_valid: True` and `tampered_proof_valid: False`. Add a fifth account and a fourth transaction to the batch.
2. Medium. Replace the 4-account flat list with a 8-account tree (depth 3). Verify that inclusion proofs now have 3 siblings. Confirm the proof still verifies after the batch.
3. Hard. Add a nonce check to `apply_tx`: each account has a `next_nonce` field, and transactions are rejected if `tx.nonce != account.next_nonce`. Include the updated nonce in the Merkle leaf hash so it is committed on-chain.

## Key Terms

| Term | What people say | What it actually means |
|------|-----------------|------------------------|
| ZK rollup | "Off-chain scaling with a proof" | L2 executes transactions; only state root delta and a validity proof land on L1 |
| State root | "The rollup's fingerprint" | Merkle root of all account balances; any balance change produces a different root |
| Validity proof | "The proof the batch is correct" | Cryptographic evidence that all state transitions respect the rules (balances non-negative, signatures valid) |
| Commitment | "Hide a value, reveal it later" | `C = H(value || randomness)`; binding (can't change value) and hiding (C reveals nothing about value) |
| Data availability | "Where is the batch data?" | L1 must store enough data for anyone to reconstruct L2 state; without it, funds can be frozen |
| Sequencer | "Who orders L2 transactions?" | The off-chain operator that batches, proves, and submits; a central sequencer is a trust assumption |

## Further Reading

- Barry Whitehat, "Roll Up" (2018, ethresear.ch) — the original rollup proposal that coined the term
- Buterin, "An Incomplete Guide to Rollups" (2021, vitalik.ca) — excellent mental model for optimistic vs ZK rollups and data availability
- StarkWare, "StarkEx Deep Dive" (docs.starkware.co) — real production validity proof pipeline
- Gabizon, Williamson & Ciobotaru, "PLONK: Permutations over Lagrange-bases for Oecumenical Noninteractive arguments of Knowledge" (2019) — the proof system behind most modern ZK rollups
