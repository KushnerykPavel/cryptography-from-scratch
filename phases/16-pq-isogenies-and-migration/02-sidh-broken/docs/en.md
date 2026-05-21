# SIDH & Why It Was Broken
> The key exchange with the shortest keys in post-quantum crypto died because it revealed too much structure.

**Type:** Build
**Languages:** Python
**Prerequisites:** 16.01 Isogenies — Maps Between Elliptic Curves
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** the structure of the SIDH key exchange and its reliance on supersingular isogeny graphs.
- **Compute** the action of an isogeny on auxiliary torsion points in a toy graph model.
- **Implement** the Torsion Compass (Castryck-Decru) attack to recover a secret path in polynomial time.
- **Distinguish** between the broken SIDH protocol and unbroken alternatives like CSIDH.
- **Apply** Kani's theorem intuition to understand why revealing torsion point mappings is fatal to isogeny secrecy.

## The Problem

By 2022, SIDH (Supersingular Isogeny Diffie-Hellman) and its NIST candidate SIKE were considered the most elegant post-quantum cryptosystems. They had a massive advantage: their public keys were incredibly small (just a few hundred bytes), making them a drop-in replacement for classical elliptic curve Diffie-Hellman.

However, in July 2022, Castryck and Decru dropped a bombshell paper. They completely broke SIDH/SIKE in polynomial time using a single core of a standard laptop. The problem wasn't the core hardness assumption (finding a path in a supersingular isogeny graph is still believed to be hard). The problem was that to make the key exchange work, Alice and Bob had to share *extra information*—specifically, how their secret isogenies transformed a basis of auxiliary torsion points. This extra information acted like a compass, allowing an attacker to navigate the vast isogeny graph and find the secret key effortlessly. Without understanding this break, one might accidentally design a new system with the same fatal flaw.

## The Concept

In a standard isogeny graph, finding a specific path of length $N$ takes $O(p^{1/4})$ or roughly exponential time in $N$, because there are $3^N$ possible paths (for a 3-isogeny graph). SIDH relied on this brute-force hardness.

However, SIDH required Alice to publish not just her end curve $E_A$, but also the images of Bob's torsion points $P$ and $Q$ under her secret isogeny $\phi_A$, i.e., $\phi_A(P)$ and $\phi_A(Q)$. 

The **Castryck-Decru attack** used a piece of algebraic geometry called Kani's Theorem. Simply put, Kani's Theorem allows an attacker to take the torsion point evaluations and mathematically check: *"If I guess the first step of Alice's path, is it the correct one?"*

Because the total degree of Alice's isogeny is known, and the action of the isogeny on a large enough torsion group is public, Kani's theorem acts as a flawless oracle. Instead of trying $3^N$ paths, the attacker guesses 3 edges at step 1, uses the oracle to pick the right one, then guesses 3 edges at step 2, and so on. The attack takes $O(N)$ time instead of $O(3^{N/2})$.

## Build It

We will build a toy model of SIDH and the Castryck-Decru attack to demonstrate the "Torsion Compass". Since true Kani's theorem requires complex abelian surfaces, our toy model will simulate the graph and the torsion point evaluations using matrix multiplication.

### Step 1: The Isogeny Graph
```python
class IsogenyGraph:
    def __init__(self, p: int):
        self.p = p

    def get_neighbors(self, node: int) -> list[int]:
        neighbors = []
        for i in range(3):
            h = hash_to_int(f"edge_{node}_{i}") % self.p
            neighbors.append(h)
        return neighbors
```
This sets up our toy supersingular isogeny graph. Each curve (node) has 3 deterministic neighbors.

### Step 2: SIDH Key Generation
```python
def sidh_alice_keygen(graph: IsogenyGraph, start_node: int, secret_path_indices: list[int]):
    current_node = start_node
    total_matrix = (1, 0, 0, 1) # Identity matrix

    for step_index in secret_path_indices:
        neighbors = graph.get_neighbors(current_node)
        next_node = neighbors[step_index]
        
        edge_matrix = generate_matrices(current_node, next_node)
        total_matrix = multiply_matrices(edge_matrix, total_matrix)
        
        current_node = next_node

    return current_node, total_matrix
```
Alice takes a secret walk and publishes her final curve `current_node` AND `total_matrix` (representing $\phi_A(P)$ and $\phi_A(Q)$). This matrix is the fatal flaw.

### Step 3: The Torsion Compass Attack
```python
def torsion_compass_attack(graph: IsogenyGraph, start_node: int, walk_length: int, public_key: tuple[int, tuple[int, int, int, int]]):
    target_node, target_matrix = public_key
    current_node = start_node
    recovered_path = []
    accumulated_matrix = (1, 0, 0, 1)
    
    for step in range(walk_length):
        neighbors = graph.get_neighbors(current_node)
        found_correct_step = False
        
        for idx, neighbor in enumerate(neighbors):
            if kani_oracle(current_node, neighbor, walk_length - step, target_matrix, accumulated_matrix):
                recovered_path.append(idx)
                edge_matrix = generate_matrices(current_node, neighbor)
                accumulated_matrix = multiply_matrices(edge_matrix, accumulated_matrix)
                current_node = neighbor
                found_correct_step = True
                break
                
        if not found_correct_step:
            raise ValueError(f"Attack failed to find a valid path at step {step}!")
            
    return recovered_path
```
Using the `kani_oracle` (which conceptually checks if a guessed step is compatible with the target torsion matrix), the attacker iteratively recovers the secret key in linear time.

Run it:
```bash
python3 code/main.py
```

## Use It

Because SIDH and SIKE are completely broken, you **must not use them**. However, the isogeny graph itself is still secure. Other protocols based on isogenies do not reveal auxiliary torsion points:

| Library / Protocol | Purpose | Status |
|--------------------|---------|--------|
| **CSIDH** | Key Exchange | Secure (relies on commutative group actions, no torsion points revealed). |
| **SQIsign** | Digital Signatures | Secure (NIST PQC standardization candidate, extremely compact signatures). |

## Pitfalls

1. **Over-sharing structure:** The fundamental flaw of SIDH was publishing the evaluations of $\phi_A$ on $P$ and $Q$. In cryptography, any extra algebraic structure exposed to the attacker is a potential vector.
2. **Assuming non-abelian means secure:** SIDH was designed because the commutative version (CSIDH) had vulnerabilities to quantum subexponential attacks. The non-commutative graph of SIDH seemed harder, but the structural hints ruined it.
3. **Ignoring higher-dimensional math:** The Castryck-Decru attack was missed for over 10 years because it relied on mapping the 1-dimensional elliptic curves to 2-dimensional abelian surfaces, which most cryptographers didn't actively study.

## Ship It

We have saved `sidh_audit_checklist.md` to the `outputs/` directory. This is an audit checklist for evaluating any new isogeny-based proposal. Use it when reviewing whitepapers or implementing cutting-edge isogeny cryptography to ensure no structural hints are leaked.

## Exercises

1. **Easy:** Run `python3 code/main.py`. Observe how the attacker recovers the path step-by-step without trying all combinations.
2. **Medium:** Modify `sidh_alice_keygen` to increase the path length to 20. See how the brute force approach would explode, but `torsion_compass_attack` still finishes instantly.
3. **Hard:** Implement a brute-force attacker that does NOT use the `kani_oracle` and does not have access to the `target_matrix`. Benchmark the time difference for a path of length 10 compared to the CD attack.

## Key Terms

| Term | What people say | What it actually means |
|------|-----------------|------------------------|
| **SIDH** | Supersingular Isogeny Diffie-Hellman | A broken key exchange protocol that used walks on isogeny graphs. |
| **Auxiliary Points** | Hints | Torsion point images $\phi(P), \phi(Q)$ required by SIDH for Bob to complete the key exchange. |
| **Kani's Theorem** | A math theorem | The theoretical basis of the CD attack that allows reconstructing an isogeny from its torsion action. |

## Further Reading

- Castryck, Decru (2022) — *An efficient key recovery attack on SIDH*
- Maino, Martindale, Panny, Pope, Robert (2022) — *A direct key recovery attack on SIDH* (The alternative/generalized break published simultaneously)
