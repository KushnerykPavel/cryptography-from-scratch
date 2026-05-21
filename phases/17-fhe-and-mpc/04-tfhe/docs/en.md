# TFHE: Torus Fully Homomorphic Encryption
> Computing over encrypted data without noise ceilings, evaluating gates infinitely.

**Type:** Build
**Languages:** Python
**Prerequisites:** 17-01-fhe-foundations, 17-02-bgv-bfv
**Time:** ~45 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** the representation of the Torus in TFHE and how it maps to integer arithmetic.
- **Implement** a Torus LWE (TLWE) encryption scheme for boolean values.
- **Compute** a homomorphic NAND gate natively using linear combination over Torus.
- **Distinguish** between TFHE's gate evaluation and BGV/BFV's arithmetic circuits.
- **Apply** noise growth measurement to understand why Programmable Bootstrapping is needed.

## The Problem
In standard Fully Homomorphic Encryption schemes like BGV or BFV, operations (like multiplication) dramatically increase the noise inside the ciphertext. To evaluate a deep circuit, you either need massive parameters (which hurts performance) or an extremely expensive bootstrapping operation that refreshes the noise.

TFHE solves this by redefining the domain. Instead of integers, it encrypts values on a Torus (real numbers modulo 1). It enables extremely fast, per-gate bootstrapping. Instead of treating bootstrapping as a rare, heavy penalty, TFHE embraces it: it bootstraps *after every single binary gate*. This allows circuits of infinite depth with relatively small, fast parameters.

## The Concept
TFHE represents values on the continuous Torus $\mathbb{T} = \mathbb{R} / \mathbb{Z}$, meaning numbers from $[0, 1)$. In software, we discretize this using 32-bit or 64-bit integers. Here, we'll map $[0, 1)$ to integers modulo $Q = 2^{32}$.

To encode boolean logic, TFHE maps bits to specific points on the Torus:
- **True (1)** is encoded as $1/8$.
- **False (0)** is encoded as $-1/8$ (which is $7/8$ on the Torus).

When we perform a TLWE encryption, the ciphertext is a pair $(a, b)$, where:
$b = \langle a, s \rangle + e + \mu$

To evaluate a **NAND** gate homomorphically, we use the fact that our encoding maps Boolean logic into arithmetic:
$c_{NAND} = (0, \frac{1}{8}) - c_1 - c_2$

This simple linear combination perfectly translates to the NAND truth table on the Torus! However, adding ciphertexts increases the noise $e$. In full TFHE, a Programmable Bootstrapping step follows the gate to reduce the noise and map the phase precisely back to $\pm 1/8$.

## Build It
### Step 1: The Torus and Boolean Encoding
```python
import random
import math

Q = 2**32

def torus_add(x, y):
    return (x + y) % Q

def torus_sub(x, y):
    return (x - y) % Q

def encode_boolean(bit):
    """
    Encodes a boolean bit to a Torus value.
    True (1) -> 1/8
    False (0) -> -1/8 (which is 7/8 mod 1)
    """
    if bit:
        return int(Q / 8)
    else:
        return int(7 * Q / 8)

def decode_boolean(torus_value):
    """
    Decodes a Torus value to a boolean bit.
    Values in (0, 1/2) are True.
    Values in (1/2, 1) are False.
    """
    if 0 <= torus_value < Q / 2:
        return 1
    else:
        return 0
```
This sets up our modular arithmetic and our specific $\pm 1/8$ boolean encoding.

### Step 2: Key Generation and TLWE Encryption
```python
def sample_torus():
    return random.randint(0, Q - 1)

def sample_noise(alpha):
    std_dev = alpha * Q
    noise = int(random.gauss(0, std_dev))
    return noise % Q

def tlwe_keygen(n):
    return [random.randint(0, 1) for _ in range(n)]

def tlwe_encrypt(bit, s, alpha):
    n = len(s)
    a = [sample_torus() for _ in range(n)]
    e = sample_noise(alpha)
    mu = encode_boolean(bit)
    
    b = e
    for i in range(n):
        if s[i] == 1:
            b = torus_add(b, a[i])
            
    b = torus_add(b, mu)
    return (a, b)
```
We generate a binary secret key `s`, sample a random mask `a`, and compute `b` with Gaussian noise `e`. 

### Step 3: Decryption
```python
def tlwe_decrypt(c, s):
    a, b = c
    n = len(s)
    
    phase = b
    for i in range(n):
        if s[i] == 1:
            phase = torus_sub(phase, a[i])
            
    return decode_boolean(phase)
```
To decrypt, we remove the mask $\langle a, s \rangle$ to extract the phase, and use our decoder to map the Torus region back to a boolean bit.

### Step 4: Homomorphic NAND Gate
```python
def homomorphic_nand(c1, c2):
    """
    Evaluates a NAND gate homomorphically on two TLWE ciphertexts.
    In TFHE encoding: NAND(c1, c2) = (0, 1/8) - c1 - c2
    """
    a1, b1 = c1
    a2, b2 = c2
    n = len(a1)
    
    a_out = [torus_sub(0, torus_add(a1[i], a2[i])) for i in range(n)]
    
    const_1_8 = int(Q / 8)
    b_out = torus_sub(const_1_8, torus_add(b1, b2))
    
    return (a_out, b_out)
```
The homomorphic NAND operation is a completely linear operation: we subtract both ciphertexts from the constant `1/8`. 

Run it:
```bash
python3 code/main.py
```

## Use It

| Library | Description |
|---|---|
| **Concrete (Zama)** | Production-ready TFHE compiler for Python and Rust. Handles the bootstrapping logic automatically. |
| **TFHE-rs** | Official Rust implementation of TFHE by Zama. Very fast and extensive. |
| **OpenFHE** | C++ library that supports TFHE along with BGV, BFV, and CKKS. |

## Pitfalls

- **Ignoring the Bootstrapping Cost:** While TFHE makes gate evaluation easy, blind rotation (bootstrapping) is computationally heavy. Evaluating thousands of gates sequentially is extremely slow without hardware acceleration.
- **Precision Loss:** When mapping the continuous Torus to 32-bit or 64-bit integers, there's inherently a discretization error.
- **Noise Overflow:** In our toy implementation, chaining too many NAND gates without a bootstrapping step will cause the noise to overflow the $(0, 1/2)$ boundaries, leading to incorrect decryption.

## Ship It

We have generated a `tfhe_evaluation_guide.md` in `outputs/`. This guide acts as a checklist for deciding when to use TFHE over BFV/CKKS, including a breakdown of boolean vs. arithmetic circuits. You can use this to assess if your application is a good fit for TFHE.

## Exercises

1. Easy. Run `python3 code/main.py`. Observe how the noise level increases after evaluating the NAND gate.
2. Medium. Implement a Homomorphic AND gate. Hint: How can you adjust the constant from `1/8` to something else to represent an AND instead of NAND? (AND is `-1/8 + c_1 + c_2`).
3. Hard. Implement an XOR gate using three NAND operations homomorphically. Note the final noise level compared to a single NAND.

## Key Terms

| Term | What people say | What it actually means |
|---|---|---|
| **Torus** | "Math shape" | Real numbers modulo 1, allowing for continuous mapping that gracefully loops around. |
| **TLWE** | "TFHE's LWE" | Torus LWE, an LWE variant where values live on the Torus instead of integers modulo $q$. |
| **Programmable Bootstrapping** | "Refreshing noise" | A TFHE technique that not only refreshes the noise of a ciphertext but also evaluates a function on it at the same time. |

## Further Reading

- Chillotti et al., TFHE: Fast Fully Homomorphic Encryption over the Torus (2020) — The definitive paper on TFHE.
