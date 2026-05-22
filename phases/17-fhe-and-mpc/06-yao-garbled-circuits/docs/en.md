# Yao's Garbled Circuits
> Two parties compute a function on private inputs without revealing anything but the final output.

**Type:** Learn | Build
**Languages:** Python
**Prerequisites:** Oblivious Transfer, Symmetric Encryption
**Time:** ~45 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** the concept of wire labels and garbled tables.
- **Compute** a secure two-party computation without revealing private inputs.
- **Implement** a garbled gate using symmetric encryption.
- **Distinguish** between the roles of the Garbler and the Evaluator.
- **Apply** a simulated Oblivious Transfer to fetch evaluator labels securely.

## The Problem
Imagine a millionaire's problem: Alice and Bob want to know who is wealthier, without revealing their actual net worth to each other. Or two hospitals wanting to train a machine learning model on combined patient data without violating patient privacy laws. 

If Alice just sends her data to Bob, Bob learns everything. If they use a trusted third party, that party becomes a single point of failure and a high-value target for hackers. We need a way to evaluate a boolean circuit such that neither party learns the other's inputs, only the final result.

## The Concept
Yao's Garbled Circuits allow two parties (the **Garbler** and the **Evaluator**) to evaluate any boolean circuit securely.

1. **Garbling the Circuit**: The Garbler creates a "garbled" version of the circuit. For every wire, they generate two random 128-bit labels (one representing `0`, one representing `1`). Then, for each gate (like AND or XOR), they encrypt the output wire's labels using the input wire's labels as keys. The four possible ciphertexts are shuffled into a "garbled table."
2. **Oblivious Transfer**: The Garbler sends the garbled tables and the labels corresponding to their own input directly to the Evaluator. For the Evaluator's input, they use a protocol called **Oblivious Transfer** (OT). OT lets the Evaluator fetch the exact label for their input bit, without the Garbler learning which bit they chose, and without the Evaluator learning the label for the other bit.
3. **Evaluation**: The Evaluator now has the garbled tables and exactly one label per input wire. They go through the circuit gate by gate. For each gate, they try to decrypt the four ciphertexts. Exactly one will decrypt successfully, yielding the label for the output wire.
4. **Decoding**: Once the final output labels are computed, the Garbler provides a mapping to reveal what those labels actually mean (`0` or `1`).

## Build It

### Step 1: Garbling

The Garbler assigns two random labels to every wire, then creates garbled gates.

```python
import hashlib
import os
import random

def generate_label():
    """Generates a random 16-byte label for a wire."""
    return os.urandom(16)

def enc(k1, k2, m):
    """Encrypts message m using two keys k1, k2 via SHA-256 stream.
    Appends 16 bytes of zeros to validate successful decryption.
    """
    h = hashlib.sha256(k1 + k2).digest()
    plaintext = m + b'\x00' * 16
    return bytes(a ^ b for a, b in zip(h, plaintext))

def dec(k1, k2, c):
    """Decrypts ciphertext c using k1, k2. Returns None if invalid."""
    h = hashlib.sha256(k1 + k2).digest()
    plaintext = bytes(a ^ b for a, b in zip(h, c))
    m, val = plaintext[:16], plaintext[16:]
    if val == b'\x00' * 16:
        return m
    return None

def garble_gate(g_type, w_in1, w_in2, w_out):
    """
    Garbles a single 2-input gate.
    w_in1, w_in2, w_out are tuples of (label_0, label_1).
    """
    garbled_table = []
    for b1 in (0, 1):
        for b2 in (0, 1):
            if g_type == 'AND':
                out_bit = b1 & b2
            elif g_type == 'XOR':
                out_bit = b1 ^ b2
            elif g_type == 'OR':
                out_bit = b1 | b2
            else:
                raise ValueError("Unsupported gate type")
            
            c = enc(w_in1[b1], w_in2[b2], w_out[out_bit])
            garbled_table.append(c)
            
    random.shuffle(garbled_table)
    return garbled_table
```
This generates the core garbled table for any boolean gate. The output table is randomly shuffled so the Evaluator cannot infer the input bits by looking at the index of the decrypted ciphertext.

### Step 2: Oblivious Transfer

The Evaluator needs labels for their inputs without revealing them to the Garbler. 

```python
def dummy_oblivious_transfer(b, labels):
    """
    Simulates a 1-out-of-2 Oblivious Transfer.
    In reality, this uses public key crypto so the sender doesn't learn b,
    and the receiver doesn't learn labels[1-b].
    """
    return labels[b]
```
In our simulation, we skip the heavy math of OT. The `dummy_oblivious_transfer` strictly returns the requested label.

### Step 3: Evaluation

The Evaluator blindly evaluates the gates using the labels they have.

```python
def evaluate_gate(garbled_table, label1, label2):
    """Evaluates a garbled gate given two input labels."""
    for c in garbled_table:
        m = dec(label1, label2, c)
        if m is not None:
            return m
    raise ValueError("Evaluation failed: no matching ciphertext found")
```
The evaluator tries to decrypt every entry in the garbled table. Because we appended `\x00` * 16 during encryption, exactly one ciphertext will decrypt correctly.

### Step 4: Putting it all together

Let's evaluate a Half-Adder (which computes Sum = A XOR B, and Carry = A AND B).

```python
def main():
    print("=== Step 1: Garbling ===")
    # Circuit: Half-Adder (S = A XOR B, C = A AND B)
    random.seed(42) # For reproducibility in the table shuffle (partially)
    
    wires = {
        'A': (generate_label(), generate_label()),
        'B': (generate_label(), generate_label()),
        'S': (generate_label(), generate_label()),
        'C': (generate_label(), generate_label())
    }
    
    table_S = garble_gate('XOR', wires['A'], wires['B'], wires['S'])
    table_C = garble_gate('AND', wires['A'], wires['B'], wires['C'])
    print("Garbler has generated labels and garbled XOR (Sum) and AND (Carry) gates.")
    
    output_map = {
        wires['S'][0]: 0, wires['S'][1]: 1,
        wires['C'][0]: 0, wires['C'][1]: 1
    }
    
    garbler_input_A = 1
    evaluator_input_B = 1
    print(f"\n=== Step 2: Oblivious Transfer ===")
    print(f"Garbler's private input A: {garbler_input_A}")
    print(f"Evaluator's private input B: {evaluator_input_B}")
    
    label_A = wires['A'][garbler_input_A]
    label_B = dummy_oblivious_transfer(evaluator_input_B, wires['B'])
    print("Evaluator obtained their input label via Oblivious Transfer.")
    
    print("\n=== Step 3: Evaluation ===")
    print("Evaluator decrypts the garbled tables...")
    label_S = evaluate_gate(table_S, label_A, label_B)
    label_C = evaluate_gate(table_C, label_A, label_B)
    
    print("\n=== Step 4: Decoding ===")
    out_S = output_map[label_S]
    out_C = output_map[label_C]
    print(f"Result -> Sum: {out_S}, Carry: {out_C}")
    
    assert out_S == 0 and out_C == 1
    print("Half-adder evaluated successfully!")

if __name__ == "__main__":
    main()
```

Run it:
```bash
python3 code/main.py
```

## Use It

| Library | Language | Why Use It |
|---|---|---|
| **EMP-toolkit** | C++ | Highly optimized suite of MPC protocols, including state-of-the-art Garbled Circuits. |
| **Obliv-C** | C | A C extension for programming 2PC using Garbled Circuits easily. |
| **MP-SPDZ** | C++/Python | Comprehensive framework for various MPC protocols, including Yao's GC. |

## Pitfalls

1. **Reusing Labels**: The Garbler MUST generate new random labels for every single execution. Reusing the garbled circuit or wire labels completely breaks the encryption.
2. **Deterministic Permutation**: If the Garbler doesn't randomly shuffle the four ciphertexts in the garbled table, the Evaluator can figure out the truth values from their position.
3. **Leaking Data in OT**: Implementing Oblivious Transfer incorrectly might leak the Evaluator's choice or the Garbler's other label. Both completely break the security of the protocol.

## Ship It

We have packaged a **Garbled Circuits Architecture Checklist** to help you securely design systems using Garbled Circuits. You can find it in `outputs/gc_checklist.md`.

## Exercises

1. **Easy**: Run `python3 code/main.py`. Observe the output. Change the inputs `garbler_input_A` and `evaluator_input_B` to test all 4 combinations of a half-adder.
2. **Medium**: Extend the circuit to be a Full Adder (using 3 inputs: A, B, and Carry-In). You will need to wire two Half-Adders and an OR gate together.
3. **Hard**: Implement "Point-and-Permute", an optimization where each label has a random color bit. The evaluator uses the XOR of the two input color bits to index directly into the garbled table, avoiding trial decryption.

## Key Terms

| Term | What people say | What it actually means |
|---|---|---|
| **Garbler** | "The one who makes the circuit." | The party that generates the wire labels, encrypts the truth tables, and supplies their own input's labels. |
| **Evaluator** | "The one who computes the result." | The party that blindly decrypts the garbled tables using labels obtained via Oblivious Transfer. |
| **Garbled Table** | "The encrypted gate." | The shuffled collection of four ciphertexts corresponding to a 2-input boolean gate. |

## Further Reading

- Yao, *How to Generate and Exchange Secrets* (1986) — The seminal paper introducing Garbled Circuits.
- Bellare, Hoang, Rogaway, *Foundations of Garbled Circuits* (2012) — A formal cryptographic treatment of garbling schemes.
