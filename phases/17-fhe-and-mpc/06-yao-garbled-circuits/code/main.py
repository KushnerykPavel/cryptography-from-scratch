"""
Educational implementation of Yao's Garbled Circuits.
Run this file directly to see a Half-Adder evaluated securely.
"""

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

def evaluate_gate(garbled_table, label1, label2):
    """Evaluates a garbled gate given two input labels."""
    for c in garbled_table:
        m = dec(label1, label2, c)
        if m is not None:
            return m
    raise ValueError("Evaluation failed: no matching ciphertext found")

def dummy_oblivious_transfer(b, labels):
    """
    Simulates a 1-out-of-2 Oblivious Transfer.
    In reality, this uses public key crypto so the sender doesn't learn b,
    and the receiver doesn't learn labels[1-b].
    """
    return labels[b]

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
    print(f"\\n=== Step 2: Oblivious Transfer ===")
    print(f"Garbler's private input A: {garbler_input_A}")
    print(f"Evaluator's private input B: {evaluator_input_B}")
    
    label_A = wires['A'][garbler_input_A]
    label_B = dummy_oblivious_transfer(evaluator_input_B, wires['B'])
    print("Evaluator obtained their input label via Oblivious Transfer.")
    
    print("\\n=== Step 3: Evaluation ===")
    print("Evaluator decrypts the garbled tables...")
    label_S = evaluate_gate(table_S, label_A, label_B)
    label_C = evaluate_gate(table_C, label_A, label_B)
    
    print("\\n=== Step 4: Decoding ===")
    out_S = output_map[label_S]
    out_C = output_map[label_C]
    print(f"Result -> Sum: {out_S}, Carry: {out_C}")
    
    assert out_S == 0 and out_C == 1
    print("Half-adder evaluated successfully!")

if __name__ == "__main__":
    main()
