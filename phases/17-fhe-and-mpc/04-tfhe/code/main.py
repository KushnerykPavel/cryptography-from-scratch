"""
TFHE: Torus Fully Homomorphic Encryption (Toy Implementation)
This file demonstrates the Torus LWE (TLWE) encryption scheme, which is the 
foundation of TFHE. It shows how to encode boolean values on the Torus, 
encrypt them, and evaluate a homomorphic NAND gate.

Run with: python3 code/main.py
"""

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

def tlwe_decrypt(c, s):
    a, b = c
    n = len(s)
    
    phase = b
    for i in range(n):
        if s[i] == 1:
            phase = torus_sub(phase, a[i])
            
    return decode_boolean(phase)

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

def get_noise_level(c, s, bit):
    """Measures the absolute noise level in a ciphertext."""
    a, b = c
    n = len(s)
    phase = b
    for i in range(n):
        if s[i] == 1:
            phase = torus_sub(phase, a[i])
    mu = encode_boolean(bit)
    noise = torus_sub(phase, mu)
    if noise > Q / 2:
        noise -= Q
    return abs(noise)

def main():
    print("=== Step 1: The Torus and Boolean Encoding ===")
    print("True (1) is encoded as: 1/8")
    print("False (0) is encoded as: 7/8 (-1/8)")
    print(f"Internal Torus representation (Q=2^32): True={encode_boolean(1)}, False={encode_boolean(0)}\n")

    print("=== Step 2: Key Generation and TLWE Encryption ===")
    n = 128
    alpha = 0.01  # Noise standard deviation
    s = tlwe_keygen(n)
    
    bit1 = 1
    bit2 = 1
    c1 = tlwe_encrypt(bit1, s, alpha)
    c2 = tlwe_encrypt(bit2, s, alpha)
    
    print(f"Encrypting bit1 = {bit1}")
    print(f"Encrypting bit2 = {bit2}")
    
    noise1 = get_noise_level(c1, s, bit1)
    noise2 = get_noise_level(c2, s, bit2)
    print(f"Initial noise level c1: {noise1 / Q:.4f}")
    print(f"Initial noise level c2: {noise2 / Q:.4f}\n")

    print("=== Step 3: Decryption ===")
    dec1 = tlwe_decrypt(c1, s)
    dec2 = tlwe_decrypt(c2, s)
    print(f"Decrypted bit1: {dec1} (Matches: {dec1 == bit1})")
    print(f"Decrypted bit2: {dec2} (Matches: {dec2 == bit2})\n")

    print("=== Step 4: Homomorphic NAND Gate ===")
    c_out = homomorphic_nand(c1, c2)
    dec_out = tlwe_decrypt(c_out, s)
    expected_out = 1 - (bit1 & bit2)
    
    print(f"Evaluated NAND({bit1}, {bit2}) homomorphically")
    print(f"Decrypted output: {dec_out} (Expected: {expected_out})")
    
    noise_out = get_noise_level(c_out, s, expected_out)
    print(f"Output noise level: {noise_out / Q:.4f}")
    print("Notice how the noise has grown! In full TFHE, Programmable Bootstrapping would reduce this noise.")

if __name__ == "__main__":
    random.seed(42)  # For deterministic output
    main()
