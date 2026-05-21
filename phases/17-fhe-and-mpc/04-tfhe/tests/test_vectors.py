import sys
import os
import json
import random

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../code')))
from main import encode_boolean, decode_boolean, torus_add, torus_sub, tlwe_keygen, tlwe_encrypt, tlwe_decrypt, homomorphic_nand

def test_vectors():
    vectors_path = os.path.join(os.path.dirname(__file__), 'vectors.json')
    with open(vectors_path, 'r') as f:
        data = json.load(f)

    for case in data['vectors']:
        op = case['op']
        inp = case['input']
        expected = case['expected']
        
        if op == "encode_boolean":
            assert encode_boolean(inp) == expected
        elif op == "decode_boolean":
            assert decode_boolean(inp) == expected
        elif op == "torus_add":
            assert torus_add(inp[0], inp[1]) == expected
        elif op == "torus_sub":
            assert torus_sub(inp[0], inp[1]) == expected
            
    print("test_vectors passed")

def test_tlwe():
    n = 128
    s = tlwe_keygen(n)
    alpha = 0.001
    
    for bit in [0, 1]:
        c = tlwe_encrypt(bit, s, alpha)
        dec = tlwe_decrypt(c, s)
        assert dec == bit
        
    print("test_tlwe passed")
    
def test_homomorphic_nand():
    n = 128
    s = tlwe_keygen(n)
    alpha = 0.0001
    
    for bit1 in [0, 1]:
        for bit2 in [0, 1]:
            c1 = tlwe_encrypt(bit1, s, alpha)
            c2 = tlwe_encrypt(bit2, s, alpha)
            
            c_out = homomorphic_nand(c1, c2)
            dec_out = tlwe_decrypt(c_out, s)
            
            expected = 1 - (bit1 & bit2)
            assert dec_out == expected, f"Failed NAND for {bit1}, {bit2}"
            
    print("test_homomorphic_nand passed")

if __name__ == "__main__":
    random.seed(42)
    test_vectors()
    test_tlwe()
    test_homomorphic_nand()
    print("all tests pass")
