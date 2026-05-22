import json
import os
import sys

# Add parent directory to sys.path to import code module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../code')))

from main import enc, dec, garble_gate, evaluate_gate, generate_label

def test_vectors():
    with open(os.path.join(os.path.dirname(__file__), 'vectors.json')) as f:
        data = json.load(f)
        
    for vec in data['vectors']:
        if vec['op'] == 'enc':
            k1 = bytes.fromhex(vec['k1'])
            k2 = bytes.fromhex(vec['k2'])
            m = bytes.fromhex(vec['m'])
            expected = bytes.fromhex(vec['expected'])
            
            c = enc(k1, k2, m)
            assert c == expected, f"Expected {expected.hex()}, got {c.hex()}"
            
            # Test decryption
            m_dec = dec(k1, k2, c)
            assert m_dec == m

def test_roundtrip():
    k1 = generate_label()
    k2 = generate_label()
    m = generate_label()
    c = enc(k1, k2, m)
    m_dec = dec(k1, k2, c)
    assert m == m_dec

def test_invalid_decryption():
    k1 = generate_label()
    k2 = generate_label()
    m = generate_label()
    c = enc(k1, k2, m)
    
    # Decrypt with wrong key
    k1_wrong = generate_label()
    m_dec = dec(k1_wrong, k2, c)
    assert m_dec is None

def test_garble_and_evaluate():
    w_in1 = (generate_label(), generate_label())
    w_in2 = (generate_label(), generate_label())
    w_out = (generate_label(), generate_label())
    
    # Test AND gate
    garbled_table = garble_gate('AND', w_in1, w_in2, w_out)
    for b1 in (0, 1):
        for b2 in (0, 1):
            expected_out_bit = b1 & b2
            res_label = evaluate_gate(garbled_table, w_in1[b1], w_in2[b2])
            assert res_label == w_out[expected_out_bit]
            
    # Test XOR gate
    garbled_table = garble_gate('XOR', w_in1, w_in2, w_out)
    for b1 in (0, 1):
        for b2 in (0, 1):
            expected_out_bit = b1 ^ b2
            res_label = evaluate_gate(garbled_table, w_in1[b1], w_in2[b2])
            assert res_label == w_out[expected_out_bit]

if __name__ == "__main__":
    test_vectors()
    test_roundtrip()
    test_invalid_decryption()
    test_garble_and_evaluate()
    print("all tests pass")
