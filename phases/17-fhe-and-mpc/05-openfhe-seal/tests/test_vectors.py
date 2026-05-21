import os
import sys
import json
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../code')))
from main import EncryptionParameters, FHEContext, KeyGenerator, BatchEncoder, Encryptor, Evaluator, Decryptor

def run_fhe_mock(poly_degree, array1, array2, operation):
    params = EncryptionParameters("BFV")
    params.set_poly_modulus_degree(poly_degree)
    context = FHEContext(params)
    
    keygen = KeyGenerator(context)
    pk, sk, relin_keys = keygen.generate_keys()
    
    encoder = BatchEncoder(context)
    plain1 = encoder.encode(array1)
    plain2 = encoder.encode(array2)
    
    encryptor = Encryptor(context, pk)
    cipher1 = encryptor.encrypt(plain1)
    cipher2 = encryptor.encrypt(plain2)
    
    evaluator = Evaluator(context)
    
    if operation == "add":
        out = evaluator.add(cipher1, cipher2)
    elif operation == "multiply":
        out = evaluator.multiply(cipher1, cipher2)
    elif operation == "multiply_and_relinearize":
        out = evaluator.multiply(cipher1, cipher2)
        out = evaluator.relinearize(out, relin_keys)
    else:
        raise ValueError("unknown op")
        
    decryptor = Decryptor(context, sk)
    dec = decryptor.decrypt(out)
    res = encoder.decode(dec)
    
    return {"result": res, "depth": out.depth, "size": out.size}

def test_vectors():
    with open(os.path.join(os.path.dirname(__file__), 'vectors.json')) as f:
        vectors = json.load(f)
        
    for vec in vectors:
        if vec["op"] == "evaluate":
            inputs = vec["inputs"]
            expected = vec["expected"]
            out = run_fhe_mock(inputs["poly_modulus_degree"], inputs["array1"], inputs["array2"], inputs["operation"])
            assert out["result"] == expected["result"]
            assert out["depth"] == expected["depth"]
            assert out["size"] == expected["size"]

def test_noise_budget():
    params = EncryptionParameters("BFV")
    params.set_poly_modulus_degree(2048) # allows max depth 2
    context = FHEContext(params)
    
    keygen = KeyGenerator(context)
    pk, sk, relin_keys = keygen.generate_keys()
    
    encoder = BatchEncoder(context)
    plain = encoder.encode([2])
    
    encryptor = Encryptor(context, pk)
    c = encryptor.encrypt(plain)
    
    evaluator = Evaluator(context)
    
    # depth 0 -> 1
    c = evaluator.multiply(c, c)
    # depth 1 -> 2
    c = evaluator.multiply(c, c)
    
    # depth 2 -> 3 (should fail)
    with pytest.raises(RuntimeError):
        c = evaluator.multiply(c, c)

if __name__ == "__main__":
    test_vectors()
    test_noise_budget()
    print("all tests pass")
