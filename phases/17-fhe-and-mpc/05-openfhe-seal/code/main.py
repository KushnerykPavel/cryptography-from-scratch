"""
Educational simulation of an FHE library API (like Microsoft SEAL or OpenFHE) in Python.
Demonstrates the lifecycle of an FHE program: Parameters, Context, Keys, Encoding, and Evaluation.
To run: python3 code/main.py
"""

class EncryptionParameters:
    def __init__(self, scheme: str):
        self.scheme = scheme
        self.poly_modulus_degree = 0

    def set_poly_modulus_degree(self, degree: int):
        self.poly_modulus_degree = degree

class FHEContext:
    def __init__(self, params: EncryptionParameters):
        self.params = params
        if params.poly_modulus_degree < 1024:
            raise ValueError("poly_modulus_degree too small for security")
        # Simulate max multiplication depth based on degree
        # In real FHE, this depends on the coeff_modulus chain
        self.max_mult_depth = params.poly_modulus_degree // 1024

class Plaintext:
    def __init__(self, values: list):
        self.values = values

class Ciphertext:
    def __init__(self, values: list, depth: int = 0):
        self.values = values
        self.depth = depth
        self.size = 2 # Initial ciphertext has 2 polynomials

class KeyGenerator:
    def __init__(self, context: FHEContext):
        self.context = context
    
    def generate_keys(self):
        return "PublicKey", "SecretKey", "RelinKey"

class BatchEncoder:
    def __init__(self, context: FHEContext):
        self.context = context
        self.slot_count = context.params.poly_modulus_degree // 2

    def encode(self, array: list) -> Plaintext:
        if len(array) > self.slot_count:
            raise ValueError("Array exceeds slot count")
        return Plaintext(array)

    def decode(self, plain: Plaintext) -> list:
        return plain.values

class Encryptor:
    def __init__(self, context: FHEContext, public_key: str):
        self.context = context
        self.public_key = public_key

    def encrypt(self, plain: Plaintext) -> Ciphertext:
        return Ciphertext(plain.values, depth=0)

class Decryptor:
    def __init__(self, context: FHEContext, secret_key: str):
        self.context = context
        self.secret_key = secret_key

    def decrypt(self, cipher: Ciphertext) -> Plaintext:
        return Plaintext(cipher.values)

class Evaluator:
    def __init__(self, context: FHEContext):
        self.context = context

    def add(self, cipher1: Ciphertext, cipher2: Ciphertext) -> Ciphertext:
        vals = [a + b for a, b in zip(cipher1.values, cipher2.values)]
        depth = max(cipher1.depth, cipher2.depth)
        c = Ciphertext(vals, depth)
        c.size = max(cipher1.size, cipher2.size)
        return c

    def multiply(self, cipher1: Ciphertext, cipher2: Ciphertext) -> Ciphertext:
        vals = [a * b for a, b in zip(cipher1.values, cipher2.values)]
        depth = max(cipher1.depth, cipher2.depth) + 1
        if depth > self.context.max_mult_depth:
            raise RuntimeError("Noise budget exhausted! (multiplication depth exceeded)")
        
        c = Ciphertext(vals, depth)
        c.size = cipher1.size + cipher2.size - 1
        return c

    def relinearize(self, cipher: Ciphertext, relin_key: str) -> Ciphertext:
        cipher.size = 2
        return cipher


def main():
    print("=== Step 1: Setting up the Context ===")
    params = EncryptionParameters("BFV")
    params.set_poly_modulus_degree(8192)
    context = FHEContext(params)
    print(f"Context initialized. Max multiplication depth: {context.max_mult_depth}")
    
    print("\n=== Step 2: Keys and Batch Encoding ===")
    keygen = KeyGenerator(context)
    pk, sk, relin_keys = keygen.generate_keys()
    
    encoder = BatchEncoder(context)
    data1 = [1, 2, 3, 4]
    data2 = [5, 6, 7, 8]
    plain1 = encoder.encode(data1)
    plain2 = encoder.encode(data2)
    print(f"Encoded array 1: {plain1.values}")
    print(f"Encoded array 2: {plain2.values}")
    
    print("\n=== Step 3: Encryption and Decryption ===")
    encryptor = Encryptor(context, pk)
    decryptor = Decryptor(context, sk)
    
    cipher1 = encryptor.encrypt(plain1)
    cipher2 = encryptor.encrypt(plain2)
    print(f"Encrypted cipher1. Depth: {cipher1.depth}, Size: {cipher1.size}")
    
    print("\n=== Step 4: Evaluation and Relinearization ===")
    evaluator = Evaluator(context)
    
    # Addition
    cipher_add = evaluator.add(cipher1, cipher2)
    print(f"After addition -> Depth: {cipher_add.depth}, Size: {cipher_add.size}")
    
    # Multiplication
    cipher_mul = evaluator.multiply(cipher1, cipher2)
    print(f"After multiplication -> Depth: {cipher_mul.depth}, Size: {cipher_mul.size}")
    
    # Relinearization
    cipher_relin = evaluator.relinearize(cipher_mul, relin_keys)
    print(f"After relinearization -> Depth: {cipher_relin.depth}, Size: {cipher_relin.size}")
    
    # Decrypt and Decode
    plain_result = decryptor.decrypt(cipher_relin)
    result = encoder.decode(plain_result)
    print(f"Decrypted and decoded result: {result}")
    
    print("\n=== Step 5: Exhausting the Noise Budget ===")
    try:
        c = cipher_relin
        for i in range(10): # 8192 allows depth 8
            c = evaluator.multiply(c, c)
            c = evaluator.relinearize(c, relin_keys)
            print(f"Multiplication {i+2} succeeded. Depth: {c.depth}")
    except RuntimeError as e:
        print(f"Failed! Error: {e}")

if __name__ == "__main__":
    main()
