# OpenFHE & SEAL Tour
> Writing FHE apps is mostly tracking parameter degrees and relinearizing ciphertexts.

**Type:** Learn | Build
**Languages:** Python
**Prerequisites:** 17-02 BGV / BFV, 17-03 CKKS
**Time:** ~60 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Initialize** an FHE context and choose secure polynomial degrees.
- **Explain** batch encoding for evaluating over arrays (SIMD operations).
- **Distinguish** between standard keys, relinearization keys, and Galois keys.
- **Compute** arithmetic circuits while managing noise budgets and ciphertext sizes.
- **Apply** relinearization to avoid explosive ciphertext growth during multiplication.

## The Problem
If you try to use BFV or CKKS from scratch, you quickly realize how much boilerplate engineering goes into it. Real FHE protocols involve choosing polynomial moduli, scaling factors, evaluating "SIMD" arrays in parallel, relinearizing ciphertexts so they don't grow infinitely after multiplications, and managing noise.

Without a mature library like Microsoft SEAL or OpenFHE, building applications on top of FHE is nearly impossible. Developers need abstractions to handle the underlying lattice mechanics so they can focus on circuit logic. But even with these libraries, developers face a brutal reality: multiplications increase noise, and if you exhaust the noise budget, your ciphertext decrypts to garbage (or fails to evaluate).

## The Concept
Modern FHE libraries follow a standard lifecycle:
1. **Parameters & Context:** You specify your scheme (BFV, CKKS) and the `poly_modulus_degree` (e.g., 4096, 8192). Larger degree = more security and deeper multiplications, but slower.
2. **Key Generation:** You generate a Public Key, Secret Key, and *Evaluation Keys* (Relinearization keys to shrink multiplied ciphertexts, Galois keys for rotating arrays).
3. **Encoding:** Instead of encrypting numbers one-by-one, you "Batch Encode" arrays of data into a single Plaintext object using Chinese Remainder Theorem (CRT) tricks.
4. **Encrypt & Evaluate:** You run `Add` and `Multiply`. Multiply grows the ciphertext from 2 polynomials to 3, requiring `Relinearize` to bring it back to 2.
5. **Decrypt & Decode:** You convert back to your native arrays.

## Build It
We will build a mocked version of the Microsoft SEAL / OpenFHE API to see exactly how developers interact with it and how it enforces the strict rules of Fully Homomorphic Encryption.

### Step 1: Setting up the Context
```python
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
```
You define parameters first. The context enforces constraints—here, the multiplication depth is bounded by your chosen degree.

### Step 2: Keys and Batch Encoding
```python
class Plaintext:
    def __init__(self, values: list):
        self.values = values

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
```
Batch encoding lets you pack thousands of values into a single ciphertext, enabling SIMD (Single Instruction, Multiple Data).

### Step 3: Encryption and Decryption
```python
class Ciphertext:
    def __init__(self, values: list, depth: int = 0):
        self.values = values
        self.depth = depth
        self.size = 2 # Initial ciphertext has 2 polynomials

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
```
Standard asymmetric encryption wrappers.

### Step 4: Evaluation and Relinearization
```python
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
```
This is the core of FHE programming. Multiplications increase the noise (depth) and the memory size of the ciphertext (size grows from 2 to 3 polynomials). `relinearize` shrinks it back to 2 polynomials.

### Step 5: Exhausting the Noise Budget
```python
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
```

Run it:
```bash
python3 code/main.py
```

## Use It

| Library | Characteristics |
|---------|-----------------|
| **Microsoft SEAL** | C++ with .NET wrapper. Excellent, readable codebase. Great for BFV, BGV, CKKS. Easy to start with. |
| **OpenFHE** | C++ and Python wrapper. Comprehensive. Contains BGV, BFV, CKKS, TFHE (FHEW). Standard for new research. |
| **Concrete (Zama)** | Rust/Python. Specialized entirely for TFHE and fast bootstrapping of booleans/integers. |
| **TenSEAL** | Python wrapper over SEAL. Great for simple FHE machine learning tasks. |

## Pitfalls

1. **Forgetting to Relinearize:** Multiplying two ciphertexts of size 2 yields size 3. Multiplying size 3 by size 3 yields size 5. Without relinearization, your evaluation will quickly grind to a halt in memory and compute.
2. **Ignoring the Noise Budget:** Running too many multiplications without sufficient `poly_modulus_degree`. In SEAL, `Evaluator::multiply` does not crash; instead, `Decryptor::decrypt` will silently give you corrupted plaintext values!
3. **Sequential over Parallel:** FHE multiplication is incredibly slow. Instead of `a * b * c * d`, compute `(a * b) * (c * d)` to keep the multiplication depth to 2 instead of 3.
4. **Single Value Encryption:** Encrypting one integer per ciphertext is a huge waste. Batching allows thousands of values to be evaluated simultaneously at no extra cost.

## Ship It

We have saved an **FHE Architecture Cheatsheet** in `outputs/fhe_cheatsheet.md`.
It lists the key objects, parameters, and common failure modes when building with Microsoft SEAL or OpenFHE. Keep it open when debugging your first real FHE application to remind yourself what a Galois Key is and why you suddenly ran out of noise budget.

## Exercises

1. Easy. Run `code/main.py`. Observe how the program simulates throwing an error when the multiplication depth exceeds the parameter limit.
2. Medium. Modify `main.py`'s Step 1 to set `poly_modulus_degree` to `16384` (which should allow depth 16) and observe how the loop in Step 5 succeeds without exhausting the noise budget.
3. Hard. Extend `Evaluator` to include `rotate_rows(cipher, step, galois_keys)`. In real FHE, batch encoded arrays are matrices (usually 2 rows). Galois keys allow rotating these arrays cryptographically to compute dot products or convolutions.

## Key Terms

| Term | What people say | What it actually means |
|------|-----------------|------------------------|
| **poly_modulus_degree** | "The degree" | The size of the polynomials. Directly dictates how many multiplications you can do and how many items you can batch. Must be a power of 2. |
| **Relinearization** | "Relin" | Mathematical procedure using a RelinKey to reduce a ciphertext back to its canonical size of 2 polynomials after multiplication. |
| **Batch Encoding** | "SIMD slots" | Packing an array of values into the coefficients of a single plaintext polynomial using CRT. |
| **Noise Budget** | "The budget" | The amount of room left before the error term in LWE grows too large and corrupts the message. |

## Further Reading
- OpenFHE Team, "OpenFHE Documentation" (2022) — Official documentation and design principles behind OpenFHE.
- Microsoft, "Microsoft SEAL Manual" — A must-read PDF that ships with SEAL, arguably the best introduction to FHE programming in existence.
