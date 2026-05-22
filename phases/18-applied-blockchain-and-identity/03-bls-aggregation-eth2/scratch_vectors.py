import hashlib

Q = 1000003

def hash_to_g1(message: bytes):
    return int(hashlib.sha256(message).hexdigest(), 16) % Q

def keygen(sk: int):
    return sk % Q

def sign(sk: int, message: bytes):
    return (hash_to_g1(message) * sk) % Q

print(f"hash('hello'): {hash_to_g1(b'hello')}")
print(f"hash('world'): {hash_to_g1(b'world')}")
print(f"keygen(100): {keygen(100)}")
print(f"sign(100, 'hello'): {sign(100, b'hello')}")
print(f"sign(200, 'world'): {sign(200, b'world')}")
print(f"agg_sig(100 'hello' + 200 'world'): {(sign(100, b'hello') + sign(200, b'world')) % Q}")

