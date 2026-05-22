import json
import hashlib
from sympy import nextprime

def hash_to_prime(g, y, N):
    seed = f"{g}:{y}:{N}".encode()
    h = int(hashlib.sha256(seed).hexdigest(), 16)
    return nextprime(h % (2**128))

def vdf_eval(g, T, N):
    y = g
    for _ in range(T):
        y = (y * y) % N
    return y

def vdf_prove(g, y, T, N):
    l = hash_to_prime(g, y, N)
    q = (1 << T) // l
    return pow(g, q, N)

N = 25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357
g = 2

vectors = []
for T in [10, 100, 1000, 10000]:
    y = vdf_eval(g, T, N)
    l = hash_to_prime(g, y, N)
    pi = vdf_prove(g, y, T, N)
    vectors.append({
        "op": "wesolowski_vdf",
        "inputs": {
            "g": g,
            "T": T,
            "N": N
        },
        "expected": {
            "y": y,
            "l": l,
            "pi": pi
        }
    })

data = {
    "source": "Custom Wesolowski VDF implementation over RSA-2048 using SHA-256 for Fiat-Shamir prime derivation",
    "vectors": vectors
}

with open("scratch/vdf_vectors.json", "w") as f:
    json.dump(data, f, indent=2)

print("Generated vectors")
