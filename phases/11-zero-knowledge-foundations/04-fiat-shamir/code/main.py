"""
Fiat–Shamir heuristic for making Schnorr proofs non-interactive (toy parameters).

Run:
  python3 code/main.py

This is an educational implementation to make the transcript hashing concrete.
It is not constant-time and not production-safe.
"""

from dataclasses import dataclass
import hashlib
from secrets import randbelow


@dataclass(frozen=True)
class SchnorrParams:
    p: int
    q: int
    g: int


def egcd(a, b):
    x0, y0, x1, y1 = 1, 0, 0, 1
    while b != 0:
        q = a // b
        a, b = b, a - q * b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def mod_inverse(a, n):
    if n <= 0:
        raise ValueError("modulus must be positive")
    a = a % n
    g, x, _ = egcd(a, n)
    if g != 1:
        raise ValueError("not invertible modulo n")
    return x % n


def check_schnorr_params(params):
    p, q, g = params.p, params.q, params.g
    if p <= 2 or q <= 1:
        raise ValueError("p and q must be > 2")
    if (p - 1) % q != 0:
        raise ValueError("q must divide p-1")
    if not (1 < g < p):
        raise ValueError("g must be in [2, p-2]")
    if pow(g, q, p) != 1:
        raise ValueError("g must have order dividing q")
    if g == 1:
        raise ValueError("g must not be 1")


def toy_params():
    return SchnorrParams(p=23, q=11, g=2)


def toy_keypair(params, x):
    check_schnorr_params(params)
    q = params.q
    if not (0 <= x < q):
        raise ValueError("secret x must be in Z_q")
    y = pow(params.g, x, params.p)
    return x, y


def schnorr_commit(params, r):
    check_schnorr_params(params)
    q = params.q
    if not (0 <= r < q):
        raise ValueError("nonce r must be in Z_q")
    return pow(params.g, r, params.p)


def schnorr_response(params, r, c, x):
    check_schnorr_params(params)
    q = params.q
    if not (0 <= r < q):
        raise ValueError("nonce r must be in Z_q")
    if not (0 <= c < q):
        raise ValueError("challenge c must be in Z_q")
    if not (0 <= x < q):
        raise ValueError("secret x must be in Z_q")
    return (r + c * x) % q


def schnorr_verify(params, y, t, c, s):
    check_schnorr_params(params)
    q, p = params.q, params.p
    if not (0 < y < p):
        raise ValueError("public key y must be in [1, p-1]")
    if not (0 < t < p):
        raise ValueError("commitment t must be in [1, p-1]")
    if pow(y, q, p) != 1:
        raise ValueError("public key y must be in the q-order subgroup")
    if pow(t, q, p) != 1:
        raise ValueError("commitment t must be in the q-order subgroup")
    if not (0 <= c < q):
        raise ValueError("challenge c must be in Z_q")
    if not (0 <= s < q):
        raise ValueError("response s must be in Z_q")
    lhs = pow(params.g, s, p)
    rhs = (t * pow(y, c, p)) % p
    return lhs == rhs


def _int_to_fixed_length_bytes(n, length):
    if n < 0:
        raise ValueError("cannot encode negative integers")
    return int(n).to_bytes(length, "big")


def _encode_transcript(params, y, t, message, domain_sep):
    check_schnorr_params(params)
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("message must be bytes")
    if not isinstance(domain_sep, (bytes, bytearray)):
        raise TypeError("domain_sep must be bytes")
    p_len = (params.p.bit_length() + 7) // 8
    out = bytearray()
    out += domain_sep
    out += _int_to_fixed_length_bytes(params.p, p_len)
    out += _int_to_fixed_length_bytes(params.q, p_len)
    out += _int_to_fixed_length_bytes(params.g, p_len)
    out += _int_to_fixed_length_bytes(y, p_len)
    out += _int_to_fixed_length_bytes(t, p_len)
    out += len(message).to_bytes(4, "big")
    out += message
    return bytes(out)


def hash_to_int(data, q):
    if q <= 1:
        raise ValueError("q must be > 1")
    digest = hashlib.sha256(data).digest()
    return int.from_bytes(digest, "big") % q


def fiat_shamir_challenge(params, y, t, message, domain_sep=b"FS-SCHNORR-v1"):
    transcript = _encode_transcript(params, y, t, message, domain_sep)
    return hash_to_int(transcript, params.q)


def fs_prove(params, x, message, nonce=None, domain_sep=b"FS-SCHNORR-v1"):
    check_schnorr_params(params)
    q = params.q
    if nonce is None:
        nonce = randbelow(q)
    t = schnorr_commit(params, nonce)
    _, y = toy_keypair(params, x)
    c = fiat_shamir_challenge(params, y, t, message, domain_sep=domain_sep)
    s = schnorr_response(params, nonce, c, x)
    return {"t": t, "s": s}


def fs_verify(params, y, message, proof, domain_sep=b"FS-SCHNORR-v1"):
    c = fiat_shamir_challenge(params, y, proof["t"], message, domain_sep=domain_sep)
    return schnorr_verify(params, y, proof["t"], c, proof["s"])


def weak_fiat_shamir_challenge_without_message(params, y, t):
    check_schnorr_params(params)
    p_len = (params.p.bit_length() + 7) // 8
    data = b"WEAK-FS-v1" + _int_to_fixed_length_bytes(y, p_len) + _int_to_fixed_length_bytes(t, p_len)
    return hash_to_int(data, params.q)


def weak_fs_prove_without_message(params, x, nonce=None):
    check_schnorr_params(params)
    q = params.q
    if nonce is None:
        nonce = randbelow(q)
    t = schnorr_commit(params, nonce)
    _, y = toy_keypair(params, x)
    c = weak_fiat_shamir_challenge_without_message(params, y, t)
    s = schnorr_response(params, nonce, c, x)
    return {"t": t, "s": s}


def weak_fs_verify_without_message(params, y, proof):
    c = weak_fiat_shamir_challenge_without_message(params, y, proof["t"])
    return schnorr_verify(params, y, proof["t"], c, proof["s"])


def forge_fs_proof_by_grinding(params, y, message, domain_sep=b"FS-SCHNORR-v1"):
    check_schnorr_params(params)
    q, p = params.q, params.p

    for c_guess in range(q):
        y_to_c = pow(y, c_guess, p)
        inv_y_to_c = mod_inverse(y_to_c, p)
        for s_guess in range(q):
            t = (pow(params.g, s_guess, p) * inv_y_to_c) % p
            c_actual = fiat_shamir_challenge(params, y, t, message, domain_sep=domain_sep)
            if c_actual == c_guess:
                proof = {"t": t, "s": s_guess}
                if fs_verify(params, y, message, proof, domain_sep=domain_sep):
                    return proof
    raise RuntimeError("failed to forge proof (unexpected for toy parameters)")


def _step(n, name):
    print(f"=== Step {n}: {name} ===")


def main():
    params = toy_params()
    x, y = toy_keypair(params, x=7)

    _step(1, "Interactive Schnorr Sigma protocol")
    r = 4
    t = schnorr_commit(params, r)
    c = 3
    s = schnorr_response(params, r, c, x)
    print(f"public key y=g^x mod p = {y}")
    print(f"commitment t=g^r mod p = {t}")
    print(f"verifier challenge c = {c}")
    print(f"response s=r+c*x mod q = {s}")
    print("verify(t, c, s) =", schnorr_verify(params, y, t, c, s))

    _step(2, "Fiat–Shamir challenge from a transcript")
    msg = b"hello"
    c_fs = fiat_shamir_challenge(params, y, t, msg)
    print("message =", msg)
    print("challenge c = H(transcript) mod q =", c_fs)

    _step(3, "Non-interactive proof via Fiat–Shamir")
    proof = fs_prove(params, x, msg, nonce=4)
    print("proof =", proof)
    print("verify(proof) =", fs_verify(params, y, msg, proof))
    print("verify(wrong message) =", fs_verify(params, y, b"bye", proof))

    _step(4, "Two real breaks: weak binding and grinding")
    weak_proof = weak_fs_prove_without_message(params, x, nonce=4)
    print("weak proof (not bound to a message) =", weak_proof)
    print("weak verify (message 1) =", weak_fs_verify_without_message(params, y, weak_proof))
    print("weak verify (message 2) =", weak_fs_verify_without_message(params, y, weak_proof))

    forged = forge_fs_proof_by_grinding(params, y, msg)
    print("forged proof by grinding (no x) =", forged)
    print("verify(forged) =", fs_verify(params, y, msg, forged))


if __name__ == "__main__":
    main()
