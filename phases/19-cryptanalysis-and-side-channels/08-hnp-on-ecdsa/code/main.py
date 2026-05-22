"""
Hidden Number Problem (HNP) idea for ECDSA nonce leakage (educational, brute-force).

Run:
  python3 code/main.py

This lesson simulates ECDSA-like signatures modulo a small prime q. If the
signer leaks a few most-significant bits of each nonce k, an attacker can
recover the secret key x by checking which x makes the implied k values match
the leaked prefixes. Real HNP attacks use lattices; this demo brute forces x.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple


def egcd(a: int, b: int) -> Tuple[int, int, int]:
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def inv_mod(a: int, n: int) -> int:
    a %= n
    g, x, _ = egcd(a, n)
    if g != 1:
        raise ValueError("not invertible")
    return x % n


@dataclass(frozen=True)
class ToySig:
    r: int
    s: int
    h: int
    k_prefix: int


def toy_ecdsa_sign(h: int, x: int, k: int, q: int) -> Tuple[int, int]:
    r = k % q
    s = (inv_mod(k, q) * (h + x * r)) % q
    return r, s


def msb_prefix(value: int, q: int, leak_bits: int) -> int:
    total_bits = q.bit_length()
    keep = total_bits - leak_bits
    if keep <= 0:
        raise ValueError("leak_bits too large")
    return value >> leak_bits


def recover_secret_key_from_leaked_nonce_prefixes(sigs: List[ToySig], q: int, leak_bits: int) -> int:
    for x in range(q):
        ok = True
        for sig in sigs:
            k = (inv_mod(sig.s, q) * (sig.h + x * sig.r)) % q
            if (k >> leak_bits) != sig.k_prefix:
                ok = False
                break
        if ok:
            return x
    raise RuntimeError("no key found")


def main():
    q = 65537
    x = 4242
    leak_bits = 8

    print("=== Step 1: ECDSA-like equation modulo q ===")
    h = 12345
    k = 40000
    r, s = toy_ecdsa_sign(h, x, k, q)
    print("r:", r, "s:", s)

    print("=== Step 2: Simulate leaked nonce MSB prefixes ===")
    sigs: List[ToySig] = []
    for i, k_i in enumerate([40000, 41000, 42000, 43000]):
        h_i = 1000 + i
        r_i, s_i = toy_ecdsa_sign(h_i, x, k_i, q)
        pref = k_i >> leak_bits
        sigs.append(ToySig(r=r_i, s=s_i, h=h_i, k_prefix=pref))
    print("num_sigs:", len(sigs))
    print("example_prefix:", sigs[0].k_prefix)

    print("=== Step 3: Recover the secret key by brute forcing x (toy HNP) ===")
    recovered = recover_secret_key_from_leaked_nonce_prefixes(sigs, q, leak_bits)
    print("recovered_x:", recovered)


if __name__ == "__main__":
    main()
