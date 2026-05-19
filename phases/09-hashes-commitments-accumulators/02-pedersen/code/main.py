"""
Pedersen commitments over a prime-order subgroup of Z_p* (toy parameters).

Run:
  python3 code/main.py

This is an educational implementation to make the algebra concrete.
It is not constant-time and not production-safe.
"""

from dataclasses import dataclass
from secrets import randbelow


@dataclass(frozen=True)
class PedersenParams:
    p: int
    q: int
    g: int
    h: int


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


def check_pedersen_params(params):
    p, q, g, h = params.p, params.q, params.g, params.h
    if p <= 2 or q <= 1:
        raise ValueError("p and q must be > 2")
    if (p - 1) % q != 0:
        raise ValueError("q must divide p-1")
    if not (1 < g < p) or not (1 < h < p):
        raise ValueError("g and h must be in [2, p-2]")
    if pow(g, q, p) != 1 or pow(h, q, p) != 1:
        raise ValueError("g and h must have order dividing q")
    if g == 1 or h == 1:
        raise ValueError("g and h must not be 1")
    if g == h:
        raise ValueError("g and h must be distinct")


def pedersen_commit(params, m, r):
    check_pedersen_params(params)
    q = params.q
    if not (0 <= m < q):
        raise ValueError("message m must be in Z_q")
    if not (0 <= r < q):
        raise ValueError("blinding r must be in Z_q")
    return (pow(params.g, m, params.p) * pow(params.h, r, params.p)) % params.p


def pedersen_verify(params, c, m, r):
    return pedersen_commit(params, m, r) == c


def pedersen_combine(params, c1, c2):
    check_pedersen_params(params)
    return (c1 * c2) % params.p


def pedersen_add_openings(params, opening1, opening2):
    check_pedersen_params(params)
    m1, r1 = opening1
    m2, r2 = opening2
    q = params.q
    if not (0 <= m1 < q and 0 <= r1 < q and 0 <= m2 < q and 0 <= r2 < q):
        raise ValueError("openings must be pairs in Z_q × Z_q")
    return ((m1 + m2) % q, (r1 + r2) % q)


def pedersen_rerandomize(params, c, delta_r):
    check_pedersen_params(params)
    q = params.q
    if not (0 <= delta_r < q):
        raise ValueError("delta_r must be in Z_q")
    return (c * pow(params.h, delta_r, params.p)) % params.p


def extract_log_g_h_from_double_opening(q, m1, r1, m2, r2):
    if m1 == m2:
        raise ValueError("need two different messages to extract log_g(h)")
    den = (r2 - r1) % q
    if den == 0:
        raise ValueError("need r2 != r1 to extract log_g(h)")
    return ((m1 - m2) % q) * mod_inverse(den, q) % q


def forge_opening_if_trapdoor_known(params, m_from, r_from, m_target, alpha):
    q = params.q
    if not (0 <= m_from < q and 0 <= r_from < q and 0 <= m_target < q):
        raise ValueError("messages and randomness must be in Z_q")
    if not (1 <= alpha < q):
        raise ValueError("alpha must be in [1, q-1]")
    return (r_from + ((m_from - m_target) % q) * mod_inverse(alpha, q)) % q


def toy_params():
    p = 23
    q = 11
    g = 4
    alpha = 7
    h = pow(g, alpha, p)
    return PedersenParams(p=p, q=q, g=g, h=h), alpha


def subgroup_elements(params):
    return [pow(params.g, i, params.p) for i in range(params.q)]


def main():
    params, alpha = toy_params()

    print("=== Step 1: Parameters and modular inverse ===")
    print(f"p={params.p} q={params.q} g={params.g} h={params.h}")
    check_pedersen_params(params)
    print("subgroup <g>:", subgroup_elements(params))

    print("\n=== Step 2: Commit and verify ===")
    m, r = 3, 5
    c = pedersen_commit(params, m, r)
    print(f"commit(m={m}, r={r}) = {c}")
    print("verify(opening) =", pedersen_verify(params, c, m, r))
    print("verify(wrong m) =", pedersen_verify(params, c, (m + 1) % params.q, r))

    r2 = 1
    c2 = pedersen_commit(params, m, r2)
    print(f"same m, different r: commit(m={m}, r={r2}) = {c2}")

    print("\n=== Step 3: Combine and add openings ===")
    m1, r1 = 2, 7
    m2, r2 = 6, 4
    c1 = pedersen_commit(params, m1, r1)
    c2 = pedersen_commit(params, m2, r2)
    combined = pedersen_combine(params, c1, c2)
    m_sum, r_sum = pedersen_add_openings(params, (m1, r1), (m2, r2))
    direct = pedersen_commit(params, m_sum, r_sum)
    print(f"c1={c1} (m1={m1}, r1={r1})")
    print(f"c2={c2} (m2={m2}, r2={r2})")
    print("c1*c2 mod p =", combined)
    print("commit(m1+m2, r1+r2) =", direct)
    print("combine matches direct =", combined == direct)

    print("\n=== Step 4: Rerandomize and trapdoors ===")
    delta = 8
    c_rr = pedersen_rerandomize(params, c, delta)
    print(f"rerandomize(commit(m={m}, r={r}), delta_r={delta}) = {c_rr}")
    print("verify with updated r =", pedersen_verify(params, c_rr, m, (r + delta) % params.q))

    m_target = 9
    r_target = forge_opening_if_trapdoor_known(params, m, r, m_target, alpha)
    print(f"if alpha=log_g(h) is known (alpha={alpha}), you can open to any m'")
    print(f"forged opening: (m'={m_target}, r'={r_target}) verifies =",
          pedersen_verify(params, c, m_target, r_target))

    alpha_extracted = extract_log_g_h_from_double_opening(params.q, m, r, m_target, r_target)
    print("double-opening lets you extract alpha =", alpha_extracted)
    print("extracted alpha equals actual alpha =", alpha_extracted == alpha)


if __name__ == "__main__":
    main()
