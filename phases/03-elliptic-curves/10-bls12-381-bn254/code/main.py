from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

import py_ecc.optimized_bn128 as bn254
import py_ecc.optimized_bls12_381 as bls12_381
from py_ecc.bls import hash_to_curve


def _fq_to_int(x: Any) -> int:
    if hasattr(x, "n"):
        return int(x.n)
    return int(x)


def fq_to_json(x: Any) -> Any:
    if hasattr(x, "coeffs"):
        return [fq_to_json(c) for c in x.coeffs]
    if isinstance(x, (tuple, list)):
        return [fq_to_json(v) for v in x]
    return _fq_to_int(x)


def point_to_json(curve: Any, point: Any, *, group: str) -> list[Any]:
    x, y = curve.normalize(point)
    if group == "g1":
        return [fq_to_json(x), fq_to_json(y)]
    if group == "g2":
        return [fq_to_json(x), fq_to_json(y)]
    raise ValueError("unknown group")


def is_infinity(curve: Any, point: Any, *, group: str) -> bool:
    if group == "g1":
        return curve.normalize(point) == curve.normalize(curve.Z1)
    if group == "g2":
        return curve.normalize(point) == curve.normalize(curve.Z2)
    raise ValueError("unknown group")


def is_in_subgroup(curve: Any, point: Any, *, group: str) -> bool:
    if group == "g1":
        return is_infinity(curve, curve.multiply(point, curve.curve_order), group="g1")
    if group == "g2":
        return is_infinity(curve, curve.multiply(point, curve.curve_order), group="g2")
    raise ValueError("unknown group")


@dataclass(frozen=True)
class CurveProfile:
    name: str
    field_modulus: int
    curve_order: int
    embedding_degree: int

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "field_modulus": self.field_modulus,
            "curve_order": self.curve_order,
            "field_bits": self.field_modulus.bit_length(),
            "order_bits": self.curve_order.bit_length(),
            "embedding_degree": self.embedding_degree,
        }


def curve_profile(name: str) -> CurveProfile:
    if name == "bn254":
        return CurveProfile(
            name="BN254",
            field_modulus=bn254.field_modulus,
            curve_order=bn254.curve_order,
            embedding_degree=12,
        )
    if name == "bls12_381":
        return CurveProfile(
            name="BLS12-381",
            field_modulus=bls12_381.field_modulus,
            curve_order=bls12_381.curve_order,
            embedding_degree=12,
        )
    raise ValueError("unknown curve")


def pairing_generator(curve: Any) -> Any:
    return curve.final_exponentiate(curve.pairing(curve.G2, curve.G1))


def pairing_generator_json(name: str) -> Any:
    if name == "bn254":
        return fq_to_json(pairing_generator(bn254))
    if name == "bls12_381":
        return fq_to_json(pairing_generator(bls12_381))
    raise ValueError("unknown curve")


def bilinearity_check(name: str, a: int, b: int) -> bool:
    if name == "bn254":
        curve = bn254
    elif name == "bls12_381":
        curve = bls12_381
    else:
        raise ValueError("unknown curve")

    base = pairing_generator(curve)
    left = curve.final_exponentiate(curve.pairing(curve.multiply(curve.G2, b), curve.multiply(curve.G1, a)))
    right = base ** (a * b)
    return left == right


def bls_map_to_curve_g1_demo(message: bytes, dst: bytes) -> dict[str, bool]:
    u = hash_to_curve.hash_to_field_FQ(message, 2, dst, hashlib.sha256)[0]
    p = hash_to_curve.map_to_curve_G1(u)
    return {
        "on_curve": bls12_381.is_on_curve(p, bls12_381.b),
        "in_subgroup": is_in_subgroup(bls12_381, p, group="g1"),
        "in_subgroup_after_clear": is_in_subgroup(bls12_381, hash_to_curve.clear_cofactor_G1(p), group="g1"),
    }


def bls_verify_naive(pk_g1: Any, message: bytes, sig_g2: Any) -> bool:
    h = hash_to_curve.hash_to_G2(
        message,
        b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_",
        hashlib.sha256,
    )
    left = bls12_381.final_exponentiate(bls12_381.pairing(sig_g2, bls12_381.G1))
    right = bls12_381.final_exponentiate(bls12_381.pairing(h, pk_g1))
    return left == right


def bls_verify_strict(pk_g1: Any, message: bytes, sig_g2: Any) -> bool:
    if is_infinity(bls12_381, pk_g1, group="g1") or is_infinity(bls12_381, sig_g2, group="g2"):
        return False
    if not is_in_subgroup(bls12_381, pk_g1, group="g1"):
        return False
    if not is_in_subgroup(bls12_381, sig_g2, group="g2"):
        return False
    return bls_verify_naive(pk_g1, message, sig_g2)


def bls_subgroup_forgery_demo(message: bytes, pk_seed: bytes) -> dict[str, bool]:
    u = hash_to_curve.hash_to_field_FQ(pk_seed, 2, b"DST", hashlib.sha256)[0]
    pk_bad = bls12_381.multiply(hash_to_curve.map_to_curve_G1(u), bls12_381.curve_order)
    sig_bad = bls12_381.Z2
    return {
        "pk_bad_in_subgroup": is_in_subgroup(bls12_381, pk_bad, group="g1"),
        "naive_accepts": bls_verify_naive(pk_bad, message, sig_bad),
        "strict_accepts": bls_verify_strict(pk_bad, message, sig_bad),
    }


def main() -> None:
    print("pairing-friendly curves quick demo (educational)")
    for key in ["bn254", "bls12_381"]:
        profile = curve_profile(key).to_json()
        print()
        print(profile["name"])
        print("- base field bits:", profile["field_bits"])
        print("- scalar field bits:", profile["order_bits"])
        print("- embedding degree:", profile["embedding_degree"])
        print("- bilinearity check:", bilinearity_check(key, a=123, b=456))

    demo = bls_map_to_curve_g1_demo(b"hello", b"DST")
    print()
    print("BLS12-381 G1 map_to_curve demo")
    print("- on curve:", demo["on_curve"])
    print("- in subgroup (before clear):", demo["in_subgroup"])
    print("- in subgroup (after clear):", demo["in_subgroup_after_clear"])

    attack = bls_subgroup_forgery_demo(b"message", b"pk-seed")
    print()
    print("BLS12-381 subgroup-check forgery demo")
    print("- pk_bad in subgroup:", attack["pk_bad_in_subgroup"])
    print("- naive verifier accepts:", attack["naive_accepts"])
    print("- strict verifier accepts:", attack["strict_accepts"])


if __name__ == "__main__":
    main()
