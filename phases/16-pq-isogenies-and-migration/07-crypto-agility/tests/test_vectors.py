import json
import os
import sys
from datetime import date

import pytest


HERE = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(HERE, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main  # noqa: E402


def _parse_date(s: str) -> date:
    y, m, d = s.split("-")
    return date(int(y), int(m), int(d))


def _algorithm_from_json(d: dict) -> main.Algorithm:
    not_after = _parse_date(d["not_after"]) if d.get("not_after") is not None else None
    return main.Algorithm(
        alg_id=d["alg_id"],
        family=d["family"],
        security_level=int(d["security_level"]),
        pq=bool(d["pq"]),
        min_protocol_version=int(d.get("min_protocol_version", 1)),
        not_after=not_after,
        notes=str(d.get("notes", "")),
    )


def _policy_from_json(d: dict) -> main.CryptoPolicy:
    allowed = d.get("allowed_algs")
    denied = d.get("denied_algs", [])
    return main.CryptoPolicy(
        protocol_version=int(d["protocol_version"]),
        now=_parse_date(d["now"]),
        min_security_level=int(d.get("min_security_level", 1)),
        require_pq=bool(d.get("require_pq", False)),
        allow_classical_fallback=bool(d.get("allow_classical_fallback", True)),
        allowed_algs=frozenset(allowed) if allowed is not None else None,
        denied_algs=frozenset(denied),
    )


def _suite_from_json(d: dict) -> main.CryptoSuite:
    return main.CryptoSuite(sig_alg=d["sig_alg"], kem_alg=d["kem_alg"])


def _load_vectors() -> dict:
    path = os.path.join(HERE, "vectors.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def test_vectors() -> None:
    data = _load_vectors()
    vectors = data["vectors"]

    for i, v in enumerate(vectors):
        op = v["op"]
        if op == "canonicalize_alg_id":
            got = main.canonicalize_alg_id(v["input"])
            assert got == v["expected"], f"vector {i} failed op={op}"
            continue

        if op == "filter_algorithms":
            algorithms = [_algorithm_from_json(a) for a in v["algorithms"]]
            policy = _policy_from_json(v["policy"])
            got_algs = main.filter_algorithms(algorithms, policy, family=v.get("family"))
            got = [a.alg_id for a in got_algs]
            assert got == v["expected"], f"vector {i} failed op={op}"
            continue

        if op == "pick_algorithm":
            algorithms = [_algorithm_from_json(a) for a in v["algorithms"]]
            policy = _policy_from_json(v["policy"])
            got = main.pick_algorithm(algorithms, policy, family=v["family"]).alg_id
            assert got == v["expected"], f"vector {i} failed op={op}"
            continue

        if op == "negotiate_suite":
            algorithms = [_algorithm_from_json(a) for a in v["algorithms"]]
            policy = _policy_from_json(v["policy"])
            client_suites = [_suite_from_json(s) for s in v["client_suites"]]
            server_suites = [_suite_from_json(s) for s in v["server_suites"]]
            got = main.negotiate_suite(client_suites, server_suites, algorithms, policy).suite_id()
            assert got == v["expected"], f"vector {i} failed op={op}"
            continue

        if op == "scan_config_for_deprecated_algorithms":
            algorithms = [_algorithm_from_json(a) for a in v["algorithms"]]
            on = _parse_date(v["on"])
            findings = main.scan_config_for_deprecated_algorithms(v["config"], algorithms, on=on)
            got = [
                {"alg_id": f.alg_id, "reason": f.reason, "action": f.action}
                for f in findings
            ]
            assert got == v["expected"], f"vector {i} failed op={op}"
            continue

        raise AssertionError(f"unknown op in vector {i}: {op}")


def test_canonicalize_idempotent() -> None:
    samples = [
        " ML-KEM_768 ",
        "Ed25519",
        "RSA 2048",
        "sike_p434",
        "  ---ml---kem---768---  ",
    ]
    for s in samples:
        once = main.canonicalize_alg_id(s)
        twice = main.canonicalize_alg_id(once)
        assert once == twice
        assert once == once.lower()


def test_policy_denied_always_removed() -> None:
    algs = [
        main.Algorithm("ml-dsa-65", family="sig", security_level=3, pq=True, min_protocol_version=2),
        main.Algorithm("ml-dsa-44", family="sig", security_level=2, pq=True, min_protocol_version=2),
    ]
    policy = main.CryptoPolicy(
        protocol_version=2,
        now=date(2026, 5, 21),
        min_security_level=1,
        require_pq=True,
        allow_classical_fallback=False,
        denied_algs=frozenset({"ml-dsa-65"}),
    )
    got = [a.alg_id for a in main.filter_algorithms(algs, policy, family="sig")]
    assert got == ["ml-dsa-44"]


def test_negotiation_rejects_disallowed_suite() -> None:
    algs = [
        main.Algorithm("ed25519", family="sig", security_level=1, pq=False),
        main.Algorithm("ml-dsa-44", family="sig", security_level=2, pq=True, min_protocol_version=2),
        main.Algorithm("x25519", family="kem", security_level=1, pq=False),
        main.Algorithm("ml-kem-768", family="kem", security_level=3, pq=True, min_protocol_version=2),
    ]
    policy = main.CryptoPolicy(
        protocol_version=2,
        now=date(2026, 5, 21),
        min_security_level=2,
        require_pq=True,
        allow_classical_fallback=False,
    )
    client = [main.CryptoSuite("ed25519", "x25519"), main.CryptoSuite("ml-dsa-44", "ml-kem-768")]
    server = [main.CryptoSuite("ed25519", "x25519"), main.CryptoSuite("ml-dsa-44", "ml-kem-768")]
    got = main.negotiate_suite(client, server, algs, policy)
    assert got.suite_id() == "sig=ml-dsa-44;kem=ml-kem-768"


def test_negotiation_fails_cleanly_when_no_suite() -> None:
    algs = [
        main.Algorithm("ed25519", family="sig", security_level=1, pq=False),
        main.Algorithm("x25519", family="kem", security_level=1, pq=False),
    ]
    policy = main.CryptoPolicy(
        protocol_version=1,
        now=date(2026, 5, 21),
        min_security_level=2,
        require_pq=True,
        allow_classical_fallback=False,
    )
    client = [main.CryptoSuite("ed25519", "x25519")]
    server = [main.CryptoSuite("ed25519", "x25519")]
    with pytest.raises(main.NegotiationError):
        main.negotiate_suite(client, server, algs, policy)


if __name__ == "__main__":
    try:
        test_vectors()
        test_canonicalize_idempotent()
        test_policy_denied_always_removed()
        test_negotiation_rejects_disallowed_suite()
        test_negotiation_fails_cleanly_when_no_suite()
    except Exception:
        raise
    else:
        print("all tests pass")
