import json
import pathlib
import sys


HERE = pathlib.Path(__file__).resolve()
LESSON_DIR = HERE.parents[1]
sys.path.insert(0, str(LESSON_DIR / "code"))

import main as lesson  # noqa: E402


def _load_vectors():
    path = HERE.parent / "vectors.json"
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _apply_smt_updates(tree, updates):
    for item in updates:
        key = item["key"].encode("utf-8")
        value = item["value"].encode("utf-8") if item.get("value") is not None else None
        tree.update(key, value)


def test_vectors():
    data = _load_vectors()
    assert isinstance(data.get("vectors"), list)

    for vec in data["vectors"]:
        op = vec["op"]
        inputs = vec["inputs"]
        expected = vec["expected"]

        if op == "smt_root":
            smt = lesson.SparseMerkleTree(inputs["bit_length"])
            _apply_smt_updates(smt, inputs["updates"])
            assert smt.root().hex() == expected["root_hex"]
            assert smt.non_default_node_count() == expected["non_default_nodes"]

        elif op == "smt_proof":
            smt = lesson.SparseMerkleTree(inputs["bit_length"])
            _apply_smt_updates(smt, inputs["updates"])
            key = inputs["key"].encode("utf-8")
            value = inputs["value"].encode("utf-8")
            proof = smt.prove(key)
            assert proof.leaf_index == expected["leaf_index"]
            assert [s.hex() for s in proof.siblings] == expected["siblings_hex"]
            assert lesson.smt_verify(smt.root(), key, value, proof)
            assert not lesson.smt_verify(smt.root(), key, value + b"!", proof)

        elif op == "smt_non_inclusion_proof":
            smt = lesson.SparseMerkleTree(inputs["bit_length"])
            _apply_smt_updates(smt, inputs["updates"])
            key = inputs["key"].encode("utf-8")
            proof = smt.prove(key)
            assert proof.leaf_index == expected["leaf_index"]
            assert [s.hex() for s in proof.siblings] == expected["siblings_hex"]
            assert lesson.smt_verify(smt.root(), key, None, proof)

        elif op == "vc_open":
            params = lesson.rsa_params_for_demo()
            assert hex(params.n) == expected["n"]
            assert params.g == expected["g"]

            values = [bytes.fromhex(x) for x in inputs["values"]]
            commitment = lesson.vc_commit(params, values)
            assert hex(commitment) == expected["commitment"]

            opened, witness = lesson.vc_open(params, values, inputs["index"])
            assert opened.hex() == expected["opened"]
            assert hex(witness) == expected["witness"]
            assert lesson.vc_verify(params, commitment, inputs["index"], opened, witness) is expected["verifies"]
            assert not lesson.vc_verify(params, commitment, inputs["index"], opened + b"!", witness)

        elif op == "toy_verkle_proof":
            params = lesson.rsa_params_for_demo()
            assert hex(params.n) == expected["n"]
            assert params.g == expected["g"]

            tree = lesson.ToyVerkleTree(width=inputs["width"], depth=inputs["depth"], params=params)
            assert hex(tree.root_commitment()) == expected["empty_root"]

            key = inputs["key"].encode("utf-8")
            value = inputs["value"].encode("utf-8")
            tree.update(key, value)
            assert hex(tree.root_commitment()) == expected["root"]

            proof = tree.prove(key)
            assert list(proof.indices) == expected["indices"]
            assert [v.hex() for v in proof.values] == expected["values_hex"]
            assert [hex(w) for w in proof.witnesses] == expected["witnesses_hex"]
            assert lesson.toy_verkle_verify(params, tree.root_commitment(), key, value, proof) is expected["verifies"]

            bad_indices = (proof.indices[0] ^ 1,) + proof.indices[1:]
            bad_proof = lesson.ToyVerkleProof(
                width=proof.width,
                depth=proof.depth,
                indices=bad_indices,
                values=proof.values,
                witnesses=proof.witnesses,
            )
            assert not lesson.toy_verkle_verify(params, tree.root_commitment(), key, value, bad_proof)

        else:
            raise AssertionError(f"unknown op: {op}")


def test_properties():
    smt = lesson.SparseMerkleTree(16)
    empty = smt.root()

    smt.update(b"a", b"1")
    root_after_insert = smt.root()
    assert root_after_insert != empty

    smt.update(b"a", None)
    assert smt.root() == empty

    params = lesson.rsa_params_for_demo()
    values = [b"A", b"B", b"C", b"D"]
    commitment = lesson.vc_commit(params, values)
    opened, witness = lesson.vc_open(params, values, 1)
    assert lesson.vc_verify(params, commitment, 1, opened, witness)
    assert not lesson.vc_verify(params, commitment, 1, opened, (witness + 1) % params.n)


if __name__ == "__main__":
    test_vectors()
    test_properties()
    print("all tests pass")

