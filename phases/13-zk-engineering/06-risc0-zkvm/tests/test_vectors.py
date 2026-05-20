import json
import os
import sys


THIS_DIR = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(THIS_DIR, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as risc0_toy  # noqa: E402


def _load_vectors():
    path = os.path.join(THIS_DIR, "vectors.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _program_from_json(xs):
    return [risc0_toy.Instr(x["op"], x.get("arg")) for x in xs]


def test_vectors():
    data = _load_vectors()
    vectors = data["vectors"]

    for v in vectors:
        op = v["op"]

        if op == "image_id":
            program = _program_from_json(v["program"])
            got = risc0_toy.image_id(program).hex()
            assert got == v["expected"]

        elif op == "run_program_journal":
            program = _program_from_json(v["program"])
            public_inputs = [bytes.fromhex(x) for x in v["public_inputs_hex"]]
            private_inputs = [bytes.fromhex(x) for x in v["private_inputs_hex"]]
            ex = risc0_toy.run_program(program, public_inputs=public_inputs, private_inputs=private_inputs)
            assert ex.halted is True
            got = [x.hex() for x in ex.trace[-1].journal]
            assert got == v["expected_journal_hex"]

        elif op == "prove_execution":
            program = _program_from_json(v["program"])
            public_inputs = [bytes.fromhex(x) for x in v["public_inputs_hex"]]
            private_inputs = [bytes.fromhex(x) for x in v["private_inputs_hex"]]
            receipt = risc0_toy.prove_execution(
                program,
                public_inputs=public_inputs,
                private_inputs=private_inputs,
                query_count=v["query_count"],
            )
            assert receipt.trace_root.hex() == v["expected_trace_root"]
            assert list(receipt.query_positions) == v["expected_query_positions"]
            assert [x.hex() for x in receipt.journal] == v["expected_journal_hex"]
            assert risc0_toy.verify_receipt(receipt, program=program, expected_journal=[bytes.fromhex(x) for x in v["expected_journal_hex"]]) is True

        else:
            raise AssertionError(f"unknown op: {op}")


def test_verify_rejects_tampering():
    program = risc0_toy.demo_program_preimage_check()
    secret = b"correct horse battery staple"
    commitment = risc0_toy.hash256(secret)
    receipt = risc0_toy.prove_execution(program, public_inputs=[commitment, b"ok"], private_inputs=[secret], query_count=6)
    assert risc0_toy.verify_receipt(receipt, program=program, expected_journal=[b"ok"]) is True

    tampered = risc0_toy.ToyReceipt(
        image_id=receipt.image_id,
        public_inputs=receipt.public_inputs,
        private_inputs=receipt.private_inputs,
        journal=receipt.journal,
        trace_root=receipt.trace_root[:-1] + bytes([receipt.trace_root[-1] ^ 0x01]),
        query_positions=receipt.query_positions,
        proofs=receipt.proofs,
    )
    assert risc0_toy.verify_receipt(tampered, program=program, expected_journal=[b"ok"]) is False


def test_verify_rejects_program_change():
    program = risc0_toy.demo_program_preimage_check()
    secret = b"correct horse battery staple"
    commitment = risc0_toy.hash256(secret)
    receipt = risc0_toy.prove_execution(program, public_inputs=[commitment, b"ok"], private_inputs=[secret], query_count=6)

    altered_program = list(program)
    altered_program[0] = risc0_toy.Instr("PUSH_PUBLIC", 0)
    assert risc0_toy.verify_receipt(receipt, program=altered_program, expected_journal=[b"ok"]) is False


def test_verify_rejects_private_input_change():
    program = risc0_toy.demo_program_preimage_check()
    secret = b"correct horse battery staple"
    commitment = risc0_toy.hash256(secret)
    receipt = risc0_toy.prove_execution(program, public_inputs=[commitment, b"ok"], private_inputs=[secret], query_count=6)

    bad = risc0_toy.ToyReceipt(
        image_id=receipt.image_id,
        public_inputs=receipt.public_inputs,
        private_inputs=(b"wrong",),
        journal=receipt.journal,
        trace_root=receipt.trace_root,
        query_positions=receipt.query_positions,
        proofs=receipt.proofs,
    )
    assert risc0_toy.verify_receipt(bad, program=program, expected_journal=[b"ok"]) is False


def test_fs_positions_unique():
    xs = risc0_toy.fs_positions(seed=b"\x00" * 32, n=128, count=64)
    assert len(xs) == 64
    assert len(set(xs)) == 64


if __name__ == "__main__":
    test_vectors()
    test_verify_rejects_tampering()
    test_verify_rejects_program_change()
    test_verify_rejects_private_input_change()
    test_fs_positions_unique()

    print("all tests pass")
