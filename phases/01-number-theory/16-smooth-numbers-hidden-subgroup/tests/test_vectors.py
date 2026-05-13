import importlib.util
import json
from pathlib import Path


LESSON_DIR = Path(__file__).resolve().parents[1]
MODULE_PATH = LESSON_DIR / "code" / "main.py"
VECTORS_PATH = LESSON_DIR / "tests" / "vectors.json"


spec = importlib.util.spec_from_file_location("smooth_hsp", MODULE_PATH)
smooth_hsp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smooth_hsp)


def load_vectors():
    return json.loads(VECTORS_PATH.read_text())


def test_smoothness_vectors():
    for vector in load_vectors()["smoothness"]:
        result = smooth_hsp.factor_over_bound(vector["value"], vector["bound"])
        expected_exponents = {
            int(prime): exponent for prime, exponent in vector["exponents"].items()
        }
        assert result.exponents == expected_exponents
        assert result.remaining == vector["remaining"]
        assert result.is_smooth is vector["is_smooth"]


def test_smooth_value_vectors():
    for vector in load_vectors()["smooth_values"]:
        values = smooth_hsp.smooth_values(vector["limit"], vector["bound"])
        assert values == vector["values"]


def test_hidden_period_vectors():
    for vector in load_vectors()["hidden_periods"]:
        table = smooth_hsp.hidden_period_table(vector["group_size"], vector["period"])
        assert table == vector["table"]
        assert smooth_hsp.recover_hidden_period(table) == vector["period"]
        subgroup = smooth_hsp.hidden_subgroup(vector["group_size"], vector["period"])
        assert subgroup == vector["hidden_subgroup"]


def test_period_factoring_vectors():
    for vector in load_vectors()["period_factoring"]:
        order = smooth_hsp.multiplicative_order(vector["base"], vector["n"])
        assert order == vector["period"]

        factors = smooth_hsp.factor_from_period(
            vector["n"], vector["base"], vector["period"]
        )
        assert list(factors) == vector["factors"]

        result = smooth_hsp.shor_classical_postprocess(vector["n"], vector["base"])
        assert result.period == vector["period"]
        assert list(result.factors) == vector["factors"]
