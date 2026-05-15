import importlib.util
import sys
from pathlib import Path


LESSON = Path(__file__).resolve().parents[1]
MODULE_PATH = LESSON / "code" / "main.py"
VECTORS_PATH = LESSON / "tests" / "vectors.json"


spec = importlib.util.spec_from_file_location("test_vectors_main", MODULE_PATH)
main = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = main
spec.loader.exec_module(main)


def test_vectors_file_schema():
    data = main.load_vectors_file(VECTORS_PATH)
    assert isinstance(data["source"], str)
    assert isinstance(data["vectors"], list)


def test_vectors():
    data = main.load_vectors_file(VECTORS_PATH)
    main.run_vectors(data["vectors"])


if __name__ == "__main__":
    test_vectors_file_schema()
    test_vectors()
    print("vector harness passed")

