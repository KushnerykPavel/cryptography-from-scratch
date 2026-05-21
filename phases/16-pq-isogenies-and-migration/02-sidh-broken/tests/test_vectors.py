import json
import os
import sys

# Add code directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../code')))

from main import (
    IsogenyGraph,
    generate_matrices,
    multiply_matrices,
    sidh_alice_keygen,
    torsion_compass_attack
)

def test_vectors():
    vectors_path = os.path.join(os.path.dirname(__file__), 'vectors.json')
    with open(vectors_path, 'r') as f:
        data = json.load(f)

    graph = IsogenyGraph(1000003)

    for case in data['vectors']:
        op = case['op']
        inputs = case['inputs']
        expected = case['expected']

        if op == "get_neighbors":
            result = graph.get_neighbors(inputs['node'])
            assert result == expected, f"Expected {expected}, got {result}"
        
        elif op == "generate_matrices":
            result = list(generate_matrices(inputs['node'], inputs['neighbor']))
            assert result == expected, f"Expected {expected}, got {result}"
            
        elif op == "multiply_matrices":
            result = list(multiply_matrices(tuple(inputs['m1']), tuple(inputs['m2'])))
            assert result == expected, f"Expected {expected}, got {result}"
            
        elif op == "sidh_alice_keygen":
            curve, matrix = sidh_alice_keygen(graph, inputs['start_node'], inputs['secret_path'])
            assert curve == expected['public_curve'], f"Curve: expected {expected['public_curve']}, got {curve}"
            assert list(matrix) == expected['torsion_matrix'], f"Matrix: expected {expected['torsion_matrix']}, got {list(matrix)}"
            
        elif op == "torsion_compass_attack":
            public_key = (inputs['public_curve'], tuple(inputs['torsion_matrix']))
            result = torsion_compass_attack(graph, inputs['start_node'], inputs['walk_length'], public_key)
            assert result == expected, f"Expected {expected}, got {result}"

def test_properties():
    # Test that the attack always works for different random walks
    graph = IsogenyGraph(1000003)
    start_node = 42
    
    # Test paths of length 3 to keep the test extremely fast
    for path in [[0, 0, 0], [1, 2, 0], [2, 1, 1]]:
        curve, matrix = sidh_alice_keygen(graph, start_node, path)
        recovered = torsion_compass_attack(graph, start_node, len(path), (curve, matrix))
        assert recovered == path, f"Failed to recover {path}"

if __name__ == "__main__":
    test_vectors()
    test_properties()
    print("all tests pass")
