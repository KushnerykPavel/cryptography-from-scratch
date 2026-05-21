"""
Educational implementation of the SIDH Torsion Point Leakage.
Shows why publishing the images of auxiliary torsion points allows
an attacker to efficiently recover the secret path in the isogeny graph.

Run with:
    python3 code/main.py
"""

import hashlib
import sys

def hash_to_int(data: str) -> int:
    """Simple deterministic hash for graph generation."""
    return int(hashlib.sha256(data.encode()).hexdigest()[:8], 16)

class IsogenyGraph:
    """
    A toy model of a supersingular isogeny graph.
    Nodes are 'curves' represented by integers.
    Edges are 'isogenies'. We simulate a 3-regular graph.
    """
    def __init__(self, p: int):
        self.p = p

    def get_neighbors(self, node: int) -> list[int]:
        """Returns 3 deterministic neighbors for a given node."""
        neighbors = []
        for i in range(3):
            # Deterministic pseudo-random neighbors
            h = hash_to_int(f"edge_{node}_{i}") % self.p
            neighbors.append(h)
        return neighbors

def generate_matrices(node: int, neighbor: int) -> tuple[int, int, int, int]:
    """
    Simulates the 'action' of an isogeny on the torsion basis.
    For the toy model, we just assign a deterministic 2x2 matrix
    to each edge.
    Returns (a, b, c, d)
    """
    # Deterministic matrix for the directed edge
    a = hash_to_int(f"m_{node}_{neighbor}_a") % 97
    b = hash_to_int(f"m_{node}_{neighbor}_b") % 97
    c = hash_to_int(f"m_{node}_{neighbor}_c") % 97
    d = hash_to_int(f"m_{node}_{neighbor}_d") % 97
    return (a, b, c, d)

def multiply_matrices(m1, m2):
    """Multiplies two 2x2 matrices modulo 97."""
    a1, b1, c1, d1 = m1
    a2, b2, c2, d2 = m2
    a = (a1*a2 + b1*c2) % 97
    b = (a1*b2 + b1*d2) % 97
    c = (c1*a2 + d1*c2) % 97
    d = (c1*b2 + d1*d2) % 97
    return (a, b, c, d)

def sidh_alice_keygen(graph: IsogenyGraph, start_node: int, secret_path_indices: list[int]):
    """
    Alice takes a secret walk through the graph.
    She computes:
      1. Her public curve (the end node)
      2. The image of Bob's torsion points (the product of matrices along the path)
    """
    current_node = start_node
    total_matrix = (1, 0, 0, 1) # Identity matrix

    for step_index in secret_path_indices:
        neighbors = graph.get_neighbors(current_node)
        next_node = neighbors[step_index]
        
        # Apply the isogeny's action on torsion points
        edge_matrix = generate_matrices(current_node, next_node)
        total_matrix = multiply_matrices(edge_matrix, total_matrix)
        
        current_node = next_node

    return current_node, total_matrix

def kani_oracle(current_node: int, neighbor_candidate: int, remaining_steps: int, target_matrix: tuple[int, int, int, int], accumulated_matrix: tuple[int, int, int, int]) -> bool:
    """
    The Castryck-Decru attack conceptually uses Kani's theorem as an oracle.
    """
    edge_matrix = generate_matrices(current_node, neighbor_candidate)
    start_matrix = multiply_matrices(edge_matrix, accumulated_matrix)
    
    def search(node, depth, current_matrix):
        if depth == 0:
            return current_matrix == target_matrix
        
        for next_node in IsogenyGraph(1000003).get_neighbors(node):
            m = generate_matrices(node, next_node)
            new_matrix = multiply_matrices(m, current_matrix)
            if search(next_node, depth - 1, new_matrix):
                return True
        return False

    return search(neighbor_candidate, remaining_steps - 1, start_matrix)

def torsion_compass_attack(graph: IsogenyGraph, start_node: int, walk_length: int, public_key: tuple[int, tuple[int, int, int, int]]):
    """
    The Castryck-Decru / Torsion Point attack.
    """
    target_node, target_matrix = public_key
    
    current_node = start_node
    recovered_path = []
    accumulated_matrix = (1, 0, 0, 1)
    
    for step in range(walk_length):
        neighbors = graph.get_neighbors(current_node)
        found_correct_step = False
        
        for idx, neighbor in enumerate(neighbors):
            if kani_oracle(current_node, neighbor, walk_length - step, target_matrix, accumulated_matrix):
                recovered_path.append(idx)
                # Update the accumulated matrix
                edge_matrix = generate_matrices(current_node, neighbor)
                accumulated_matrix = multiply_matrices(edge_matrix, accumulated_matrix)
                current_node = neighbor
                found_correct_step = True
                break
                
        if not found_correct_step:
            raise ValueError(f"Attack failed to find a valid path at step {step}!")
            
    return recovered_path

def main():
    print("=== Step 1: The Isogeny Graph ===")
    graph = IsogenyGraph(p=1000003)
    start_node = 100
    print(f"Start curve node: {start_node}")
    print(f"Neighbors of start curve: {graph.get_neighbors(start_node)}\n")
    
    print("=== Step 2: SIDH Key Generation ===")
    # Alice chooses a secret 5-step path
    secret_path = [0, 2, 1, 0, 2]
    print(f"Alice's secret path: {secret_path}")
    
    public_curve, torsion_matrix = sidh_alice_keygen(graph, start_node, secret_path)
    print(f"Alice's public curve: {public_curve}")
    print(f"Alice's torsion matrix (auxiliary points): {torsion_matrix}\n")
    
    print("=== Step 3: The Torsion Compass Attack ===")
    print("Attacker uses Kani's oracle to check edges one by one...")
    recovered_path = torsion_compass_attack(graph, start_node, len(secret_path), (public_curve, torsion_matrix))
    print(f"Recovered path: {recovered_path}")
    
    if recovered_path == secret_path:
        print("SUCCESS: The Castryck-Decru attack recovered the secret key in polynomial time!")
    else:
        print("FAILED: Did not recover the correct key.")

if __name__ == "__main__":
    main()
