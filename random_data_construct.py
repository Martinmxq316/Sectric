#!/usr/bin/env python3
"""Generate a random simple undirected graph with bounded maximum degree."""

import argparse
import random
from pathlib import Path


def generate_graph(vertex_count: int, max_degree: int, seed: int | None = None) -> list[set[int]]:
    """Return a random, edge-maximal graph whose maximum degree is at most max_degree."""
    if vertex_count <= 0:
        raise ValueError("N must be a positive integer")
    if max_degree < 0:
        raise ValueError("D must be a non-negative integer")

    rng = random.Random(seed)
    candidate_edges = [
        (u, v)
        for u in range(vertex_count)
        for v in range(u + 1, vertex_count)
    ]
    rng.shuffle(candidate_edges)

    adjacency = [set() for _ in range(vertex_count)]
    for u, v in candidate_edges:
        if len(adjacency[u]) < max_degree and len(adjacency[v]) < max_degree:
            adjacency[u].add(v)
            adjacency[v].add(u)

    return adjacency


def validate_graph(adjacency: list[set[int]], max_degree: int) -> None:
    """Check that adjacency describes a valid bounded-degree simple undirected graph."""
    vertex_count = len(adjacency)
    for u, neighbors in enumerate(adjacency):
        if u in neighbors:
            raise ValueError(f"self-loop found at vertex {u}")
        if len(neighbors) > max_degree:
            raise ValueError(f"degree of vertex {u} exceeds D={max_degree}")
        for v in neighbors:
            if not 0 <= v < vertex_count:
                raise ValueError(f"invalid vertex {v} in neighbor list of {u}")
            if u not in adjacency[v]:
                raise ValueError(f"edge ({u}, {v}) is not symmetric")


def write_dataset(
    adjacency: list[set[int]], max_degree: int, data_dir: Path
) -> tuple[Path, int]:
    """Write the graph using this project's neighbor-file data format."""
    validate_graph(adjacency, max_degree)

    vertex_count = len(adjacency)
    edge_count = sum(len(neighbors) for neighbors in adjacency) // 2
    dataset_name = (
        f"neighbor_files_test_{vertex_count}_{edge_count}_{max_degree}"
    )
    output_dir = data_dir / dataset_name
    output_dir.mkdir(parents=True, exist_ok=True)

    for vertex, neighbors in enumerate(adjacency):
        content = "".join(f"{neighbor}\n" for neighbor in sorted(neighbors))
        (output_dir / f"neighbor_{vertex}.txt").write_text(
            content, encoding="utf-8"
        )

    return output_dir, edge_count


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate a random simple undirected graph with N vertices and "
            "maximum degree at most D."
        )
    )
    parser.add_argument("N", type=int, help="number of vertices, numbered 0 to N-1")
    parser.add_argument("D", type=int, help="maximum allowed degree (D >= 0)")
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="optional random seed for reproducible output",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        adjacency = generate_graph(args.N, args.D, args.seed)
        data_dir = Path(__file__).resolve().parent / "data"
        output_dir, edge_count = write_dataset(adjacency, args.D, data_dir)
    except ValueError as error:
        raise SystemExit(f"error: {error}") from error

    actual_max_degree = max(map(len, adjacency), default=0)
    print(f"Generated dataset: {output_dir}")
    print(
        f"Vertices: {args.N}, edges: {edge_count}, "
        f"maximum degree: {actual_max_degree} (limit: {args.D})"
    )


if __name__ == "__main__":
    main()
