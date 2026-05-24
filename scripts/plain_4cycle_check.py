#!/usr/bin/env python3
"""Plaintext oracle for local 4-cycle counting."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


NEIGHBOR_FILE_RE = re.compile(r"^neighbor_(\d+)\.txt$")


def count_4cycle_at_q(adj, q):
    """
    adj: list[set[int]] or dict[int, set[int]]
    q: queried node id
    return: (answer, per_u)
        answer: int
        per_u: list of tuples (u, common_count, contribution)
               where contribution = common_count * (common_count - 1) // 2
    """
    if isinstance(adj, dict):
        if q not in adj:
            raise KeyError(f"q={q} is not present in adjacency")
        q_neighbors = adj[q]
        nodes = sorted(adj)
        get_neighbors = adj.__getitem__
    else:
        if q < 0 or q >= len(adj):
            raise IndexError(f"q={q} is outside adjacency list")
        q_neighbors = adj[q]
        nodes = range(len(adj))
        get_neighbors = adj.__getitem__

    answer = 0
    per_u = []
    for u in nodes:
        if u == q:
            continue
        common_count = len(q_neighbors & get_neighbors(u))
        contribution = common_count * (common_count - 1) // 2
        answer += contribution
        per_u.append((u, common_count, contribution))

    return answer, per_u


def _add_undirected_edge(adj, u, v):
    if u == v:
        adj.setdefault(u, set())
        return
    adj.setdefault(u, set()).add(v)
    adj.setdefault(v, set()).add(u)


def _read_int_lines(path):
    values = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                values.append(int(stripped))
            except ValueError as exc:
                raise ValueError(f"{path}:{line_no}: expected integer node id") from exc
    return values


def _project_node_count_from_dir(graph_dir):
    name = graph_dir.name
    if name.startswith("neighbor_files_"):
        name = name[len("neighbor_files_") :]
    parts = name.split("_")
    if len(parts) < 3:
        return None
    try:
        return int(parts[-3])
    except ValueError:
        return None


def load_project_neighbor_dir(graph_dir):
    """Load test.py's data/neighbor_files_<name>/neighbor_<node>.txt format."""
    graph_dir = Path(graph_dir)
    if not graph_dir.is_dir():
        raise FileNotFoundError(f"graph directory not found: {graph_dir}")

    adj = {}
    owner_ids = []
    for path in sorted(graph_dir.iterdir()):
        match = NEIGHBOR_FILE_RE.match(path.name)
        if not match:
            continue
        owner = int(match.group(1))
        owner_ids.append(owner)
        adj.setdefault(owner, set())
        for neighbor in _read_int_lines(path):
            _add_undirected_edge(adj, owner, neighbor)

    if not owner_ids:
        raise ValueError(f"no neighbor_<node>.txt files found in {graph_dir}")

    node_count = _project_node_count_from_dir(graph_dir)
    if node_count is not None:
        owner_set = set(owner_ids)
        if 0 in owner_set:
            for node in range(node_count):
                adj.setdefault(node, set())
        elif node_count in owner_set:
            for node in range(1, node_count + 1):
                adj.setdefault(node, set())

    return adj


def load_edge_list(graph_path):
    """Load a simple two-column edge list; comments and blank lines are ignored."""
    graph_path = Path(graph_path)
    if not graph_path.is_file():
        raise FileNotFoundError(f"graph file not found: {graph_path}")

    adj = {}
    with graph_path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = stripped.split()
            if len(parts) != 2:
                raise ValueError(
                    f"{graph_path}:{line_no}: expected exactly two integer node ids"
                )
            try:
                u, v = int(parts[0]), int(parts[1])
            except ValueError as exc:
                raise ValueError(
                    f"{graph_path}:{line_no}: expected integer node ids"
                ) from exc
            _add_undirected_edge(adj, u, v)
    return adj


def _adj_from_edges(edges, node_count=None):
    adj = {node: set() for node in range(node_count or 0)}
    for u, v in edges:
        _add_undirected_edge(adj, u, v)
    return adj


def run_self_tests():
    tests = [
        (
            "C4",
            _adj_from_edges([(0, 1), (1, 2), (2, 3), (3, 0)]),
            0,
            1,
        ),
        (
            "K4",
            _adj_from_edges(
                [(0, 1), (0, 2), (0, 3), (1, 2), (1, 3), (2, 3)]
            ),
            0,
            3,
        ),
        (
            "path",
            _adj_from_edges([(0, 1), (1, 2), (2, 3)]),
            0,
            0,
        ),
        (
            "empty",
            _adj_from_edges([], node_count=4),
            0,
            0,
        ),
        (
            "square_with_diagonal",
            _adj_from_edges([(0, 1), (1, 2), (2, 3), (3, 0), (1, 3)]),
            0,
            1,
        ),
    ]

    ok = True
    for name, adj, q, expected in tests:
        actual, _ = count_4cycle_at_q(adj, q)
        status = "PASS" if actual == expected else "FAIL"
        print(f"[{status}] {name} q={q} expected={expected} actual={actual}")
        ok = ok and actual == expected
    return ok


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Plaintext local 4-cycle checker for Sectric graph inputs."
    )
    parser.add_argument("--self-test", action="store_true", help="run toy tests")
    parser.add_argument(
        "--graph-dir",
        help="directory with neighbor_<node>.txt files, as used by test.py",
    )
    parser.add_argument(
        "--graph",
        help="simple two-column undirected edge-list file",
    )
    parser.add_argument("--q", type=int, help="queried node id")
    parser.add_argument("--verbose", action="store_true", help="print per-u details")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])

    if args.self_test:
        return 0 if run_self_tests() else 1

    if args.q is None:
        print("error: --q is required unless --self-test is used", file=sys.stderr)
        return 2

    if bool(args.graph_dir) == bool(args.graph):
        print("error: provide exactly one of --graph-dir or --graph", file=sys.stderr)
        return 2

    try:
        adj = (
            load_project_neighbor_dir(args.graph_dir)
            if args.graph_dir
            else load_edge_list(args.graph)
        )
        answer, per_u = count_4cycle_at_q(adj, args.q)
    except (FileNotFoundError, IndexError, KeyError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"q = {args.q}")
    print(f"degree(q) = {len(adj[args.q])}")
    print(f"candidate_count = {len(per_u)}")
    print(f"plaintext_4cycle = {answer}")

    if args.verbose:
        for u, common_count, contribution in per_u:
            print(f"u={u} common={common_count} contribution={contribution}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
