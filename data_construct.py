from pathlib import Path


NODE_COUNT = 50
DATASET_NAME = "neighbor_files_test_50_1_49"


def construct_complete_graph() -> Path:
    """Generate neighbor files for a complete graph with vertices 0 through 49."""
    output_dir = Path(__file__).resolve().parent / "data" / DATASET_NAME
    output_dir.mkdir(parents=True, exist_ok=True)

    for vertex in range(NODE_COUNT):
        neighbors = (str(neighbor) for neighbor in range(NODE_COUNT) if neighbor != vertex)
        content = "\n".join(neighbors) + "\n"
        (output_dir / f"neighbor_{vertex}.txt").write_text(
            content, encoding="utf-8"
        )

    return output_dir


if __name__ == "__main__":
    generated_dir = construct_complete_graph()
    print(f"Generated complete-graph data in: {generated_dir}")
