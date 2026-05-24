# 4-Cycle Development Notes

## Step 1 Plaintext Oracle

Step 1 added `scripts/plain_4cycle_check.py`, a standalone Python checker for
local non-induced 4-cycle counts at a queried node `q`.

The checker computes exactly:

```text
sum over u != q of C(|N[q] intersection N[u]|, 2)
```

using Python sets for neighbor intersections. It treats loaded graphs as
undirected, ignores self-loops, and deduplicates repeated edges through adjacency
sets.

## Commands

Run the toy self-test:

```bash
python3 scripts/plain_4cycle_check.py --self-test
```

Run on the existing project neighbor-list layout used by `test.py`:

```bash
python3 scripts/plain_4cycle_check.py \
  --graph-dir data/neighbor_files_facebook_4039_1_1045 \
  --q 0
```

For per-candidate details, add `--verbose`:

```bash
python3 scripts/plain_4cycle_check.py \
  --graph-dir data/neighbor_files_facebook_4039_1_1045 \
  --q 0 \
  --verbose
```

The script also supports a simple two-column edge-list file:

```bash
python3 scripts/plain_4cycle_check.py --graph path/to/edges.txt --q 0
```

No cryptographic protocol code, C++ triangle-counting behavior, or CMake files
were modified in this step.

## Step 2 Isolated Executable

Step 2 added `triangle_counting/cycle4_psi.cpp` and a separate `gcf_4cycle`
target in `triangle_counting/CMakeLists.txt`. The new source was copied from the
existing triangle executable entry and keeps the old code path isolated from
`gcf_psi`.

Build with the existing project command:

```bash
./build.sh
```

The original `gcf_psi` target is intentionally unchanged.
The build script also copies `gcf_4cycle` to the repository-level `bin/`
directory next to `gcf_psi`.

## Step 3 Dry-Run Layout

Step 3 added a non-cryptographic dry-run mode to `gcf_4cycle`:

```bash
./bin/gcf_4cycle \
  --task cycle4 \
  --dry-run \
  --idx 0 \
  --name facebook_4039_1_1045 \
  --num_v 4039 \
  --num_d 1045
```

The dry-run uses the same neighbor-list layout as `test.py`:
`data/neighbor_files_<name>/neighbor_<node>.txt`.

Printed fields:

- `q`: queried node id from `--idx`.
- `num_vertices`: graph vertex count from `--num_v`.
- `degree(q)`: number of entries loaded from q's neighbor file.
- `candidate_count`: number of candidate providers, currently
  `num_vertices - 1`.
- `expected_query_count`: conceptual future membership-query count,
  `candidate_count * degree(q)`.

This dry-run does not run PSI, does not contact other nodes, and does not
implement the private 4-cycle protocol yet. It only loads q's neighbor list,
constructs candidate metadata, validates the layout counts, and prints sanity
information.
