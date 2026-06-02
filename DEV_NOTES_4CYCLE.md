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

## Step 4 Candidate Loop Skeleton

Step 4 added a per-candidate streaming-loop skeleton behind the same dry-run
entry:

```bash
./bin/gcf_4cycle \
  --task cycle4 \
  --dry-run \
  --step4 \
  --data-dir data/neighbor_files_test_6_6_2 \
  --idx 0
```

If the same dataset is mounted at an absolute path, the equivalent command is:

```bash
./bin/gcf_4cycle \
  --task cycle4 \
  --dry-run \
  --step4 \
  --data-dir /data/neighbor_files_test_6_6_2 \
  --idx 0
```

`--data-dir` points directly at a directory containing `neighbor_<node>.txt`
files. If `--num_v` is omitted, the dry-run infers the vertex count from the
existing directory naming convention, for example
`neighbor_files_test_6_6_2` means 6 vertices. The toy sample uses 0-based node
ids, so `q=0` produces candidates `1, 2, 3, 4, 5`.

Step 4 validates that `q` is in range, that candidates do not contain `q`, and
that the candidate count is exactly `num_vertices - 1`. The placeholder currently
prints:

```text
[4cycle][candidate] u=<u> q=<q> q_degree=<degree>
```

Step 4 does not run PSI, OKVS decode, OPRF, equality, OT, or Beaver triples.

## Step 5 Padded Q Query List

Step 5 added construction and validation of Q's padded query list for future
per-candidate 4-cycle checks.

Run on the 6-vertex toy sample:

```bash
./bin/gcf_4cycle \
  --task cycle4 \
  --dry-run \
  --step5 \
  --data-dir /data/neighbor_files_test_6_1_4 \
  --idx 0 \
  --degree-bound 4
```

The same command also works with the repository-local path:

```bash
./bin/gcf_4cycle \
  --task cycle4 \
  --dry-run \
  --step5 \
  --data-dir data/neighbor_files_test_6_1_4 \
  --idx 0 \
  --degree-bound 4
```

`degree_bound` is provided by `--degree-bound`. If that flag is omitted, the
dry-run falls back to the existing `--num_d` value, and finally to the last field
of the existing dataset naming convention, such as `neighbor_files_test_6_1_4`.

Padding rules:

- Real neighbors from `N[q]` stay at the front of the list.
- If `degree(q) < D`, deterministic dummy vertex ids starting at
  `num_vertices` are appended.
- Dummy ids are validated to be outside the valid vertex-id range.
- If `degree(q) > D`, the command fails clearly instead of truncating.

Step 5 does not run OKVS decode, PSI, OPRF, equality, OT, or Beaver triples.
