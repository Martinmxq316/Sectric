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
