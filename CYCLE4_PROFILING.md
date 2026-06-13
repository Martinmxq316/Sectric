# Cycle4 PSI Profiling Usage

This document describes how to run the profiling added to `gcf_4cycle`.

## Where Results Appear

Profiling results are printed to the terminal stdout of each `gcf_4cycle`
process. No CSV, JSON, or log file is written.

Enable aggregate profiling with:

```bash
--profile
```

Enable aggregate plus per-candidate rows with:

```bash
--profile-candidate-detail
```

`--profile-candidate-detail` also enables profiling, so it can be used without
`--profile`.

Each profiled party prints a block like:

```text
[PROFILE] role=server dataset=test_6_1_4 query=0
[PROFILE] aggregate
stage                    calls       time_ms     sent_MB     recv_MB ...
...
```

The server and querier print separate tables. Compare both outputs when
measuring total behavior.

## Build

Build from the repository root:

```bash
SECTRIC_OPENSSL_ROOT=/usr/local/openssl ./build.sh
```

The executable is copied to:

```text
bin/gcf_4cycle
```

## What Is Measured

Profiling starts after the PSI connections are established and excludes the
existing `cycle4.h` preprocessing / neighbor OKVS exchange.

Measured stages:

- `prepare_table`
- `vole_oprf`
- `oprf_evaluate`
- `okvs`
- `block_equality`
- `ot_sum`
- `psi_ca_total`
- `beaver_square`
- `term_exchange`
- `final_total_exchange`
- `protocol_total`

`psi_ca_total` contains the inner PSI-CA stages, and `protocol_total` contains
the whole profiled main flow. Do not sum all rows as if they were disjoint.

Communication columns are split by channel family:

- `kunlun_*`: Kunlun `NetIO`
- `sci_*`: SCI `NetIO`
- `libote_*`: libOTe `osuCrypto::Channel`
- `aby_*`: ABY `CSocket`

All byte counts are shown in MB.

## Example: Small Dataset

Example dataset:

```text
data/neighbor_files_test_6_1_4
```

Use:

- `--name test_6_1_4`
- `--idx 0`
- `--num_v 6`
- `--num_d 4`

### Terminal 1: Querier

Start the querier first. It waits for role-2 preprocessing senders on port
`8999`, then joins the PSI protocol.

```bash
./bin/gcf_4cycle \
  --role 1 \
  --idx 0 \
  --name test_6_1_4 \
  --num_v 6 \
  --num_d 4 \
  --profile-candidate-detail
```

### Terminal 2: Server

Start the server in another terminal:

```bash
./bin/gcf_4cycle \
  --role 0 \
  --idx 0 \
  --name test_6_1_4 \
  --num_v 6 \
  --num_d 4 \
  --profile-candidate-detail
```

### Terminal 3: Preprocessing Senders

The querier needs one role-2 sender for every candidate vertex except `q`.
For `q=0` and `num_v=6`, run:

```bash
for u in 1 2 3 4 5; do
  ./bin/gcf_4cycle \
    --role 2 \
    --neighbor "$u" \
    --name test_6_1_4 \
    --num_v 6 \
    --num_d 4
done
```

Role-2 processes only perform preprocessing and exit. They do not print profiling
tables because the profiled PSI main flow is only run by role 0 and role 1.

## Aggregate-Only Run

Use `--profile` instead of `--profile-candidate-detail` to print only aggregate
stage totals:

```bash
./bin/gcf_4cycle \
  --role 1 \
  --idx 0 \
  --name test_6_1_4 \
  --num_v 6 \
  --num_d 4 \
  --profile
```

Run the matching role-0 server with the same dataset arguments and `--profile`.

## Notes

- Run commands from the repository root so `./data/neighbor_files_<name>` is
  found correctly.
- Keep `--idx`, `--name`, `--num_v`, and `--num_d` consistent between the server
  and querier.
- If ports are already in use, change `--port` consistently for role 0 and role
  1. The Kunlun channels currently still use fixed ports `8080` and `8081`.
- The current output is intended for terminal inspection. Redirect stdout if you
  want to save results:

```bash
./bin/gcf_4cycle ... --profile > querier_profile.txt
```
