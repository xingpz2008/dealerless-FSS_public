# Test Layout

This directory contains only the active dFSS-facing tests and benchmarks.
Legacy tests and benchmark drivers live under `src/legacy`.

## Targets

- `DFSS_CORRECTNESS_TEST`: new dFSS primitives, wrappers, building blocks, and math checks.
- `HELPER_CORRECTNESS_TEST`: protocol-neutral helper checks.
- `DFSS_EXT_BENCH`: dFSS-only benchmark target.

## Layout

- `correctness/correctness.cpp`: dFSS correctness entry point.
- `correctness/protocol/`: dFSS protocol correctness cases.
- `correctness/helper/`: helper-only correctness entry point and cases.
- `correctness/common/`: shared test utilities.
- `benchmark/benchmark.cpp`: dFSS benchmark entry point.
- `benchmark/protocol/`, `benchmark/helper/`, `benchmark/microbench/`: protocol benchmarks, benchmark utilities, and component microbenchmarks.

## Scripts

```bash
scripts/run_correctness.sh --suite dfss
scripts/run_correctness.sh --suite helper
scripts/run_dfss_ext_bench.sh --bench dpf --bin 8 --repeat 1
```

Use `src/legacy/scripts/run_legacy_correctness.sh` and
`src/legacy/scripts/run_legacy_bench.sh` for the isolated legacy baseline.
