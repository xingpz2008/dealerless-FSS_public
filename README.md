# Distributed Function Secret Sharing and Applications
Source code for the NDSS'25 paper [_Distributed Function Secret Sharing and Applications_](https://www.ndss-symposium.org/ndss-paper/distributed-function-secret-sharing-and-applications/).

## Introduction
We introduce distributed key generation schemes for FSS-based distributed point
functions and distributed comparison functions, supporting arithmetic-shared
inputs and outputs. We further design FSS-based components optimized for online
efficiency, serving as building blocks for advanced protocols. Finally, we
propose a trigonometric evaluation framework that uses periodicity to reduce
the input bit length during FSS evaluation.

## What's New

- Fixed DCF-based comparison handling for arithmetic-shared inputs and payloads.
- Fixed truncate-and-reduce carry handling for split additive shares.
- Fixed interval containment endpoint handling and reduced its online
  multiplication work.
- Fixed spline and trigonometric evaluation issues caused by ring-width changes
  in fixed-point arithmetic.
- Fixed sine, cosine, and tangent correctness over representative in-domain,
  wrapped, and signed fixed-point inputs.
- Added DCF-based ring extension for widening additive shares during online
  evaluation.
- Added public correctness checks covering FSS primitives, building blocks,
  trigonometric functions, and case-study helpers.
- Added `scripts/run_correctness.sh` for one-command local correctness
  validation.
- Updated the build flow to configure dealerless FSS against a local EzPC
  checkout through CMake.
- Improved macOS build support for the SCI/FSS dependency stack.
- Improved DPF/DCF high-bit stability by removing large stack temporaries,
  reducing tree-buffer copies, and adding explicit guards for impractical
  full-domain bit lengths.
- Added thresholded PRG-only parallel expansion for DPF/iDPF and DCF key
  generation, plus parallel full-domain DPF evaluation.
- Replaced time-seeded randomness in dealerless offline paths with
  `sysRandomSeed()`-backed PRNG draws.
- Modernized keypack ownership and read-only online APIs to reduce manual
  memory-management risks while preserving cheap key copies.
- Added `2pc_test/SAFETY_TEST` and `scripts/run_safety_perf.sh` for
  high-depth safety and performance stress checks.

## Contents
This repository consists of the following parts:
- __src__: Implementations for the 2PC FSS scheme and case-study helpers.
- __2pc_test__: Example programs, performance drivers, and correctness checks.
- __scripts__: Build and validation helpers for a local checkout.
- __docs__: Developer usage guide and public development notes.

## Installation
The implementation builds against a local [EzPC](https://github.com/mpc-msri/EzPC)
checkout. EzPC provides the FSS and SCI source trees used by this repository.

1. Clone and prepare EzPC.

```bash
git clone http://github.com/mpc-msri/EzPC/
cd EzPC
./setup_env_and_build.sh quick
```

2. Build the EzPC compiler.

```bash
cd EzPC
eval `opam env`
make
cd ../..
```

3. Clone and configure dealerless FSS.

```bash
git clone https://github.com/xingpz2008/dealerless-FSS_public.git
cd dealerless-FSS_public
cmake -S . -B build \
    -DEZPC_ROOT=/path/to/EzPC \
    -DCMAKE_BUILD_TYPE=Release
```

When the two repositories are siblings, the default `EZPC_ROOT` is `../EzPC`.
In that layout the configure command can be shortened to:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
```

4. Build the library and examples.

```bash
cmake --build build --parallel
```

The build directory contains an FSS source overlay assembled from EzPC FSS and
the dealerless implementation files. Generated objects, test binaries, and logs
stay under the configured build directory.

### Correctness Check

Run the public correctness helper from the repository root:

```bash
scripts/run_correctness.sh --ezpc-root /path/to/EzPC
```

For sibling checkouts, this is enough:

```bash
scripts/run_correctness.sh
```

The helper configures CMake, builds `CORRECTNESS_TEST`, runs both 2PC parties on
localhost, and stores logs under `build/correctness-logs/`. A successful run
prints:

```text
Correctness checks: PASS
```

Useful options:

```bash
scripts/run_correctness.sh --case 12       # trigonometric functions
scripts/run_correctness.sh --case 5        # truncation
scripts/run_correctness.sh --build-dir /tmp/dealerless-fss-build
scripts/run_correctness.sh --skip-build    # reuse an existing build
```

### Safety and Performance Stress Check

Run the safety/performance helper from the repository root:

```bash
scripts/run_safety_perf.sh
```

The helper builds and runs `SAFETY_PERF_TEST`, which checks high-depth DPF and
DCF generation/evaluation, DPF full-domain evaluation, and batched DCF
evaluation while reporting timing totals. Useful options:

```bash
scripts/run_safety_perf.sh --bits 19 --repeat 5
scripts/run_safety_perf.sh --dcf-batch 512 --eval-all-bits 14
scripts/run_safety_perf.sh --skip-configure --skip-build
```

## Usage
For developer-facing usage, integration notes, key lifetime rules, and extension
guidelines, see [`docs/developer-usage.md`](docs/developer-usage.md).

The examples in `2pc_test` expose the protocol wrappers directly. They can also
be used as reference code for integrating the FSS routines into post-compiled
EzPC/Athos workflows.

## Disclaimer
This repository is a proof-of-concept prototype.

## Cite Us
```
@inproceedings{dealerfss25xing,
  author       = {Pengzhi Xing and
                  Hongwei Li and
                  Meng Hao and
                  Hanxiao Chen and
                  Jia Hu and
                  Dongxiao Liu},
  title        = {Distributed Function Secret Sharing and Applications},
  booktitle    = {32nd Annual Network and Distributed System Security Symposium, {NDSS}
                  2025, San Diego, California, USA, February 24-28, 2025},
  publisher    = {The Internet Society},
  year         = {2025},
  url          = {https://www.ndss-symposium.org/ndss-paper/distributed-function-secret-sharing-and-applications/}
}
```
