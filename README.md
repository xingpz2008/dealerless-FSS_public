# Distributed Function Secret Sharing and Applications

This repo provides implementation for:

- Pengzhi Xing, et al, "Communication-Efficient Secure Nonlinear Evaluation from Dealer-less Function Secret Sharing," 2026.
- Pengzhi Xing, Hongwei Li, Meng Hao, Hanxiao Chen, Jia Hu and Dongxiao Liu, "[Distributed Function Secret Sharing and Applications](https://www.ndss-symposium.org/ndss-paper/distributed-function-secret-sharing-and-applications/)," in Proceedings of NDSS, 2025.

## Introduction

We introduce distributed key generation schemes for FSS-based distributed point
functions and distributed comparison functions, supporting arithmetic-shared
inputs and outputs. We further design FSS-based components optimized for online
efficiency, serving as building blocks for advanced protocols. Finally, we
propose a trigonometric evaluation framework that uses periodicity to reduce
the input bit length during FSS evaluation.

## What's New

- Reorganized the code into separate CMake targets: `dfss_common`, `dfss`, and
  `dfss_legacy`.
- Isolated old NDSS-compatible code under `src/legacy` while keeping dFSS
  primitives and building blocks under `src/fss`, `src/buildingblock`, and
  `src/math`.
- Added explicit correctness targets and scripts for dFSS protocols, helper
  primitives, and legacy compatibility tests.
- Added a dFSS benchmark driver with explicit CLI parameters and separate
  protocol/microbenchmark implementations.
- Added generic public-LUT and MIC-based piecewise-polynomial evaluation
  support for the dFSS library.
- Kept legacy trigonometric and case-study drivers available as isolated
  compatibility/baseline code.

## Contents

This repository consists of the following parts:

- __src__: dFSS library code plus isolated legacy compatibility/baseline
  code.
- __test__: dFSS correctness tests and dFSS benchmark drivers.
- __scripts__: Build, correctness, benchmark, and validation helpers for a
  local checkout.
- __tools__: Public-data generation and polynomial-fitting helpers for nonlinear
  evaluation experiments. See `tools/nonlinear/*.py` and `tools/polyfit/*.py`
  for public LUT/polynomial material generation and semantic checks.
- __docs__: Public developer usage guide and documentation index.

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

On macOS, install OpenMP before configuring dealerless FSS:

```bash
brew install libomp
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

> [!IMPORTANT]
> **Correctness checks are currently recommended with Clang/AppleClang. If you
> use another compiler and see build or correctness issues, reconfigure the
> project with `-DCMAKE_CXX_COMPILER=clang++`.**

Run the public correctness helper from the repository root:

```bash
scripts/run_correctness.sh --ezpc-root /path/to/EzPC
```

For sibling checkouts, this is enough:

```bash
scripts/run_correctness.sh
```

The helper configures CMake, builds `DFSS_CORRECTNESS_TEST`, runs both 2PC
parties on localhost, and stores logs under `build/correctness-logs/`. A
successful run prints:

```text
Correctness checks: PASS
```

Useful options:

```bash
scripts/run_correctness.sh --suite dfss --case 12      # dFSS comparison
scripts/run_correctness.sh --suite dfss --case 16      # MIC PolyEval
scripts/run_correctness.sh --suite helper --case 3     # OHG helper
src/legacy/scripts/run_legacy_correctness.sh --case 11 # legacy trigonometric functions
scripts/run_correctness.sh --build-dir /tmp/dealerless-fss-build
scripts/run_correctness.sh --skip-configure --skip-build    # reuse an existing build
```

## Usage

For developer-facing usage, integration notes, key lifetime rules, and extension
guidelines, see [`docs/developer-usage.md`](docs/developer-usage.md).

The examples in `test` and `src/legacy/benchmark` expose the protocol wrappers
directly. They can also be used as reference code for integrating the FSS
routines into post-compiled EzPC/Athos workflows.

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
