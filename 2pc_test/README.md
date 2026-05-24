# Usage and Test Case

## Contents
This repository consists of the following parts:
- __GEN_TEST__: Dealer-less DPF/DCF examples.
- __BB_TEST__: FSS-based building-block examples.
- __TRI_TEST__: Trigonometric evaluation examples.
- __CASE_STUDIES__: Case-study performance drivers.
- __CORRECTNESS_TEST__: Public correctness checks with pass/fail assertions.

## Compilation
```bash
# From the repository root
cmake -S . -B build -DEZPC_ROOT=/path/to/EzPC
cmake --build build --parallel
```

The test executables are placed under the matching `build/2pc_test`
subdirectories. Each individual test directory can also be configured directly
with CMake when `EZPC_ROOT` is provided.

## Correctness Check

The recommended correctness entry point is the repository-level helper:

```bash
scripts/run_correctness.sh --ezpc-root /path/to/EzPC
```

The helper starts both parties, checks the final result, and writes logs to
`build/correctness-logs/`.

To run a focused case:

```bash
scripts/run_correctness.sh --case 12   # sine, cosine, tangent
scripts/run_correctness.sh --case 6    # containment
```

## Usage
After compilation, each test subdirectory has a binary executable. Run one party
with `r=2` and the other party with `r=3`, using the same port `p`.

General Arguments:

`r` stands for the party number: `r=2` for server and `r=3` for client.

`f` stands for the function type if the specification of this option is necessary. 

`i` stands for the input bit length. The tested experiment range uses `i<=18`.

`o` stands for the output bit length. The tested experiment range uses `o<=18`.

`s` stands for the scale under fixed-point arithmetic.

`p` stands for the TCP port. Use the same port for both parties.

### DPF (DCF) Test
```bash
cd build/2pc_test/GEN_TEST
./GEN_TEST r=2 p=32000 f=0 i=8 o=8
./GEN_TEST r=3 p=32000 f=0 i=8 o=8
```
Argument:

`f` stands for the function type. Function choice: DPF = 0; DCF = 1; DPF-based Equality Test = 2; DCF-based comparison = 3

### Building Block Test
```bash
cd build/2pc_test/BB_TEST
./BB_TEST r=2 p=32001 f=0 i=8 o=8 s=5
./BB_TEST r=3 p=32001 f=0 i=8 o=8 s=5
```
Argument:

`f` stands for the function type. Function choice: Modular with 2^N = 1; Truncate and Reduce = 2; Containment = 3; 
Digit Decomposition = 4; Public LUT = 5; Private LUT = 6; Spline Polynomial Approximation = 7.

You may change the parameter in `BuildingBlock_Test.cpp` to test functions under different parameter settings:

For Modular, `MODULAR_N` must be powers of 2.

For Truncate and Reduce, adjust the `TR_S` to change the amount of truncated bit.

For Containment, change `CTN_SIZE` to any knots number and `CTN_KNOTS` to define custom knot points.

For Public / Private LUT, the size of table entries is determined by input bit length `i`.

For Spline Polynomial Approximation, variable `APPROX_DEG` determines approximation degree and `APPROX_SEG` determines spline numbers. 

### Trigonometric Test
```bash
cd build/2pc_test/TRI_TEST
./SIN_TEST r=2 p=32002 f=0 i=8 o=8 s=5 l=1
./SIN_TEST r=3 p=32002 f=0 i=8 o=8 s=5 l=1
```
Argument:

`f` stands for the function type. Function choice: Sine = 0; Cosine = 1; Tangent = 2

`l` stands for if Lookup Table implementation is used. 0 = Using Spline Polynomial Approximation. 
The current coefficient tables cover the tested 2-degree, 16-segment
approximation settings. Additional settings can be added through
`create_approx_spline` in `src/utils.cpp`.

### Case Studies Test
```bash
cd build/2pc_test/CASE_STUDIES
./PROX_TEST r=2 p=32003
./PROX_TEST r=3 p=32003
```

There are three test scripts in the folder.

`ULP.cpp` is used to check the accuracy of the trigonometric framework.

`Proximity.cpp` is used to test the proximity testing function.

`Biometric.cpp` contains the biometric authentication driver.

To build a different case-study driver, edit the executable target in
`CASE_STUDIES/CMakeLists.txt`.
