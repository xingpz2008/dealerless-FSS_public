# Usage and Test Case

## Contents
This repository consists of the following parts:
- __GEN_TEST__: Scripts for testing dealer-less DPF/DCF scheme.
- __BB_TEST__: Scripts for testing FSS-based building blocks.
- __TRI_TEST__: Scripts for testing trigonometric evaluation framework.
- __CASE_STUDIES__: Scripts for case studies performance.

## Compilation
```bash
cd [GEN_TEST|BB_TEST|TRI_TEST|CASE_STUDIES]
cmake .
make
```

## Usage
After compilation, there will be a binary executable in the sub-folder. As this is the two party computation (2PC), there should be two independent terminal (may use tmux) 
and execute the following commands.

General Arguments:

`r` stands for the party number. For another terminal, execute the same command except `r=3`.

`f` stands for the function type if the specification of this option is necessary. 

`i` stands for the input bit length. In our experiment, it indicates that setting `i>18` may lead to unexpected program termination.

`o` stands for the output bit length. In our experiment, it indicates that setting `o>18` may lead to unexpected program termination.

`s` stands for the scale under fixed-point arithmetic.

### DPF (DCF) Test
```bash
cd GEN_TEST
./GEN_TEST r=2 f=0 i=8 o=8
```
Argument:

`f` stands for the function type. Function choice: DPF = 0; DCF = 1; DPF-based Equality Test = 2; DCF-based comparison = 3

### Building Block Test
```bash
cd BB_TEST
./BB_TEST r=2 f=0 i=8 o=8 s=5
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
cd TRI_TEST
./SIN_TEST r=2 f=0 i=8 o=8 s=5 l=1
```
Argument:

`f` stands for the function type. Function choice: Sine = 0; Cosine = 1; Tangent = 2

`l` stands for if Lookup Table implementation is used. 0 = Using Spline Polynomial Approximation. 
Note that, we only implement 2-deg-16-segment approximation currently. 
To test other settings, you have to construct the coefficient list first via `create_approx_spline` function from `src/utils.cpp`, which is a little bit complex.

### Case Studies Test
```bash
cd CASE_STUDIES
./PROX_TEST r=2
```

There are three test scripts in the folder.

`ULP.cpp` is used to check the accuracy of out trigonometric framework.

`Proximity.cpp` is used to test proximity testing function.

`Biometric.cpp` is used to test biometric authentication function.

To compile different test script, simply change `add_executable(PROX_TEST {TARGET CPP FILE NAME})` in `CASE_STUDIES/CMakeLists.txt`
