## Installation Note:

Our source code is built based on the [EZPC-LLAMA](https://github.com/mpc-msri/EzPC/tree/master/FSS) framework, and we reuse script codes like ArgMapping from it. Therefore, the complete installation of this framework is necessary, otherwise it is likely to fail to compile or execute.

## Files

Naming rules: Files staring with `2pc` implements dealer-less FSS or its related functions, otherwise, it is modifed from LLAMA framework. Refer to [LLAMA documentation](https://github.com/mpc-msri/EzPC/blob/master/FSS/README.md) for their original usage.

* `deps/` - This directory contains the external code on which our codebase depends, including AES implementation, Millionaire protocol, Oblivious Transfer and other Utils. See respective files for the copyright information.
* `2pc_api.cpp` and `2pc_api.h` - This file contains the implementations of FSS-based building blocks.
* `2pc_cleartext.cpp` and `2pc_cleartext.h` - This file contains the implementations of trigonometric evaluations and case studies under the cleartext (not secret-sharing) values, only for used correctness verification.
* `2pc_dcf.cpp` and `2pc_dcf.h` - This file contains the implementations of dealer-less distributed comparison function (DCF). Note that, the incremental-DPF (iDPF) based DCF, namely `iDCF` in the file, is incorrect and should not be used currently.
* `2pc_idpf.cpp` and `2pc_idpf.h` - This file contains the implementations of dealer-less distributed point function (DPF) and incremental-DPF (iDPF).
* `2pc_math.cpp` and `2pc_math.h` - This file contains the implementations of dealer-less FSS-based trigonometric function and related case studies.
* `2pcwrapper.cpp` and `2pcwrapper.h` - This file contains the wrapper functions for the underlying MPC functionalities in our work.
* `api.cpp` and `api.h` - We modified this file with the reconstruct operation and count the overhead caused by reconstruct operation when it is invoked. 
* `comms.cpp` and`comms.h` - We modified this file with COT (Correlated Oblivious Transfer) invocations and count the overhead caused by COT when it is invoked. 
* `GroupElement.h` - We modified this file with local segment operation and constant multiplication for fixed-point representation.
* `keypack.h` - We modified this file with various key pack classes.
* `utils.cpp` and `utils.h` - We modified this file with LUT construction and other helper functions.

## Protocols

We have implemented the following protocols from the [paper](https://dx.doi.org/10.14722/ndss.2025.242233) in the respective files:

1. Constraint Comparison (Algorithm 1): `cmp_2bit_opt` in `2pcwrapper.cpp`.
2. Dealer-less DPF (Algorithm 2): `keyGenDPF` and `evalDPF` in `2pc_dpf.cpp`. Overloaded functions with batched DPF evaluation are provided. Full domain evaluation is implemented via `evalAll`.
3. Dealer-less DCF, Correlated CW Generation (Algorithm 3, 4): `keyGenNewDCF` and `evalNewDCF` in `2pc_dcf.cpp`, enabling batched evaluation in default (no overloaded function).
4. DPF-based Equality Test (Algorithm 5): `keyGenDPF` and `evalDPF` in `2pc_dpf.cpp`, with the variable `masked = True`.
5. DCF-based Comparison (Algorithm 6): `comparison_offline` and `comparison` in `2pc_api.cpp`. Overloaded functions with batched comparisons are provided.
6. Truncate and Reduce (Algorithm 7): `truncate_and_reduce_offline` and `truncate_and_reduce` in `2pc_api.cpp`.
7. Secure Containment (Algorithm 8): `containment_offline` and `containment` in `2pc_api.cpp`.
8. Secure Digit Decomposition Protocol (Algorithm 9): `digdec_offline` and `digdec` in `2pc_api.cpp`.
9. Public Lookup Table Protocol (Algorithm 10): `pub_lut_offline` and `pub_lut` in `2pc_api.cpp`.
10. Private Lookup Table Protocol (Algorithm 11): `pri_lut_offline` and `pri_lut` in `2pc_api.cpp`.
11. Secure Spline Polynomial Approximation Protocol (Algorithm 12): `spline_poly_approx_offline` and `spline_poly_approx` in `2pc_api.cpp`.
12. Secure Sine Protocol (Algorithm 13): `sine_offline` and `sine` in `2pc_math.cpp`.
13. Secure Cosine Protocol: `cosine_offline` and `cosine` in `2pc_math.cpp`.
14. Secure Tangent Protocol (Algorithm 16): `tangent_offline` and `tangent` in `2pc_math.cpp`.
15. Proximity Test and Biometric Authentication: `proximity(_offline)` and `biometric(_offline)` in `2pc_math.cpp`.

For the detailed usage, please refer to the `2pc_test` folder.

