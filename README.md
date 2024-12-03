# Distributed Function Secret Sharing and Applications
Source code and the implementation of the NDSS'25 accepted paper - [_Distributed Function Secret Sharing and Applications_](https://dx.doi.org/10.14722/ndss.2025.242233).

## Introduction
We introduce distributed key generation schemes for FSS-based distributed point function and distributed comparison function,
supporting both input and output to be arithmetic-shared. We further design crucial FSS-based components optimized for online efficiency, serving as the building blocks for advanced protocols.
Finally, we propose a framework leverages the periodic property of trigonometric functions, ubiquitous in scientific computations, reducing the bit length of input during FSS evaluation.

## Contents
This repository consists of the following parts:
- __src__: Implementations for our 2PC FSS scheme and case studies.
- __2pc_test__: Demonstrations for function usage and performance test.

## Installation
***NOTE: Our implementation is built based on [EzPC](https://github.com/mpc-msri/EzPC) and a complete compilation process of EzPC is required.
For any issues occurred during step 1 to 4, please refer to [EzPC troubleshooting](https://github.com/mpc-msri/EzPC/issues).***

1. Clone EzPC repository (At this step, you do not have to clone our repo. If you have already done so, it is recommended to execute ```cd ..```).

```bash
git clone http://github.com/mpc-msri/EzPC/
cd EzPC
```

2. Install dependencies. This installs required tools like `g++`, `cmake`, `boost` and `ocaml`. This takes a long time.

```bash
./setup_env_and_build.sh quick
```

3. Recompile EzPC compiler.

```bash
cd EzPC/EzPC/
eval `opam env`
make
cd ../../
```

4. Compile FSS backend.

```bash
cd FSS/
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=./install -DCMAKE_BUILD_TYPE=Release ../
make install
cd ../../../
```

5. Clone this repository.

```bash
git clone https://github.com/xingpz2008/dealerless-FSS_public.git
```

6. Update our code to LLAMA folder.

```bash
cd EzPC/FSS
cp -r ../../dealerless-FSS_public/* ./
```

7. Recompile LLAMA framework again

```bash
rm -rf ./build
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=./install -DCMAKE_BUILD_TYPE=Release ../
make install
```

## Usage
For detailed useage, refer to `2pc_test` folder.

## Disclaimer
This repository is a proof-of-concept prototype.