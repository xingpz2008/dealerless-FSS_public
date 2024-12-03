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

### DPF (DCF) Test
```bash
cd GEN_TEST
./GEN_TEST r=2 f=0 i=8 o=0
```
Argument:
`r` stands for the party number. For another terminal, execute the same command except `r=3`.
`f` stands for the function type. Function choice: DPF = 0; DCF = 1; DPF-based Equality Test = 2; DCF-based comparison = 3
`i` stands for the input bit length. In our experiment, it indicates that setting `i>18` may lead to unexpected program termination.
`o` stands for the output bit length. In our experiment, it indicates that setting `o>18` may lead to unexpected program termination.