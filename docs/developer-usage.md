# Developer Usage Guide

This guide is for developers who want to call or extend the dealerless FSS
implementation. It focuses on the public C++ interface, runtime setup, key
lifetime, testing, and performance boundaries.

## Build and Link

Dealerless FSS builds against a local EzPC checkout. Configure from the
repository root:

```bash
cmake -S . -B build \
    -DEZPC_ROOT=/path/to/EzPC \
    -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

If EzPC and this repository are sibling directories, `EZPC_ROOT` defaults to
`../EzPC`:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

This source tree exports three CMake targets:

- `dfss_common`: shared runtime, communication, common types, and low-level MPC helpers.
- `dfss`: the new dFSS primitives, building blocks, and math layer.
- `dfss_legacy`: old NDSS/EzPC-compatible code kept for baseline and compatibility tests.

A small local test or downstream example that uses the new dFSS APIs should
link `dfss`:

```cmake
set(DEALERLESS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
add_subdirectory(/path/to/dealerless-FSS_public dealerless-fss)

add_executable(my_protocol my_protocol.cpp)
target_link_libraries(my_protocol PRIVATE dfss)
```

`dfss` brings in `dfss_common` transitively. Link `dfss_common` directly only
for helper/runtime tests that do not call FSS or building-block APIs. Link
`dfss_legacy` only for the isolated legacy baselines.

## Runtime Model

Most APIs assume a two-party online runtime:

| Party | Constant | Command-line role |
| --- | --- | --- |
| Server | `SERVER` / `2` | `r=2` |
| Client | `CLIENT` / `3` | `r=3` |

Both parties run the same executable with the same port. The server starts
first and waits for the client:

```bash
./my_protocol r=2 p=32000
./my_protocol r=3 p=32000
```

The public tests define the process-wide runtime variables expected by the
imported EzPC/FSS compatibility layer:

```cpp
#include "buildingblock/comparison.h"
#include "buildingblock/lut.h"
#include "legacy/dcf.h"
#include "legacy/dpf.h"
#include "ArgMapping.h"
#include "mpc/comms.h"

using namespace sci;
using namespace dfss;

int party_instance = 0;
int party = 0;
int32_t bitlength = 32;
int num_threads = 1;
int port = 32000;
std::string address = "127.0.0.1";
int num_argmax = 1000;
uint8_t choice_bit = 0;
bool verbose = false;
int length = 1;
Peer* client = nullptr;
Peer* server = nullptr;
Dealer* dealer = nullptr;
Peer* peer = nullptr;
```

Initialize the network peer before calling online APIs:

```cpp
ArgMapping amap;
amap.arg("r", party, "Role: 2=server, 3=client");
amap.arg("p", port, "Port");
amap.parse(argc, argv);

if (party == SERVER) {
    client = waitForPeer(port);
    peer = client;
} else if (party == CLIENT) {
    server = new Peer(address, port);
    peer = server;
}
```

The examples in `test` and `src/legacy/benchmark` are the best reference for
complete `main` functions, argument parsing, and cleanup.

## Sharing Conventions

Values are represented as `GroupElement(value, bitsize)` in rings modulo
`2^bitsize`. Protocol inputs and outputs are additive shares unless a function
explicitly says the value is public.

Common test helpers:

```cpp
GroupElement public_share(uint64_t value, int bitsize) {
    return GroupElement(value * static_cast<uint64_t>(party - SERVER), bitsize);
}

GroupElement split_share(uint64_t value, int bitsize, uint64_t server_share) {
    if (party == SERVER) {
        return GroupElement(server_share, bitsize);
    }
    return GroupElement(value - server_share, bitsize);
}
```

## API Layers

The public surface is split into a few practical layers:

| Layer | Headers | Typical use |
| --- | --- | --- |
| Legacy FSS primitives | `legacy/dpf.h`, `legacy/dcf.h` | Legacy DPF/DCF key generation and evaluation. |
| Building blocks | `buildingblock/*.h` | Comparison, ring extension, truncation, equality, MIC, and LUT. |
| New math | `math/*.h` | Generic LUT evaluation and MIC-based polynomial evaluation. |
| Legacy math helpers | `legacy/math.h` | Trigonometric and case-study math helpers. |
| Low-level wrappers | `mpc/secure_ops.h`, `comms.h` | OT-backed mux, bit operations, Beaver multiplication, peer communication. |

For new protocol code, include the header from the layer that owns the
function. Avoid adding a central compatibility entry point.

## Protocol Summary

The implementation covers the following protocol families:

| Protocol | Public entry points | Header | Notes |
| --- | --- | --- | --- |
| Constraint comparison | `cmp_2bit_opt` | `mpc/secure_ops.h` | Low-level 2-bit comparison helper used by higher-level code. |
| Legacy dealerless DPF | `keyGenDPF`, `evalDPF`, `evalAll` | `legacy/dpf.h` | Scalar, batch, and full-domain evaluation are available. |
| Legacy dealerless DCF | `keyGenNewDCF`, `evalNewDCF` | `legacy/dcf.h` | `evalNewDCF` is batch-oriented by default. |
| Legacy DCF comparison | `legacyComparisonOffline`, `legacyComparison` | `legacy/comparison.h` | Baseline only. |
| Equality | `equalityOffline`, `equality`, `equalityBit`, `equalityBlock` | `buildingblock/equality.h` | Wrapper over correlated DPF. |
| Comparison | `comparisonOffline`, `comparison`, `comparisonBit` | `buildingblock/comparison.h` | New dFSS comparison. |
| Ring extension | `ringExtendOffline`, `ringExtend` | `buildingblock/comparison.h` | Uses the new comparison path. |
| Modular reduction | `modularOffline`, `modular` | `buildingblock/modular.h` | Intended for reducing an input known to be smaller than `2N`. |
| Truncation | `truncateOffline`, `truncate` | `buildingblock/truncation.h` | Truncates by `s` bits and adjusts the ring size. |
| Legacy containment | `containmentOffline`, `containmentOfflinePublic`, `containment` | `legacy/containment.h` | Baseline/compatibility interval containment. Do not include it from new dFSS code. |
| Digit decomposition | `digdecOffline`, `digdec` | `buildingblock/digit_decomposition.h` | Splits an input into fixed-width digit shares. |
| Public LUT | `publicLutOffline`, `publicLut` | `buildingblock/lut.h` | Table is public; lookup index is shared. |
| Private LUT | `privateLutOffline`, `privateLut` | `buildingblock/lut.h` | Table entries are shared/private. |
| Legacy spline approximation | `splinePolyApproxOffline`, `splinePolyApprox` | `legacy/spline_approx.h` | Baseline only. |
| Legacy trigonometric functions | `sine`, `cosine`, `tangent` and offline variants | `legacy/math.h` | Supports LUT and spline-approximation modes. |
| Legacy case studies | `proximity`, `biometric` and offline variants | `legacy/math.h` | Built on the trigonometric framework. |

The legacy DCF header exposes `keyGenNewDCF` and `evalNewDCF`; new
correctness-sensitive code should use those entry points.

## Low-Level Wrapper Usage

`mpc/secure_ops.h` exposes lower-level MPC helpers that are used by the public
building blocks. They are useful when implementing a new protocol, but ordinary
applications should prefer the higher-level headers in `buildingblock/`,
`math/`, and `legacy/math.h` only for legacy baselines.

Constraint comparison compares two shared bits encoded as high/low components:

```cpp
u8 out = cmp_2bit_opt(party, high_bit_share, low_bit_share, peer);
```

Boolean wrappers and multiplexers are available in scalar and batch forms:

```cpp
u8 z = and_wrapper(party, x_bit_share, y_bit_share, peer);
u8 w = or_wrapper(party, x_bit_share, y_bit_share, peer);

GroupElement selected =
    multiplexer2(party, control_bit_share, left_share, right_share, peer);
```

Beaver multiplication has explicit offline and online phases:

```cpp
GroupElement a(-1, Bout), b(-1, Bout), c(-1, Bout);
beaver_mult_offline(party, &a, &b, &c, peer, 1);

GroupElement product =
    beaver_mult_online(party, x_share, y_share, a, b, c, peer);
```

For many independent products, use the batch overloads with caller-owned
vectors rather than looping over scalar calls.

## DPF Usage

For shared target and shared query values, use the wrapper API. The wrapper
handles BitDec, masking, and dispatch to the FSS core:

```cpp
constexpr int Bin = 8;
constexpr int Bout = 16;

GroupElement alpha = split_share(42, Bin, 7);
GroupElement beta = split_share(1234, Bout, 99);
GroupElement query = split_share(42, Bin, 13);

DPFKeyPack key = dfss::wrapper::keyGenDPF(party, alpha, beta);
GroupElement out = dfss::wrapper::evalDPF(party, query, key);

reconstruct(&out);
```

The FSS-core `dfss::keyGenDPF` API is lower level: it expects Boolean shares of
the target bits and evaluates on public query points. New building blocks should
prefer `dfss::wrapper::*` unless they are explicitly testing or benchmarking the
FSS primitive itself.

`evalAllDPF` evaluates the full domain without repeatedly calling scalar
`evalDPF`, but it must materialize `2^length` outputs. Call it before releasing
the key:

```cpp
std::vector<GroupElement> domain(1ULL << Bin, GroupElement(0, Bout));
dfss::wrapper::evalAllDPF(party, domain.data(), key);
freeDPFKeyPack(key);
```

Use point or batch evaluation for large domains. Full-domain `evalAllDPF` is not
an appropriate interface for a 32-bit domain because the output itself would
contain `2^32` entries.

For shared-input equality, use the building-block offline/online pair. The
plain `equality` output is arithmetic; use `equalityBit` for a 0/1 XOR bit and
`equalityBlock` for an XOR block payload.

```cpp
EqualityKey key = equalityOffline(party, alpha, beta);
GroupElement y = equality(party, query_share, key);
freeEqualityKey(key);
```

The implementation goes through `fss_wrapper`, which handles shared-input
masking, BitDec, and Boolean-share inputs before calling the FSS core. New
building-block or math code should not call DPF/iDPF core APIs directly.

## DCF and Comparison Usage

Use `keyGenNewDCF` and `evalNewDCF` for correctness-sensitive DCF code.

`evalNewDCF` is a batch interface. For one query, pass arrays of length one:

```cpp
constexpr int Bin = 8;
constexpr int Bout = 16;

newDCFKeyPack key = keyGenNewDCF(
    party, Bin, Bout,
    split_share(64, Bin, 11),
    split_share(1, Bout, 3));

GroupElement query[1] = {split_share(21, Bin, 5)};
GroupElement result[1] = {GroupElement(0, Bout)};
newDCFKeyPack keys[1] = {key};

evalNewDCF(party, result, query, keys, 1, Bin);
reconstruct(1, result, Bout);
freeNewDCFKeyPack(key);
```

For comparisons, generate the offline key once and use the online function for
the query:

```cpp
ComparisonKeyPack key =
    comparisonOffline(party, Bin, Bout, public_share(1, Bout));

GroupElement y = comparison(party, split_share(21, Bin, 5), 64, key);
reconstruct(&y);
freeComparisonKeyPack(key);
```

When evaluating many comparisons, use the batch `comparison` overload with
pointer-plus-size buffers instead of a loop of scalar calls.

## Building-Block Usage

Most building blocks follow the same shape:

1. Generate an offline key pack with matching bit lengths and public parameters.
2. Call the online function with shared inputs and the key pack.
3. Release the key pack with the matching `free*KeyPack` helper when early
   release is desired.

### Ring Extension

Use unsigned ring extension when a shared value must move from a smaller ring to
a larger ring while preserving the represented unsigned value. The unsigned API
is declared in `buildingblock/comparison.h`:

```cpp
ComparisonKeyPack key = ringExtendOffline(party, Bin, Bout);
GroupElement y = ringExtend(party, x_share, Bout, key);
freeComparisonKeyPack(key);
```

Signed two's-complement ring extension is a separate API declared in
`buildingblock/ring_extension.h`:

```cpp
SignedRingExtensionKeyPack key =
    signedRingExtendOffline(party, Bin, Bout);
GroupElement y = signedRingExtend(party, x_share, Bout, key);
freeSignedRingExtensionKeyPack(key);
```

### Modular Reduction

`modular` reduces an input modulo public `N`, assuming the input is less than
`2N`:

```cpp
const int N = 64;
ModularKeyPack key = modularOffline(party, GroupElement(N, Bin), Bout);
GroupElement y = modular(party, x_share, N, key);
freeModularKeyPack(key);
```

### Truncation

`truncate` truncates `s` low bits and returns a share in the smaller ring:

```cpp
const int s = 5;
TRKeyPack key = truncateOffline(party, Bin, s);
GroupElement y = truncate(party, x_share, s, key);
freeTRKeyPack(key);
```

### Legacy Containment

Containment evaluates which interval contains a shared input. The online output
buffer must have `knots_size + 1` entries:

```cpp
std::vector<GroupElement> knots = {
    GroupElement(8, Bout),
    GroupElement(16, Bout),
    GroupElement(24, Bout),
};
ContainmentKeyPack key =
    dfss::legacy::containmentOfflinePublic(
        party, Bout, knots.data(), knots.size());

std::vector<GroupElement> indicators(knots.size() + 1, GroupElement(0, Bout));
dfss::legacy::containment(
    party, x_share, indicators.data(), knots.size(), key);
freeContainmentKeyPack(key);
```

Use `dfss::legacy::containmentOffline` when the knots are shared rather than
public.

### Digit Decomposition

Digit decomposition splits one shared input into chunks of `NewBitSize` bits.
The output buffer length is `ceil(Bin / NewBitSize)`:

```cpp
const int NewBitSize = 4;
const int digit_count = (Bin + NewBitSize - 1) / NewBitSize;

DigDecKeyPack key = digdecOffline(party, Bin, NewBitSize);
std::vector<GroupElement> digits(digit_count, GroupElement(0, NewBitSize));
digdec(party, x_share, digits.data(), NewBitSize, key);
freeDigDecKeyPack(key);
```

### Public and Private Lookup Tables

For a public table, the table entries are local public values and the lookup
index is shared:

```cpp
PublicLUTData table = generatePublicLUT(idx_bitlen, lut_bitlen, [](uint64_t x) {
    return 3 * x + 1;
});
std::vector<GroupElement> shifted(table.values.size());

PublicLutOptions options;
options.early_termination = true;  // false selects full-domain correlated DPF.
PublicLutKeyPack key = publicLutOffline(party, table, options);
GroupElement y = publicLut(party, idx_share, table, key, shifted.data());
freePublicLutKeyPack(key);
```

For a private table, pass the caller-owned shared table entries to the offline
key generation:

```cpp
std::vector<GroupElement> private_table(table_size, GroupElement(0, lut_bitlen));
PrivateLutKey key =
    privateLutOffline(party, idx_bitlen, lut_bitlen, private_table.data());
GroupElement y = privateLut(party, idx_share, key);
freePrivateLutKey(key);
```

### Spline Polynomial Approximation

Spline approximation uses public polynomial coefficients. The coefficient list
has `(degree + 1) * segNum` entries:

```cpp
std::vector<GroupElement> coefficients((degree + 1) * segNum);
create_approx_spline(uuid, Bout, scale, coefficients.data());

SplinePolyApproxKeyPack key = dfss::legacy::splinePolyApproxOffline(
    party, Bin, Bout, coefficients.data(), degree, segNum, scale);
GroupElement y = dfss::legacy::splinePolyApprox(party, x_share, key);
freeSplinePolyApproxKeyPack(key);
```

The helper `create_approx_spline` constructs supported coefficient tables from
the repository's approximation data. See `src/legacy/utils.cpp` and
`src/legacy/benchmark/buildingblock/BuildingBlock_Test.cpp` for supported
`uuid`, degree, and segment settings.

## Trigonometric and Case-Study Usage

The trigonometric APIs use fixed-point `GroupElement` values. `scale` is the
number of fractional bits used by the approximation framework.

```cpp
const bool using_lut = true;
const int digdec_new_bitsize = 3;
const int approx_segNum = 16;
const int approx_deg = 2;

SineKeyPack key = sine_offline(
    party, Bin, Bout, scale, using_lut,
    digdec_new_bitsize, approx_segNum, approx_deg);
GroupElement y = sine(party, x_share, key);
freeSineKeyPack(key);
```

Cosine follows the same parameter shape:

```cpp
CosineKeyPack key = cosine_offline(
    party, Bin, Bout, scale, using_lut,
    digdec_new_bitsize, approx_segNum, approx_deg);
GroupElement y = cosine(party, x_share, key);
freeCosineKeyPack(key);
```

Tangent does not take `digdec_new_bitsize` in the current public signature:

```cpp
TangentKeyPack key = tangent_offline(
    party, Bin, Bout, scale, using_lut, approx_segNum, approx_deg);
GroupElement y = tangent(party, x_share, key);
freeTangentKeyPack(key);
```

The proximity helper builds on the same trigonometric components:

```cpp
ProximityKeyPack key = proximity_offline(
    party, Bin, scale, using_lut,
    digdec_new_bitsize, approx_segNum, approx_deg);
GroupElement is_close =
    proximity(party, xA_share, yA_share, xB_share, yB_share, key);
freeProximityKeyPack(key);
```

The current public `biometric` entry point is a case-study interface for the
biometric-authentication driver. Its signature keeps an output pointer for
integration, while the public performance driver currently passes `nullptr` and
measures the invoked tangent subprotocols:

```cpp
BiometricKeyPack key =
    biometric_offline(party, Bin, scale, using_lut, approx_segNum, approx_deg);
biometric(party, xA_share, yA_share, xB_share, yB_share, nullptr, key);
freeBiometricKeyPack(key);
```

## Key and Buffer Lifetime

Key packs returned by offline/key-generation APIs own their internal key arrays
through RAII-backed key storage. Copies are cheap and share the same key material.
Do not manually delete fields inside a key pack.

Use the provided reset/free helpers when you want to release key material before
the end of scope:

```cpp
freeDPFKeyPack(dpf_key);
freeNewDCFKeyPack(dcf_key);
freeComparisonKeyPack(comparison_key);
```

Many protocol APIs still use raw pointers for non-owning buffers. In this code
base, that means:

| Pointer shape | Meaning |
| --- | --- |
| `const T* data, int size` | Read-only caller-owned array. |
| `T* output, int size` | Caller-owned output or in-place array. |
| `Peer* peer` | Non-owning runtime session pointer. |

Allocate these buffers with normal C++ containers in new code and pass
`.data()` at the API boundary:

```cpp
std::vector<GroupElement> queries(n);
std::vector<GroupElement> outputs(n, GroupElement(0, Bout));
std::vector<newDCFKeyPack> keys(n);

evalNewDCF(party, outputs.data(), queries.data(), keys.data(), n, Bin);
```

## Performance Guidelines

- Build in `Release` mode for benchmarks or real experiments.
- Prefer batch APIs when evaluating many independent DPF/DCF/comparison queries.
- Do not replace full-domain `evalAll` with repeated scalar `evalDPF`; `evalAll`
  expands the binary tree directly and shares prefix work.
- Avoid `evalAll` for large domains. Its memory and output size are exponential
  in `length`.
- Keep offline and online phases separated when adding a new building block.
  Offline key generation may be more expensive, but online communication and
  rounds should remain visible in the API.
- Use `OMP_NUM_THREADS` to control OpenMP-backed primitive expansion during
  benchmarks. More threads are not always faster, so compare with one thread for
  a new workload.

## Extending the Code

For source-tree layout and ownership rules, see `src/README.md`,
`test/README.md`, and `src/legacy/README.md`.

When adding a new building block:

1. Define any offline key material in `keypack.h`.
2. Use `KeyArray<T>` or `makeKeyArray<T>()` for key-owned arrays.
3. Use `std::vector`, `std::array`, or `std::unique_ptr` for local owned storage.
4. Prefer `const&` for required scalar inputs and `const T*` for read-only arrays.
5. Keep output arrays as `T*` plus an explicit size when the existing API style
   needs a batch buffer.
6. Put offline/key-generation logic and online evaluation in separate functions.
7. Add correctness coverage under the matching suite in
   `test/correctness` when behavior changes or a new public primitive
   is added. Use the dFSS suite for new dFSS APIs and the helper suite for
   protocol-neutral helpers. Legacy-exposed APIs are tested under
   `src/legacy/correctness` via
   `src/legacy/scripts/run_legacy_correctness.sh`.

Building blocks should use a `*_offline` key-generation function and an online
function with the same base name. Reserve `keyGenX`, `evalX`, and `evalAllX`
for primitive FSS code.

For random protocol masks or key material, use the repository's cryptographic
PRNG helpers, such as `secure_prng()` and `random_ge_from_prng()`, instead of
`rand()`, time-based seeds, or deterministic test-only randomness.

## Validation

Run the public correctness script from the repository root:

```bash
scripts/run_correctness.sh --suite dfss
```

Useful focused cases:

```bash
scripts/run_correctness.sh --suite dfss --case 1      # correlated DPF
scripts/run_correctness.sh --suite dfss --case 4      # DPF-ET
scripts/run_correctness.sh --suite dfss --case 12     # dFSS comparison
scripts/run_correctness.sh --suite dfss --case 16     # MIC PolyEval
scripts/run_correctness.sh --suite helper --case 3    # OHG helper
src/legacy/scripts/run_legacy_correctness.sh --case 2 # legacy DCF
```

Correctness cases are organized by suite:
`test/correctness/correctness.cpp` is the dFSS protocol entry point,
`test/correctness/protocol/` contains dFSS protocol cases,
`test/correctness/helper/` contains helper-only cases, and
`test/correctness/common/` contains shared test utilities. Legacy correctness is
owned by `src/legacy/correctness/Legacy_Correctness_Test.cpp`.

dFSS extension benchmarks live under `test/benchmark/`: `benchmark.cpp` is the
entry point, `helper/` contains CLI/report/metric helpers, `protocol/` contains
main protocol benchmarks, and `microbench/` contains component microbenchmarks.
For direct/manual use, run the C++ benchmark binary with explicit parameters:

```bash
./build/test/benchmark/DFSS_EXT_BENCH \
    role=server port=32000 bench=poly bin=16 scale=8 degree=2 parts=8
./build/test/benchmark/DFSS_EXT_BENCH \
    role=client port=32000 bench=poly bin=16 scale=8 degree=2 parts=8
```

The binary supports main benchmarks
`bench=et|dpf|idpf|lut|mic|comparison|poly|equality` and the
`bench=payload_conversion` microbenchmark. Common parameters are `bin`,
optional `bout` with `bout=bin` by default, `repeat`, `phase=all|offline`, and
`output=table|csv|both`. ET-enabled benchmarks use `et=1 suffix=-1` for the
default suffix and `et=1 suffix=N` for an explicit suffix, including
`suffix=1`. `parts` means interval count for `bench=mic` and segment count for
`bench=poly`. Correctness checks are on by default; pass `correctness=0` or
`skip_correctness=1` for large sweeps where correctness has already been
checked separately.

`scripts/run_dfss_ext_bench.sh` is the two-party runner for local benchmark
runs, raw-log capture, and CSV aggregation. It calls the same explicit C++ CLI,
for example:

```bash
scripts/run_dfss_ext_bench.sh \
    --bench et \
    --bin 8 \
    --repeat 1 \
    --skip-configure \
    --skip-build
```

Payload conversion is compiled into the same binary but remains a
microbenchmark, physically separated under `test/benchmark/microbench/`.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| CMake cannot find EzPC | Pass `-DEZPC_ROOT=/path/to/EzPC` or set `EZPC_ROOT`. |
| One party waits forever | Start `r=2` first, use the same port, and ensure no stale process owns the port. |
| Link errors in a downstream test | Link `dfss`, `dfss_common`, or `dfss_legacy` according to the API layer instead of manually listing source files. |
| Unexpected full-domain memory use | Check whether `evalAll` is being used with a large `length`. |
| Different results across parties | Verify both parties use the same bit lengths, constants, and offline keys. |
