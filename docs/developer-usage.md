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

The CMake target exported inside this source tree is `dealerless_fss`. A small
local test or downstream example can link it as follows:

```cmake
set(DEALERLESS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
add_subdirectory(/path/to/dealerless-FSS_public dealerless-fss)

add_executable(my_protocol my_protocol.cpp)
target_link_libraries(my_protocol PRIVATE dealerless_fss)
```

`dealerless_fss` exposes the dealerless headers, the EzPC FSS overlay headers,
SCI headers, cryptoTools headers, and required link libraries through CMake.

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
#include "2pc_api.h"
#include "2pc_dcf.h"
#include "2pc_idpf.h"
#include "ArgMapping.h"
#include "comms.h"

using namespace sci;

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

The examples in `2pc_test` are the best reference for complete `main`
functions, argument parsing, and cleanup.

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
| FSS primitives | `2pc_idpf.h`, `2pc_dcf.h` | DPF/DCF key generation and evaluation. |
| Building blocks | `2pc_api.h` | Comparison, ring extension, truncation, containment, LUT, spline approximation. |
| Math helpers | `2pc_math.h` | Trigonometric and case-study math helpers. |
| Low-level wrappers | `2pcwrapper.h`, `comms.h` | OT-backed mux, bit operations, Beaver multiplication, peer communication. |

For new protocol code, prefer the building-block APIs in `2pc_api.h` unless you
are changing a primitive or implementing a new building block.

## Protocol Summary

The implementation covers the following protocol families:

| Protocol | Public entry points | Header | Notes |
| --- | --- | --- | --- |
| Constraint comparison | `cmp_2bit_opt` | `2pcwrapper.h` | Low-level 2-bit comparison helper used by higher-level code. |
| Dealerless DPF | `keyGenDPF`, `evalDPF`, `evalAll` | `2pc_idpf.h` | Scalar, batch, and full-domain evaluation are available. |
| Dealerless DCF | `keyGenNewDCF`, `evalNewDCF` | `2pc_dcf.h` | `evalNewDCF` is batch-oriented by default. |
| DPF equality test | `keyGenDPF`, `evalDPF` with `masked=true` | `2pc_idpf.h` | Uses the masked DPF path. |
| DCF comparison | `comparison_offline`, `comparison` | `2pc_api.h` | Scalar and batch online overloads are available. |
| Ring extension | `ring_extend_offline`, `ring_extend` | `2pc_api.h` | Preferred over the deprecated direct `zero_extend` helper. |
| Modular reduction | `modular_offline`, `modular` | `2pc_api.h` | Intended for reducing an input known to be smaller than `2N`. |
| Truncate and reduce | `truncate_and_reduce_offline`, `truncate_and_reduce` | `2pc_api.h` | Truncates by `s` bits and adjusts the ring size. |
| Secure containment | `containment_offline`, `containment_offline_public`, `containment` | `2pc_api.h` | Produces interval-indicator outputs for ordered knots. |
| Digit decomposition | `digdec_offline`, `digdec` | `2pc_api.h` | Splits an input into fixed-width digit shares. |
| Public LUT | `pub_lut_offline`, `pub_lut` | `2pc_api.h` | Table is public; lookup index is shared. |
| Private LUT | `pri_lut_offline`, `pri_lut` | `2pc_api.h` | Table entries are shared/private. |
| Spline approximation | `spline_poly_approx_offline`, `spline_poly_approx` | `2pc_api.h` | Uses public coefficients and shared input. |
| Trigonometric functions | `sine`, `cosine`, `tangent` and offline variants | `2pc_math.h` | Supports LUT and spline-approximation modes. |
| Case studies | `proximity`, `biometric` and offline variants | `2pc_math.h` | Built on the trigonometric framework. |

The deprecated legacy `iDCF` functions remain in the headers for compatibility,
but new correctness-sensitive code should use `keyGenNewDCF` and `evalNewDCF`.

## Low-Level Wrapper Usage

`2pcwrapper.h` exposes lower-level MPC helpers that are used by the public
building blocks. They are useful when implementing a new protocol, but ordinary
applications should prefer the higher-level APIs in `2pc_api.h` and
`2pc_math.h`.

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

Generate a key from shared point `alpha` and shared payload `beta`, then evaluate
it on a query point:

```cpp
constexpr int Bin = 8;
constexpr int Bout = 16;

GroupElement alpha = split_share(42, Bin, 7);
GroupElement beta = split_share(1234, Bout, 99);

DPFKeyPack key = keyGenDPF(party, Bin, Bout, alpha, beta, false);
GroupElement out = evalDPF(party, GroupElement(42, Bin), key, false);

reconstruct(&out);
freeDPFKeyPack(key);
```

`evalAll` evaluates the full domain without repeatedly calling scalar
`evalDPF`, but it must materialize `2^length` outputs. Call it before releasing
the key:

```cpp
std::vector<GroupElement> domain(1 << Bin, GroupElement(0, Bout));
evalAll(party, domain.data(), key, Bin);
```

Use point or batch evaluation for large domains. Full-domain `evalAll` is not an
appropriate interface for a 32-bit domain because the output itself would contain
`2^32` entries.

For DPF-based equality tests, use the same DPF APIs with the default
`masked=true` path:

```cpp
DPFKeyPack key = keyGenDPF(party, Bin, Bout, alpha, beta);
GroupElement y = evalDPF(party, query_share, key);
freeDPFKeyPack(key);
```

## DCF and Comparison Usage

Use `keyGenNewDCF` and `evalNewDCF` for correctness-sensitive DCF code. The
legacy `iDCF` API is kept only for compatibility and is marked deprecated.

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
ComparisonKeyPack key = comparison_offline(
    party, Bin, Bout,
    split_share(64, Bin, 11),
    public_share(1, Bout),
    true);

GroupElement y = comparison(party, split_share(21, Bin, 5), key);
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

Use ring extension when a shared value must move from a smaller ring to a larger
ring while preserving the represented value:

```cpp
ComparisonKeyPack key = ring_extend_offline(party, Bin, Bout);
GroupElement y = ring_extend(party, x_share, Bout, key);
freeComparisonKeyPack(key);
```

### Modular Reduction

`modular` reduces an input modulo public `N`, assuming the input is less than
`2N`:

```cpp
const int N = 64;
ModularKeyPack key = modular_offline(party, GroupElement(N, Bin), Bout);
GroupElement y = modular(party, x_share, N, key);
freeModularKeyPack(key);
```

### Truncate and Reduce

`truncate_and_reduce` truncates `s` low bits and returns a share in the smaller
ring:

```cpp
const int s = 5;
TRKeyPack key = truncate_and_reduce_offline(party, Bin, s);
GroupElement y = truncate_and_reduce(party, x_share, s, key);
freeTRKeyPack(key);
```

### Secure Containment

Containment evaluates which interval contains a shared input. The online output
buffer must have `knots_size + 1` entries:

```cpp
std::vector<GroupElement> knots = {
    GroupElement(8, Bout),
    GroupElement(16, Bout),
    GroupElement(24, Bout),
};
ContainmentKeyPack key =
    containment_offline_public(party, Bout, knots.data(), knots.size());

std::vector<GroupElement> indicators(knots.size() + 1, GroupElement(0, Bout));
containment(party, x_share, indicators.data(), knots.size(), key);
freeContainmentKeyPack(key);
```

Use `containment_offline` when the knots are shared rather than public.

### Digit Decomposition

Digit decomposition splits one shared input into chunks of `NewBitSize` bits.
The output buffer length is `ceil(Bin / NewBitSize)`:

```cpp
const int NewBitSize = 4;
const int digit_count = (Bin + NewBitSize - 1) / NewBitSize;

DigDecKeyPack key = digdec_offline(party, Bin, NewBitSize);
std::vector<GroupElement> digits(digit_count, GroupElement(0, NewBitSize));
digdec(party, x_share, digits.data(), NewBitSize, key);
freeDigDecKeyPack(key);
```

### Public and Private Lookup Tables

For a public table, the table entries are local public values and the lookup
index is shared:

```cpp
const int table_size = 1 << idx_bitlen;
std::vector<GroupElement> table(table_size, GroupElement(0, lut_bitlen));
std::vector<GroupElement> shifted(table_size, GroupElement(0, lut_bitlen));

DPFKeyPack key = pub_lut_offline(party, idx_bitlen, lut_bitlen);
GroupElement y = pub_lut(
    party, idx_share, table.data(), shifted.data(),
    table_size, lut_bitlen, key);
freeDPFKeyPack(key);
```

For a private table, pass the caller-owned shared table entries to the offline
key generation:

```cpp
std::vector<GroupElement> private_table(table_size, GroupElement(0, lut_bitlen));
PrivateLutKey key =
    pri_lut_offline(party, idx_bitlen, lut_bitlen, private_table.data());
GroupElement y = pri_lut(party, idx_share, key);
freePrivateLutKey(key);
```

### Spline Polynomial Approximation

Spline approximation uses public polynomial coefficients. The coefficient list
has `(degree + 1) * segNum` entries:

```cpp
std::vector<GroupElement> coefficients((degree + 1) * segNum);
create_approx_spline(uuid, Bout, scale, coefficients.data());

SplinePolyApproxKeyPack key = spline_poly_approx_offline(
    party, Bin, Bout, coefficients.data(), degree, segNum, scale);
GroupElement y = spline_poly_approx(party, x_share, key);
freeSplinePolyApproxKeyPack(key);
```

The helper `create_approx_spline` constructs supported coefficient tables from
the repository's approximation data. See `src/utils.cpp` and
`2pc_test/BB_TEST/BuildingBlock_Test.cpp` for supported `uuid`, degree, and
segment settings.

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

When adding a new building block:

1. Define any offline key material in `keypack.h`.
2. Use `KeyArray<T>` or `makeKeyArray<T>()` for key-owned arrays.
3. Use `std::vector`, `std::array`, or `std::unique_ptr` for local owned storage.
4. Prefer `const&` for required scalar inputs and `const T*` for read-only arrays.
5. Keep output arrays as `T*` plus an explicit size when the existing API style
   needs a batch buffer.
6. Put offline/key-generation logic and online evaluation in separate functions.
7. Add a public correctness case under `2pc_test/CORRECTNESS_TEST` when behavior
   changes or a new public primitive is added.

For random protocol masks or key material, use the repository's cryptographic
PRNG helpers, such as `secure_prng()` and `random_ge_from_prng()`, instead of
`rand()`, time-based seeds, or deterministic test-only randomness.

## Validation

Run the public correctness script from the repository root:

```bash
scripts/run_correctness.sh
```

Useful focused cases:

```bash
scripts/run_correctness.sh --case 1    # DPF
scripts/run_correctness.sh --case 2    # DCF
scripts/run_correctness.sh --case 3    # comparison
scripts/run_correctness.sh --case 12   # trigonometric helpers
```

Run the safety/performance smoke check after performance-sensitive changes:

```bash
scripts/run_safety_perf.sh \
    --bits 19 \
    --output-bits 16 \
    --repeat 5 \
    --dcf-batch 512 \
    --eval-all-bits 14
```

The helper runs both parties on localhost and writes logs under the configured
build directory.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| CMake cannot find EzPC | Pass `-DEZPC_ROOT=/path/to/EzPC` or set `EZPC_ROOT`. |
| One party waits forever | Start `r=2` first, use the same port, and ensure no stale process owns the port. |
| Link errors in a downstream test | Link `dealerless_fss` instead of manually listing source files. |
| Unexpected full-domain memory use | Check whether `evalAll` is being used with a large `length`. |
| Different results across parties | Verify both parties use the same bit lengths, constants, and offline keys. |
