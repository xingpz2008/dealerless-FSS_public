# Source Layout

The source code builds against the FSS/SCI stack from
[EzPC](https://github.com/mpc-msri/EzPC). The root CMake build creates a
build-tree overlay so existing EzPC/FSS include conventions continue to work.

## Directories

The source tree is organized by role. The repository root `src/` directory is
kept free of protocol `.cpp`/`.h` files; the root CMake build assembles a
build-tree overlay that still provides old include names for compatibility.

* `commons/` - This directory contains dFSS-wide types, `GroupElement`,
  public material helpers, common utilities, and key material used by the new
  dFSS library.
* `mpc/` - This directory contains low-level runtime support: communication,
  reconstruct/opening, COT accounting, MUX, Boolean gates, bit decomposition,
  Beaver multiplication, and B2A.
* `fss/` - This directory contains the reorganized dFSS FSS core: ordinary
  GGM, correlated GGM, payload conversion, DPF, iDPF, and shared-input wrapper
  APIs.
* `buildingblock/` - This directory contains reorganized dFSS building blocks
  such as equality, MIC, LUT, ring extension, signed ring extension, modular
  reduction, digit decomposition, and truncation. It also contains the new
  comparison API.
* `math/` - This directory contains reorganized dFSS math APIs such as generic
  MIC-based PolyEval and generic LUT-based evaluation.
* `legacy/` - This directory contains old NDSS-compatible baseline code that
  is not part of the new dFSS library, including the original global DPF entry
  point, DCF, old trigonometric/case study math, DCF-based comparison,
  old legacy-only key material, and the old spline approximation baseline.

## New dFSS Library

The reorganized library is limited to the new dFSS protocols and building
blocks whose bottom FSS layer is decoupled from the old NDSS implementation.

1. FSS core: `fss/dpf.*`, `fss/idpf.*`, and `fss/internal/*`.
2. Shared-input FSS wrappers: `fss/fss_wrapper.*`.
3. Equality: `buildingblock/equality.*`.
4. MIC: `buildingblock/mic.*`.
5. Comparison: `buildingblock/comparison.*`. In the new library,
   `comparison` means the new dFSS comparison; the old DCF construction is
   exposed as `dfss::legacy::legacyComparisonOffline` and
   `dfss::legacy::legacyComparison`.
6. Ring extension, truncation, modular reduction, and digit
   decomposition: `buildingblock/comparison.*`,
   `buildingblock/ring_extension.*`,
   `buildingblock/truncation.*`, `buildingblock/modular.*`,
   `buildingblock/digit_decomposition.*`.
   These blocks use the new comparison.
7. Generic LUT and polynomial evaluation:
   `buildingblock/lut.*`, `math/luteval.*`, and `math/polyeval.*`.

## Legacy And Compatibility

The following code is retained for compatibility or baseline comparison only.
It is not part of the new dFSS library and must not be included from new
`fss/`, `buildingblock/`, or `math/` implementations.

1. Old DCF-based comparison and old comparison-based ring extension:
   `legacy/comparison.*`.
2. Old interval containment baseline: `legacy/containment.*`.
3. Raw-table public LUT used by old trigonometric code: `legacy/lut.*`.
4. Old public-coefficient spline approximation baseline:
   `legacy/spline_approx.*`.
5. Old global DPF entry point: `legacy/dpf.*`.
6. Old NDSS/EzPC math code, including trigonometric functions and case
   studies: `legacy/math.*` and related original files.
7. Old key material that is not part of the new dFSS API:
   `legacy/keypack.h`.

For detailed usage, see `docs/developer-usage.md` and the `test` folder.
