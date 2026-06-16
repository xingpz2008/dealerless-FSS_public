# Legacy Layout

This directory owns the isolated legacy baseline code.

- `correctness/`: legacy correctness target and legacy-local test helpers.
- `benchmark/`: old NDSS/EzPC-style benchmark drivers.
- `dpf.*`, `dcf.*`, `comparison.*`, `containment.*`, `lut.*`,
  `spline_approx.*`, and `math.*`: old NDSS-compatible protocol and
  application code retained for compatibility and baseline comparisons.

Run legacy correctness from the repository root with:

```bash
src/legacy/scripts/run_legacy_correctness.sh --case 0
```

The dFSS-facing `test/` directory does not own or dispatch legacy correctness.
New dFSS code should include headers from `fss/`, `buildingblock/`, or `math/`
instead of depending on `src/legacy`.
