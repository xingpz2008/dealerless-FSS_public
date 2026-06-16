#!/usr/bin/env python3
"""Verify generated nonlinear materials against signed fixed-point semantics."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import random
import struct
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[1]
sys.path.insert(0, str(SCRIPT_DIR))
sys.path.insert(0, str(REPO_ROOT / "tools" / "polyfit"))

import generate_public_nonlinear_data as nonlinear  # noqa: E402
import generate_piecewise_poly as polyfit  # noqa: E402


PUBLIC_LUT_MAGIC = 0x54464C4255504644
PUBLIC_POLY_MAGIC = 0x594C4F5042555044
PUBLIC_DATA_VERSION = 1


def read_u64(buf: bytes, offset: int) -> Tuple[int, int]:
    return struct.unpack_from("<Q", buf, offset)[0], offset + 8


def load_lut(path: Path) -> Dict:
    buf = path.read_bytes()
    off = 0
    magic, off = read_u64(buf, off)
    version, off = read_u64(buf, off)
    if magic != PUBLIC_LUT_MAGIC or version != PUBLIC_DATA_VERSION:
        raise ValueError(f"invalid LUT header: {path}")
    bin_bits, off = read_u64(buf, off)
    bout, off = read_u64(buf, off)
    count, off = read_u64(buf, off)
    values = []
    for _ in range(count):
        value, off = read_u64(buf, off)
        values.append(value)
    return {"bin": bin_bits, "bout": bout, "values": values}


def load_poly(path: Path) -> Dict:
    buf = path.read_bytes()
    off = 0
    magic, off = read_u64(buf, off)
    version, off = read_u64(buf, off)
    if magic != PUBLIC_POLY_MAGIC or version != PUBLIC_DATA_VERSION:
        raise ValueError(f"invalid poly header: {path}")
    bin_bits, off = read_u64(buf, off)
    bout, off = read_u64(buf, off)
    scale, off = read_u64(buf, off)
    degree, off = read_u64(buf, off)
    segment_count, off = read_u64(buf, off)
    breakpoints = []
    for _ in range(segment_count + 1):
        value, off = read_u64(buf, off)
        breakpoints.append(value)
    coefficients = []
    for _ in range(segment_count * (degree + 1)):
        value, off = read_u64(buf, off)
        coefficients.append(value)
    return {
        "bin": int(bin_bits),
        "bout": int(bout),
        "scale": int(scale),
        "degree": int(degree),
        "breakpoints": breakpoints,
        "coefficients": coefficients,
    }


def resolve_repo_path(path: str | Path) -> Path:
    p = Path(path)
    return p if p.is_absolute() else REPO_ROOT / p


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def segment_for_input(encoded_x: int, breakpoints: Sequence[int]) -> int:
    for idx in range(len(breakpoints) - 1):
        if breakpoints[idx] <= encoded_x < breakpoints[idx + 1]:
            return idx
    raise ValueError(f"input {encoded_x} outside breakpoints")


def floor_div_pow2(value: int, shift: int) -> int:
    if shift == 0:
        return value
    if value >= 0:
        return value >> shift
    return -((-value + (1 << shift) - 1) >> shift)


def eval_poly_fixed(encoded_x: int, poly: Dict) -> Tuple[int, float]:
    segment = segment_for_input(encoded_x, poly["breakpoints"])
    x = polyfit.signed_from_twos(encoded_x, poly["bin"])
    total = 0
    x_power = 1
    stride = poly["degree"] + 1
    for i in range(stride):
        raw = poly["coefficients"][segment * stride + i]
        coeff = polyfit.signed_from_twos(raw, poly["bout"])
        total += (coeff << ((poly["degree"] - i) * poly["scale"])) * x_power
        x_power *= x
    scaled = floor_div_pow2(total, poly["degree"] * poly["scale"])
    encoded = polyfit.twos_from_signed(scaled, poly["bout"])
    real = polyfit.signed_from_twos(encoded, poly["bout"]) / float(1 << poly["scale"])
    return encoded, real


def legal_poly_ranges(metadata: Dict) -> List[Tuple[int, int]]:
    ranges = []
    for segment in metadata.get("segments", []):
        if segment.get("legal", True):
            left, right = segment["encoded_range"]
            if left < right:
                ranges.append((int(left), int(right)))
    return ranges


def excluded_poly_ranges(metadata: Dict) -> List[Tuple[int, int]]:
    ranges = []
    for segment in metadata.get("segments", []):
        if not segment.get("legal", True):
            left, right = segment["encoded_range"]
            if left < right:
                ranges.append((int(left), int(right)))
    return ranges


def in_ranges(value: int, ranges: Sequence[Tuple[int, int]]) -> bool:
    return any(left <= value < right for left, right in ranges)


def range_count(ranges: Sequence[Tuple[int, int]]) -> int:
    return sum(right - left for left, right in ranges)


def percentile(values: Sequence[float], q: float) -> float:
    if not values:
        return float("nan")
    ordered = sorted(values)
    idx = int(math.ceil((q / 100.0) * len(ordered))) - 1
    idx = min(max(idx, 0), len(ordered) - 1)
    return float(ordered[idx])


def row_data_path(row: Dict, metadata: Dict) -> Path:
    return resolve_repo_path(metadata.get("output") or row.get("data_path") or
                             Path(row["metadata_path"]).with_suffix(".bin"))


def iter_material_rows(manifest: Dict) -> Iterable[Dict]:
    for row in manifest.get("rows", []):
        if not str(row.get("status", "")).startswith("ok"):
            continue
        if row.get("format") in ("PublicPiecewisePolyData", "PublicLUTData"):
            yield row


def target_representable(units: int, bout: int) -> bool:
    return -(1 << (bout - 1)) <= units <= (1 << (bout - 1)) - 1


def material_id(metadata: Dict) -> str:
    return f"{metadata['function']}_{metadata['format']}"


def signed_units_from_encoded(encoded: int, bits: int) -> int:
    return polyfit.signed_from_twos(int(encoded), int(bits))


def compute_true(metadata: Dict, specs: Dict[str, nonlinear.FunctionSpec],
                 encoded_x: int) -> Tuple[float, float, int, bool]:
    scale = int(metadata["scale"])
    bin_bits = int(metadata["bin"])
    bout = int(metadata["bout"])
    func = nonlinear.make_function(specs[metadata["function"]].python_expr)
    real_x = polyfit.signed_from_twos(encoded_x, bin_bits) / float(1 << scale)
    true_y_real = func(real_x)
    true_y_units = math.floor(true_y_real * float(1 << scale))
    return real_x, true_y_real, true_y_units, target_representable(true_y_units, bout)


def eval_material_encoded(encoded_x: int, metadata: Dict, material: Dict) -> int:
    if metadata["format"] == "PublicPiecewisePolyData":
        encoded, _ = eval_poly_fixed(encoded_x, material)
        return encoded
    return int(material["values"][encoded_x])


def sample_poly_inputs(metadata: Dict, poly: Dict, samples_per_segment: int) -> List[int]:
    inputs = set()
    legal_by_range = {
        tuple(segment["encoded_range"])
        for segment in metadata.get("segments", [])
        if segment.get("legal", True)
    }
    for left, right in zip(poly["breakpoints"], poly["breakpoints"][1:]):
        if legal_by_range and (left, right) not in legal_by_range:
            continue
        width = right - left
        if width <= 0:
            continue
        count = max(2, min(samples_per_segment, width))
        for i in range(count):
            inputs.add(left + ((width - 1) * i) // (count - 1))
    return sorted(inputs)


def verify_poly(row: Dict, specs: Dict[str, nonlinear.FunctionSpec],
                samples_per_segment: int) -> Dict:
    metadata = json.loads(Path(row["metadata_path"]).read_text(encoding="utf-8"))
    data_path = Path(metadata["output"])
    poly = load_poly(data_path)
    function = specs[metadata["function"]]
    func = nonlinear.make_function(function.python_expr)
    factor = float(1 << poly["scale"])
    max_abs = 0.0
    max_fixed_units = 0
    worst = None
    for encoded_x in sample_poly_inputs(metadata, poly, samples_per_segment):
        real_x = polyfit.signed_from_twos(encoded_x, poly["bin"]) / factor
        target = func(real_x)
        target_units = math.floor(target * factor)
        _, actual_real = eval_poly_fixed(encoded_x, poly)
        actual_units = math.floor(actual_real * factor)
        abs_error = abs(actual_real - target)
        fixed_units = abs(actual_units - target_units)
        if abs_error > max_abs:
            max_abs = abs_error
            worst = {
                "encoded_x": encoded_x,
                "real_x": real_x,
                "target": target,
                "actual_real": actual_real,
            }
        max_fixed_units = max(max_fixed_units, fixed_units)
    return {
        "function": metadata["function"],
        "format": "PublicPiecewisePolyData",
        "data_path": str(data_path),
        "samples": len(sample_poly_inputs(metadata, poly, samples_per_segment)),
        "max_abs_error": max_abs,
        "max_fixed_units": max_fixed_units,
        "worst": worst,
        "manifest_max_abs_error": row.get("accuracy", {}).get("max_abs_error"),
    }


def sample_lut_inputs(lut: Dict, samples: int) -> List[int]:
    count = len(lut["values"])
    inputs = {0, count - 1}
    if count > 2:
        inputs.update({count // 4, count // 2, (3 * count) // 4})
    if samples >= count:
        inputs.update(range(count))
    else:
        for i in range(samples):
            inputs.add(((count - 1) * i) // max(1, samples - 1))
    return sorted(inputs)


def verify_lut(row: Dict, specs: Dict[str, nonlinear.FunctionSpec],
               samples: int) -> Dict:
    metadata = json.loads(Path(row["metadata_path"]).read_text(encoding="utf-8"))
    data_path = Path(row["metadata_path"]).with_suffix(".bin")
    lut = load_lut(data_path)
    function = specs[metadata["function"]]
    func = nonlinear.make_function(function.python_expr)
    factor = float(1 << metadata["scale"])
    max_abs = 0.0
    max_fixed_units = 0
    worst = None
    for encoded_x in sample_lut_inputs(lut, samples):
        real_x = polyfit.signed_from_twos(encoded_x, lut["bin"]) / factor
        target = func(real_x)
        target_units = math.floor(target * factor)
        actual_real = (
            polyfit.signed_from_twos(lut["values"][encoded_x], lut["bout"]) /
            factor
        )
        actual_units = math.floor(actual_real * factor)
        abs_error = abs(actual_real - target)
        fixed_units = abs(actual_units - target_units)
        if abs_error > max_abs:
            max_abs = abs_error
            worst = {
                "encoded_x": encoded_x,
                "real_x": real_x,
                "target": target,
                "actual_real": actual_real,
            }
        max_fixed_units = max(max_fixed_units, fixed_units)
    return {
        "function": metadata["function"],
        "format": "PublicLUTData",
        "data_path": str(data_path),
        "samples": len(sample_lut_inputs(lut, samples)),
        "max_abs_error": max_abs,
        "max_fixed_units": max_fixed_units,
        "worst": worst,
        "manifest_max_abs_error": row.get("accuracy", {}).get("max_abs_error"),
    }


FULL_DOMAIN_FIELDS = [
    "function", "construction", "Bin", "Bout", "scale", "degree",
    "requested_segments", "actual_total_segments", "backend",
    "effective_legal_domain", "legal_input_count", "excluded_input_count",
    "excluded_ranges", "target_unrepresentable_count", "max_abs_error",
    "mean_abs_error", "rmse_abs_error", "max_ulp_error", "mean_ulp_error",
    "p50_ulp", "p90_ulp", "p99_ulp", "worst_encoded_x", "worst_real_x",
    "worst_true_y_real", "worst_true_y_fixed_unbounded",
    "worst_material_y_real", "worst_material_y_fixed", "status",
]

WORST_FIELDS = [
    "function", "encoded_x", "real_x", "true_y_real",
    "true_y_fixed_unbounded", "material_y_real", "material_y_fixed",
    "material_vs_true_abs", "material_vs_true_ulp",
]

PER_INPUT_FIELDS = [
    "encoded_x", "real_x", "true_y_real", "true_y_fixed_unbounded",
    "target_representable", "material_y_encoded", "material_y_fixed",
    "material_y_real", "material_vs_true_ulp", "material_vs_true_abs",
    "status",
]


def summarize_errors(abs_errors: Sequence[float],
                     ulp_errors: Sequence[int]) -> Dict[str, float]:
    if not abs_errors:
        return {
            "max_abs_error": float("nan"),
            "mean_abs_error": float("nan"),
            "rmse_abs_error": float("nan"),
            "max_ulp_error": float("nan"),
            "mean_ulp_error": float("nan"),
            "p50_ulp": float("nan"),
            "p90_ulp": float("nan"),
            "p99_ulp": float("nan"),
        }
    return {
        "max_abs_error": max(abs_errors),
        "mean_abs_error": sum(abs_errors) / len(abs_errors),
        "rmse_abs_error": math.sqrt(sum(x * x for x in abs_errors) / len(abs_errors)),
        "max_ulp_error": max(ulp_errors),
        "mean_ulp_error": sum(ulp_errors) / len(ulp_errors),
        "p50_ulp": percentile(ulp_errors, 50),
        "p90_ulp": percentile(ulp_errors, 90),
        "p99_ulp": percentile(ulp_errors, 99),
    }


def write_full_domain_for_row(row: Dict, specs: Dict[str, nonlinear.FunctionSpec],
                              per_input_dir: Optional[Path]) -> Tuple[Dict, Dict]:
    metadata = json.loads(resolve_repo_path(row["metadata_path"]).read_text(
        encoding="utf-8"))
    data_path = row_data_path(row, metadata)
    if metadata["format"] == "PublicPiecewisePolyData":
        material = load_poly(data_path)
        legal_ranges = legal_poly_ranges(metadata)
        excluded_ranges = excluded_poly_ranges(metadata)
    else:
        material = load_lut(data_path)
        legal_ranges = [(0, len(material["values"]))]
        excluded_ranges = []

    abs_errors: List[float] = []
    ulp_errors: List[int] = []
    worst: Optional[Dict] = None
    target_unrepresentable_count = 0

    per_writer = None
    per_file = None
    if per_input_dir is not None:
        per_input_dir.mkdir(parents=True, exist_ok=True)
        per_file = (per_input_dir /
                    f"{metadata['function']}_{metadata['format']}.csv").open(
                        "w", newline="", encoding="utf-8")
        per_writer = csv.DictWriter(per_file, fieldnames=PER_INPUT_FIELDS)
        per_writer.writeheader()

    for left, right in legal_ranges:
        for encoded_x in range(left, right):
            real_x, true_y_real, true_y_units, representable = compute_true(
                metadata, specs, encoded_x)
            material_encoded = eval_material_encoded(encoded_x, metadata, material)
            material_units = signed_units_from_encoded(
                material_encoded, int(metadata["bout"]))
            material_real = material_units / float(1 << int(metadata["scale"]))
            if not representable:
                target_unrepresentable_count += 1
                status = "target_unrepresentable"
                ulp = ""
                abs_error = ""
            else:
                ulp = abs(material_units - true_y_units)
                abs_error = abs(material_real - true_y_real)
                ulp_errors.append(int(ulp))
                abs_errors.append(float(abs_error))
                status = "ok"
                if worst is None or abs_error > worst["material_vs_true_abs"]:
                    worst = {
                        "function": metadata["function"],
                        "encoded_x": encoded_x,
                        "real_x": real_x,
                        "true_y_real": true_y_real,
                        "true_y_fixed_unbounded": true_y_units,
                        "material_y_real": material_real,
                        "material_y_fixed": material_units,
                        "material_vs_true_abs": abs_error,
                        "material_vs_true_ulp": ulp,
                    }
            if per_writer is not None:
                per_writer.writerow({
                    "encoded_x": encoded_x,
                    "real_x": real_x,
                    "true_y_real": true_y_real,
                    "true_y_fixed_unbounded": true_y_units,
                    "target_representable": representable,
                    "material_y_encoded": material_encoded,
                    "material_y_fixed": material_units,
                    "material_y_real": material_real,
                    "material_vs_true_ulp": ulp,
                    "material_vs_true_abs": abs_error,
                    "status": status,
                })

    if per_file is not None:
        per_file.close()

    summary = summarize_errors(abs_errors, ulp_errors)
    summary.update({
        "function": metadata["function"],
        "construction": metadata["format"],
        "Bin": metadata.get("bin", ""),
        "Bout": metadata.get("bout", ""),
        "scale": metadata.get("scale", ""),
        "degree": metadata.get("degree", ""),
        "requested_segments": metadata.get("requested_legal_segments", ""),
        "actual_total_segments": metadata.get("actual_total_segments", ""),
        "backend": metadata.get("backend_used", ""),
        "effective_legal_domain": json.dumps(metadata.get("effective_legal_domain", "")),
        "legal_input_count": range_count(legal_ranges),
        "excluded_input_count": range_count(excluded_ranges),
        "excluded_ranges": json.dumps(excluded_ranges),
        "target_unrepresentable_count": target_unrepresentable_count,
        "worst_encoded_x": "" if worst is None else worst["encoded_x"],
        "worst_real_x": "" if worst is None else worst["real_x"],
        "worst_true_y_real": "" if worst is None else worst["true_y_real"],
        "worst_true_y_fixed_unbounded": "" if worst is None else worst["true_y_fixed_unbounded"],
        "worst_material_y_real": "" if worst is None else worst["material_y_real"],
        "worst_material_y_fixed": "" if worst is None else worst["material_y_fixed"],
        "status": "ok" if abs_errors else "no_representable_targets",
    })
    return summary, (worst or {"function": metadata["function"]})


def run_full_domain(args: argparse.Namespace) -> int:
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    specs = nonlinear.build_specs()
    summaries = []
    worst_rows = []
    for row in iter_material_rows(manifest):
        summary, worst = write_full_domain_for_row(row, specs, args.per_input_dir)
        summaries.append(summary)
        worst_rows.append(worst)

    if args.summary_csv is not None:
        args.summary_csv.parent.mkdir(parents=True, exist_ok=True)
        with args.summary_csv.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FULL_DOMAIN_FIELDS)
            writer.writeheader()
            for row in summaries:
                writer.writerow({field: row.get(field, "") for field in FULL_DOMAIN_FIELDS})

    if args.worst_points_csv is not None:
        args.worst_points_csv.parent.mkdir(parents=True, exist_ok=True)
        with args.worst_points_csv.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=WORST_FIELDS)
            writer.writeheader()
            for row in worst_rows:
                writer.writerow({field: row.get(field, "") for field in WORST_FIELDS})

    output = args.output or args.manifest.with_name("material_semantic_full_domain.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({
        "manifest": str(args.manifest),
        "mode": "full_domain",
        "rows": summaries,
        "worst": worst_rows,
    }, indent=2), encoding="utf-8")
    print(f"wrote {output}")
    print(f"full-domain rows={len(summaries)}")
    return 0


def add_input_source(sources: Dict[int, set], encoded_x: int, source: str,
                     ranges: Sequence[Tuple[int, int]]) -> None:
    if in_ranges(encoded_x, ranges):
        sources.setdefault(encoded_x, set()).add(source)


def generate_inputs_for_metadata(metadata: Dict, seed: int,
                                 random_samples: int) -> Dict[int, set]:
    ranges = legal_poly_ranges(metadata)
    sources: Dict[int, set] = {}
    for left, right in ranges:
        mid = left + (right - left - 1) // 2
        candidates = [
            (left, "segment_left"),
            (left + 1, "segment_left_plus1"),
            (mid, "segment_mid"),
            (right - 2, "segment_right_minus2"),
            (right - 1, "segment_right_minus1"),
        ]
        for value, label in candidates:
            add_input_source(sources, value, label, ranges)

    for breakpoint in metadata.get("breakpoints", []):
        for delta in range(-2, 3):
            add_input_source(sources, int(breakpoint) + delta,
                             f"breakpoint_{delta:+d}", ranges)

    for signed_value in [-2, -1, 0, 1, 2]:
        encoded = polyfit.twos_from_signed(signed_value, int(metadata["bin"]))
        add_input_source(sources, encoded, f"zero_neighborhood_{signed_value}", ranges)

    total = range_count(ranges)
    rng = random.Random(f"{seed}:{metadata['function']}")
    for _ in range(random_samples):
        offset = rng.randrange(total)
        for left, right in ranges:
            width = right - left
            if offset < width:
                add_input_source(sources, left + offset, "random", ranges)
                break
            offset -= width
    return sources


def run_write_protocol_inputs(args: argparse.Namespace) -> int:
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    args.write_protocol_inputs.mkdir(parents=True, exist_ok=True)
    count = 0
    for row in iter_material_rows(manifest):
        metadata = json.loads(resolve_repo_path(row["metadata_path"]).read_text(
            encoding="utf-8"))
        if metadata["format"] != "PublicPiecewisePolyData":
            continue
        sources = generate_inputs_for_metadata(
            metadata, args.sample_seed, args.random_samples)
        path = args.write_protocol_inputs / f"{metadata['function']}.inputs.csv"
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f, fieldnames=["encoded_x", "input_source", "seed"])
            writer.writeheader()
            for encoded_x in sorted(sources):
                writer.writerow({
                    "encoded_x": encoded_x,
                    "input_source": ";".join(sorted(sources[encoded_x])),
                    "seed": args.sample_seed,
                })
        count += 1
    print(f"wrote protocol input lists for {count} materials to {args.write_protocol_inputs}")
    return 0


PROTOCOL_FIELDS = [
    "function", "Bin", "Bout", "scale", "degree", "requested_segments",
    "actual_total_segments", "material_sha256", "encoded_x", "real_x",
    "input_source", "seed", "secure_y_encoded", "material_y_encoded",
    "secure_y_fixed", "material_y_fixed", "true_y_real",
    "true_y_fixed_unbounded", "target_representable", "secure_y_real",
    "material_y_real", "secure_vs_material_ulp", "secure_vs_true_ulp",
    "secure_vs_true_abs", "material_vs_true_ulp", "material_vs_true_abs",
    "status",
]


def load_input_sources(path: Path) -> Dict[int, Dict[str, str]]:
    result = {}
    with path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            result[int(row["encoded_x"])] = row
    return result


def run_join_protocol(args: argparse.Namespace) -> int:
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    specs = nonlinear.build_specs()
    output_rows = []
    for row in iter_material_rows(manifest):
        metadata = json.loads(resolve_repo_path(row["metadata_path"]).read_text(
            encoding="utf-8"))
        if metadata["format"] != "PublicPiecewisePolyData":
            continue
        function = metadata["function"]
        raw_path = args.join_protocol_csv_dir / function / "raw_protocol.csv"
        inputs_path = args.join_protocol_csv_dir / "inputs" / f"{function}.inputs.csv"
        if not raw_path.is_file():
            continue
        input_sources = load_input_sources(inputs_path)
        material_hash = sha256_file(row_data_path(row, metadata))
        with raw_path.open(newline="", encoding="utf-8") as f:
            for raw in csv.DictReader(f):
                encoded_x = int(raw["encoded_x"])
                secure_encoded = int(raw["secure_y_encoded"])
                material_encoded = int(raw["material_y_encoded"])
                real_x, true_y_real, true_units, representable = compute_true(
                    metadata, specs, encoded_x)
                secure_units = signed_units_from_encoded(
                    secure_encoded, int(metadata["bout"]))
                material_units = signed_units_from_encoded(
                    material_encoded, int(metadata["bout"]))
                factor = float(1 << int(metadata["scale"]))
                secure_real = secure_units / factor
                material_real = material_units / factor
                secure_vs_material = abs(secure_units - material_units)
                status = "ok"
                if secure_vs_material != 0:
                    status = "protocol_material_mismatch"
                elif not representable:
                    status = "target_unrepresentable"
                src = input_sources.get(encoded_x, {})
                output_rows.append({
                    "function": function,
                    "Bin": metadata.get("bin", ""),
                    "Bout": metadata.get("bout", ""),
                    "scale": metadata.get("scale", ""),
                    "degree": metadata.get("degree", ""),
                    "requested_segments": metadata.get("requested_legal_segments", ""),
                    "actual_total_segments": metadata.get("actual_total_segments", ""),
                    "material_sha256": material_hash,
                    "encoded_x": encoded_x,
                    "real_x": real_x,
                    "input_source": src.get("input_source", ""),
                    "seed": src.get("seed", ""),
                    "secure_y_encoded": secure_encoded,
                    "material_y_encoded": material_encoded,
                    "secure_y_fixed": secure_units,
                    "material_y_fixed": material_units,
                    "true_y_real": true_y_real,
                    "true_y_fixed_unbounded": true_units,
                    "target_representable": representable,
                    "secure_y_real": secure_real,
                    "material_y_real": material_real,
                    "secure_vs_material_ulp": secure_vs_material,
                    "secure_vs_true_ulp": abs(secure_units - true_units),
                    "secure_vs_true_abs": abs(secure_real - true_y_real),
                    "material_vs_true_ulp": abs(material_units - true_units),
                    "material_vs_true_abs": abs(material_real - true_y_real),
                    "status": status,
                })

    args.output_protocol_sampled_csv.parent.mkdir(parents=True, exist_ok=True)
    with args.output_protocol_sampled_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PROTOCOL_FIELDS)
        writer.writeheader()
        for row in output_rows:
            writer.writerow({field: row.get(field, "") for field in PROTOCOL_FIELDS})
    print(f"wrote {args.output_protocol_sampled_csv}")
    print(f"protocol rows={len(output_rows)}")

    if args.paper_summary_csv is not None and args.full_domain_summary_csv is not None:
        write_paper_summary(args.full_domain_summary_csv,
                            args.output_protocol_sampled_csv,
                            args.paper_summary_csv)
    return 0


def write_paper_summary(full_domain_csv: Path, protocol_csv: Path,
                        output_csv: Path) -> None:
    full_rows = {}
    with full_domain_csv.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            full_rows[row["function"]] = row

    protocol_by_function: Dict[str, List[Dict]] = {}
    with protocol_csv.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            protocol_by_function.setdefault(row["function"], []).append(row)

    fields = [
        "function", "profile", "generation_status", "full_domain_point_count",
        "excluded_input_count", "target_unrepresentable_count",
        "material_vs_true_max_ulp", "material_vs_true_mean_ulp",
        "material_vs_true_p50_ulp", "material_vs_true_p90_ulp",
        "material_vs_true_p99_ulp", "material_vs_true_max_abs",
        "material_vs_true_mean_abs", "material_vs_true_rmse_abs",
        "sampled_protocol_point_count", "secure_vs_material_max_ulp",
        "secure_vs_material_all_zero", "status",
    ]
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with output_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for function, full in sorted(full_rows.items()):
            protocol_rows = protocol_by_function.get(function, [])
            secure_ulps = [
                int(float(row["secure_vs_material_ulp"]))
                for row in protocol_rows
                if row.get("secure_vs_material_ulp", "") != ""
            ]
            all_zero = bool(secure_ulps) and max(secure_ulps) == 0
            status = full.get("status", "")
            if secure_ulps and not all_zero:
                status = "protocol_material_mismatch"
            writer.writerow({
                "function": function,
                "profile": "Bin=16,Bout=16,scale=7,degree=3,M=32",
                "generation_status": "ok",
                "full_domain_point_count": full.get("legal_input_count", ""),
                "excluded_input_count": full.get("excluded_input_count", ""),
                "target_unrepresentable_count": full.get("target_unrepresentable_count", ""),
                "material_vs_true_max_ulp": full.get("max_ulp_error", ""),
                "material_vs_true_mean_ulp": full.get("mean_ulp_error", ""),
                "material_vs_true_p50_ulp": full.get("p50_ulp", ""),
                "material_vs_true_p90_ulp": full.get("p90_ulp", ""),
                "material_vs_true_p99_ulp": full.get("p99_ulp", ""),
                "material_vs_true_max_abs": full.get("max_abs_error", ""),
                "material_vs_true_mean_abs": full.get("mean_abs_error", ""),
                "material_vs_true_rmse_abs": full.get("rmse_abs_error", ""),
                "sampled_protocol_point_count": len(protocol_rows),
                "secure_vs_material_max_ulp": max(secure_ulps) if secure_ulps else "",
                "secure_vs_material_all_zero": all_zero,
                "status": status,
            })
    print(f"wrote {output_csv}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path,
                        default=REPO_ROOT / "generated_public_data" /
                        "material_manifest_current.json")
    parser.add_argument("--poly-samples-per-segment", type=int, default=17)
    parser.add_argument("--lut-samples", type=int, default=0,
                        help="0 means exhaustive for current small LUTs")
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--full-domain", action="store_true")
    parser.add_argument("--summary-csv", type=Path, default=None)
    parser.add_argument("--worst-points-csv", type=Path, default=None)
    parser.add_argument("--per-input-dir", type=Path, default=None)
    parser.add_argument("--write-protocol-inputs", type=Path, default=None)
    parser.add_argument("--sample-seed", type=int, default=20260611)
    parser.add_argument("--random-samples", type=int, default=256)
    parser.add_argument("--join-protocol-csv-dir", type=Path, default=None)
    parser.add_argument("--output-protocol-sampled-csv", type=Path, default=None)
    parser.add_argument("--full-domain-summary-csv", type=Path, default=None)
    parser.add_argument("--paper-summary-csv", type=Path, default=None)
    args = parser.parse_args()

    if args.full_domain:
        return run_full_domain(args)
    if args.write_protocol_inputs is not None:
        return run_write_protocol_inputs(args)
    if args.join_protocol_csv_dir is not None:
        if args.output_protocol_sampled_csv is None:
            raise ValueError("--output-protocol-sampled-csv is required with "
                             "--join-protocol-csv-dir")
        return run_join_protocol(args)

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    specs = nonlinear.build_specs()
    rows = []
    for row in manifest["rows"]:
        if row.get("format") == "PublicPiecewisePolyData":
            rows.append(verify_poly(row, specs, args.poly_samples_per_segment))
        elif row.get("format") == "PublicLUTData":
            lut_samples = args.lut_samples
            if lut_samples == 0:
                lut_samples = 1 << int(row["bin"])
            rows.append(verify_lut(row, specs, lut_samples))

    worst = sorted(rows, key=lambda item: item["max_abs_error"], reverse=True)[:10]
    report = {
        "manifest": str(args.manifest),
        "counts": {
            "total": len(rows),
            "poly": sum(1 for row in rows if row["format"] == "PublicPiecewisePolyData"),
            "lut": sum(1 for row in rows if row["format"] == "PublicLUTData"),
        },
        "max_abs_error": max(row["max_abs_error"] for row in rows),
        "max_fixed_units": max(row["max_fixed_units"] for row in rows),
        "worst": worst,
        "rows": rows,
    }
    output = args.output or args.manifest.with_name("material_semantic_verification.json")
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"wrote {output}")
    print(
        f"verified total={report['counts']['total']} "
        f"poly={report['counts']['poly']} lut={report['counts']['lut']}"
    )
    print(
        f"max_abs_error={report['max_abs_error']:.8g} "
        f"max_fixed_units={report['max_fixed_units']}"
    )
    print("worst:")
    for item in worst[:5]:
        print(
            f"  {item['function']} {item['format']} "
            f"err={item['max_abs_error']:.8g} "
            f"fixed_units={item['max_fixed_units']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
