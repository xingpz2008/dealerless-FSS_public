#!/usr/bin/env python3
"""Generate public nonlinear data for the dFSS extension protocols.

This is a higher-level wrapper around the existing PublicLUTData and
PublicPiecewisePolyData binary formats. It chooses function presets, encoded
breakpoints, optional nonuniform grids, approximation parameters, and writes an
accuracy report next to the generated data.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import math
import sys
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[1]
POLYFIT_DIR = REPO_ROOT / "tools" / "polyfit"
sys.path.insert(0, str(POLYFIT_DIR))

import generate_piecewise_poly as polyfit  # noqa: E402


PUBLIC_LUT_MAGIC = 0x54464C4255504644  # DF-PUBLT
PUBLIC_LUT_VERSION = 1


@dataclasses.dataclass(frozen=True)
class FunctionSpec:
    name: str
    python_expr: str
    remez_expr: Optional[str]
    domain: Tuple[float, float]
    default_degrees: Tuple[int, ...]
    default_segments: Tuple[int, ...]
    critical_points: Tuple[float, ...] = ()
    singleton_points: Tuple[float, ...] = ()
    preferred_grid: str = "uniform"
    notes: str = ""


@dataclasses.dataclass
class Segment:
    left: int
    right: int
    legal: bool
    real_left: float
    real_right: float
    fill_value: Optional[float] = None


@dataclasses.dataclass
class CandidateResult:
    ok: bool
    bin_path: Path
    meta_path: Path
    metadata: Dict
    max_abs_error: float
    max_fixed_error: float
    max_fixed_units: int


def build_specs() -> Dict[str, FunctionSpec]:
    def spec(name: str, python_expr: str, remez_expr: Optional[str],
             domain: Tuple[float, float], degrees: Tuple[int, ...],
             segments: Tuple[int, ...], *,
             critical: Tuple[float, ...] = (),
             singleton: Tuple[float, ...] = (),
             grid: str = "uniform", notes: str = "") -> FunctionSpec:
        return FunctionSpec(
            name=name,
            python_expr=python_expr,
            remez_expr=remez_expr,
            domain=domain,
            default_degrees=degrees,
            default_segments=segments,
            critical_points=critical,
            singleton_points=singleton,
            preferred_grid=grid,
            notes=notes,
        )

    specs = [
        spec("sigmoid", "1.0 / (1.0 + exp(-x))",
             "1.0 / (1.0 + exp(-x))", (-8.0, 8.0),
             (2, 3, 4), (16, 32, 64, 128)),
        spec("tanh", "tanh(x)", "tanh(x)", (-8.0, 8.0),
             (2, 3, 4), (16, 32, 64, 128)),
        spec("erf", "erf(x)", "erf(x)", (-4.0, 4.0),
             (2, 3, 4), (16, 32, 64, 128)),
        spec("erfc", "erfc(x)", "erfc(x)", (-4.0, 4.0),
             (2, 3, 4), (16, 32, 64, 128)),
        spec("softplus", "log1p(exp(x))", "log(1.0 + exp(x))",
             (-8.0, 8.0), (2, 3, 4), (16, 32, 64, 128)),
        spec("softminus", "log1p(exp(-x))", "log(1.0 + exp(-x))",
             (-8.0, 8.0), (2, 3, 4), (16, 32, 64, 128)),
        spec("softsign", "x / (1.0 + abs(x))", None, (-8.0, 8.0),
             (2, 3, 4), (16, 32, 64, 128), critical=(0.0,)),
        spec("elu", "x if x >= 0.0 else exp(x) - 1.0", None,
             (-8.0, 8.0), (1, 2, 3), (16, 32, 64, 128),
             critical=(0.0,)),
        spec("celu", "x if x >= 0.0 else exp(x) - 1.0", None,
             (-8.0, 8.0), (1, 2, 3), (16, 32, 64, 128),
             critical=(0.0,),
             notes="CELU alpha is fixed to 1 in this preset."),
        spec("silu", "x / (1.0 + exp(-x))", "x / (1.0 + exp(-x))",
             (-8.0, 8.0), (2, 3, 4), (16, 32, 64, 128)),
        spec("gelu", "0.5 * x * (1.0 + erf(x / sqrt(2.0)))", None,
             (-8.0, 8.0), (2, 3, 4), (16, 32, 64, 128),
             notes="Direct final-function fit; no online erf/multiply composition."),
        spec("mish", "x * tanh(log1p(exp(x)))", None, (-8.0, 8.0),
             (2, 3, 4), (16, 32, 64, 128),
             notes="Direct final-function fit; no online softplus/tanh composition."),
        spec("lecun_tanh", "1.7159 * tanh((2.0 / 3.0) * x)",
             "1.7159 * tanh((2.0 / 3.0) * x)", (-8.0, 8.0),
             (2, 3, 4), (16, 32, 64, 128)),
        spec("tanh_exp", "x * tanh(exp(x))", "x * tanh(exp(x))",
             (-8.0, 4.0), (2, 3, 4), (16, 32, 64, 128)),
        spec("tanhshrink", "x - tanh(x)", "x - tanh(x)", (-8.0, 8.0),
             (2, 3, 4), (16, 32, 64, 128)),
        spec("serf", "x * erf(log1p(exp(x)))", None, (-8.0, 8.0),
             (2, 3, 4), (16, 32, 64, 128)),
        spec("logsigmoid", "-log1p(exp(-x))", "-log(1.0 + exp(-x))",
             (-8.0, 8.0), (2, 3, 4), (16, 32, 64, 128)),
        spec("sin", "sin(x)", "sin(x)", (-math.pi, math.pi),
             (2, 3, 4), (32, 64, 128, 256)),
        spec("cos", "cos(x)", "cos(x)", (-math.pi, math.pi),
             (2, 3, 4), (32, 64, 128, 256)),
        spec("tan", "tan(x)", "tan(x)", (-1.2, 1.2),
             (2, 3, 4), (32, 64, 128, 256),
             notes="Principal-domain preset excludes tangent poles."),
        spec("asin", "asin(x)", "asin(x)", (-1.0, 1.0),
             (2, 3, 4), (32, 64, 128, 256), grid="chebyshev"),
        spec("acos", "acos(x)", "acos(x)", (-1.0, 1.0),
             (2, 3, 4), (32, 64, 128, 256), grid="chebyshev"),
        spec("atan", "atan(x)", "atan(x)", (-8.0, 8.0),
             (2, 3, 4), (32, 64, 128, 256)),
        spec("asinh", "asinh(x)", "asinh(x)", (-8.0, 8.0),
             (2, 3, 4), (32, 64, 128, 256)),
        spec("acosh", "acosh(x)", "acosh(x)", (1.0, 8.0),
             (2, 3, 4), (64, 128, 256, 512), grid="left-geometric"),
        spec("atanh", "atanh(x)", "atanh(x)", (-0.875, 0.875),
             (2, 3, 4), (64, 128, 256, 512), grid="chebyshev"),
        spec("ln", "log(x)", "log(x)", (0.0625, 8.0),
             (2, 3, 4), (64, 128, 256, 512), grid="left-geometric"),
        spec("log2", "log2(x)", "log(x) / log(2.0)", (0.0625, 8.0),
             (2, 3, 4), (64, 128, 256, 512), grid="left-geometric"),
        spec("log10", "log10(x)", "log(x) / log(10.0)", (0.0625, 8.0),
             (2, 3, 4), (64, 128, 256, 512), grid="left-geometric"),
        spec("sqrt", "sqrt(x)", "sqrt(x)", (0.0, 8.0),
             (2, 3, 4), (64, 128, 256, 512), grid="left-geometric"),
        spec("cbrt", "copysign(abs(x) ** (1.0 / 3.0), x)", None,
             (-8.0, 8.0), (2, 3, 4), (64, 128, 256, 512),
             grid="chebyshev", notes="Signed real cube-root preset."),
        spec("reciprocal", "1.0 / x", "1.0 / x", (0.125, 8.0),
             (2, 3, 4), (64, 128, 256, 512), grid="left-geometric"),
        spec("isqrt", "1.0 / sqrt(x)", "1.0 / sqrt(x)", (0.125, 8.0),
             (2, 3, 4), (64, 128, 256, 512), grid="left-geometric"),
        spec("abs", "abs(x)", None, (-8.0, 8.0), (1,), (2,),
             critical=(0.0,)),
        spec("relu", "max(0.0, x)", None, (-8.0, 8.0), (1,), (2,),
             critical=(0.0,)),
        spec("relu6", "min(max(0.0, x), 6.0)", None, (-8.0, 8.0),
             (1,), (3,), critical=(0.0, 6.0)),
        spec("leaky_relu", "x if x >= 0.0 else 0.01 * x", None,
             (-8.0, 8.0), (1,), (2,), critical=(0.0,)),
        spec("relu2", "x*x if x >= 0.0 else 0.0", None, (-8.0, 8.0),
             (2,), (2,), critical=(0.0,)),
        spec("hardsigmoid", "min(max((x + 3.0) / 6.0, 0.0), 1.0)",
             None, (-8.0, 8.0), (1,), (3,), critical=(-3.0, 3.0)),
        spec("hardswish", "x * min(max((x + 3.0) / 6.0, 0.0), 1.0)",
             None, (-8.0, 8.0), (2,), (3,), critical=(-3.0, 3.0)),
        spec("hardtanh", "min(max(x, -1.0), 1.0)", None, (-8.0, 8.0),
             (1,), (3,), critical=(-1.0, 1.0)),
        spec("hardshrink", "x if abs(x) > 0.5 else 0.0", None,
             (-8.0, 8.0), (1,), (3,), critical=(-0.5, 0.5),
             singleton=(0.5,)),
        spec("softshrink", "x - 0.5 if x > 0.5 else (x + 0.5 if x < -0.5 else 0.0)",
             None, (-8.0, 8.0), (1,), (3,), critical=(-0.5, 0.5)),
        spec("signum", "1.0 if x > 0.0 else (-1.0 if x < 0.0 else 0.0)",
             None, (-8.0, 8.0), (0,), (3,), critical=(0.0,),
             singleton=(0.0,)),
        spec("positive", "1.0 if x > 0.0 else 0.0", None,
             (-8.0, 8.0), (0,), (2,), critical=(0.0,),
             singleton=(0.0,)),
        spec("negative", "1.0 if x < 0.0 else 0.0", None,
             (-8.0, 8.0), (0,), (2,), critical=(0.0,),
             singleton=(0.0,)),
        spec("nonnegative", "1.0 if x >= 0.0 else 0.0", None,
             (-8.0, 8.0), (0,), (2,), critical=(0.0,),
             singleton=(0.0,)),
        spec("nonpositive", "1.0 if x <= 0.0 else 0.0", None,
             (-8.0, 8.0), (0,), (2,), critical=(0.0,),
             singleton=(0.0,)),
        spec("zero", "1.0 if x == 0.0 else 0.0", None,
             (-8.0, 8.0), (0,), (3,), critical=(0.0,),
             singleton=(0.0,)),
        spec("nonzero", "0.0 if x == 0.0 else 1.0", None,
             (-8.0, 8.0), (0,), (3,), critical=(0.0,),
             singleton=(0.0,)),
    ]
    return {spec.name: spec for spec in specs}


def parse_int_list(text: str) -> Tuple[int, ...]:
    return tuple(int(part.strip(), 0) for part in text.split(",") if part.strip())


def parse_domain(text: str) -> Tuple[float, float]:
    left, right = text.split(":", 1)
    domain = (float(eval(left, {"__builtins__": {}}, vars(math))),
              float(eval(right, {"__builtins__": {}}, vars(math))))
    if not domain[0] < domain[1]:
        raise ValueError("domain must be left:right with left < right")
    return domain


def signed_range(bin_bits: int) -> Tuple[int, int]:
    return -(1 << (bin_bits - 1)), (1 << (bin_bits - 1))


def signed_to_encoded(value: int, bin_bits: int) -> int:
    return value & ((1 << bin_bits) - 1)


def real_to_signed_floor(value: float, scale: int) -> int:
    return math.floor(value * (1 << scale))


def real_to_signed_ceil(value: float, scale: int) -> int:
    return math.ceil(value * (1 << scale))


def clamp_int(value: int, left: int, right: int) -> int:
    return min(max(value, left), right)


def make_function(expr: str) -> Callable[[float], float]:
    allowed = {
        name: getattr(math, name) for name in dir(math) if not name.startswith("_")
    }
    allowed.update({"abs": abs, "min": min, "max": max, "pow": pow})
    code = compile(expr, "<nonlinear-function>", "eval")

    def func(x: float) -> float:
        return float(eval(code, {"__builtins__": {}}, {**allowed, "x": x}))

    return func


def quantized_real(value: float, scale: int) -> float:
    return math.floor(value * (1 << scale)) / float(1 << scale)


def grid_points(left: int, right: int, parts: int, mode: str) -> List[int]:
    width = right - left
    parts = max(1, min(parts, width))
    if parts == 1:
        return [left, right]

    points = {left, right}
    if mode == "uniform":
        for i in range(1, parts):
            points.add(left + (width * i) // parts)
    elif mode == "chebyshev":
        for i in range(1, parts):
            t = 0.5 * (1.0 - math.cos(math.pi * i / parts))
            points.add(left + int(round(width * t)))
    elif mode in ("left-geometric", "right-geometric"):
        ratio = 1.055
        weights = [ratio ** i for i in range(parts)]
        total = sum(weights)
        prefix = 0.0
        raw = []
        for i in range(1, parts):
            prefix += weights[i - 1]
            t = prefix / total
            if mode == "right-geometric":
                t = 1.0 - t
            raw.append(left + int(round(width * t)))
        points.update(raw)
    else:
        raise ValueError(f"unknown grid mode: {mode}")
    return sorted(p for p in points if left <= p <= right)


def add_critical_points(points: Iterable[int], critical: Sequence[float],
                        scale: int, left: int, right: int) -> List[int]:
    output = set(points)
    for value in critical:
        encoded = round(value * (1 << scale))
        if left < encoded < right:
            output.add(encoded)
    return sorted(output)


def add_singleton_points(points: Iterable[int], singleton: Sequence[float],
                         scale: int, left: int, right: int) -> List[int]:
    output = set(points)
    for value in singleton:
        encoded = round(value * (1 << scale))
        if left < encoded < right:
            output.add(encoded)
        if left < encoded + 1 < right:
            output.add(encoded + 1)
    return sorted(output)


def legal_signed_pieces(domain: Tuple[float, float], bin_bits: int, scale: int,
                        segments: int, grid: str,
                        critical_points: Sequence[float],
                        singleton_points: Sequence[float]) -> List[Tuple[int, int]]:
    range_left, range_right = signed_range(bin_bits)
    left = clamp_int(real_to_signed_ceil(domain[0], scale), range_left, range_right)
    right = clamp_int(real_to_signed_floor(domain[1], scale) + 1,
                      range_left, range_right)
    if left >= right:
        raise ValueError("domain has no representable fixed-point values")

    chunks: List[Tuple[int, int]] = []
    if left < 0:
        chunks.append((left, min(right, 0)))
    if right > 0:
        chunks.append((max(left, 0), right))

    widths = [r - l for l, r in chunks]
    total_width = sum(widths)
    pieces: List[Tuple[int, int]] = []
    remaining_segments = max(1, segments)
    for index, ((chunk_left, chunk_right), width) in enumerate(zip(chunks, widths)):
        if width <= 0:
            continue
        if index == len(chunks) - 1:
            chunk_segments = remaining_segments
        else:
            chunk_segments = max(1, round(segments * width / total_width))
            chunk_segments = min(chunk_segments, remaining_segments - (len(chunks) - index - 1))
            remaining_segments -= chunk_segments
        points = grid_points(chunk_left, chunk_right, chunk_segments, grid)
        points = add_critical_points(points, critical_points, scale,
                                     chunk_left, chunk_right)
        points = add_singleton_points(points, singleton_points, scale,
                                      chunk_left, chunk_right)
        for a, b in zip(points, points[1:]):
            if a < b:
                pieces.append((a, b))
    return pieces


def encoded_segments(domain: Tuple[float, float], bin_bits: int, scale: int,
                     segments: int, grid: str,
                     critical_points: Sequence[float],
                     singleton_points: Sequence[float],
                     fill_policy: str,
                     func: Callable[[float], float]) -> List[Segment]:
    modulus = 1 << bin_bits
    factor = float(1 << scale)
    legal_encoded: List[Segment] = []
    for signed_left, signed_right in legal_signed_pieces(
            domain, bin_bits, scale, segments, grid, critical_points,
            singleton_points):
        left = signed_to_encoded(signed_left, bin_bits)
        right = signed_to_encoded(signed_right, bin_bits)
        if signed_right <= 0:
            right = modulus if signed_right == 0 else right
        if left >= right:
            raise ValueError("signed legal piece did not map to one encoded interval")
        legal_encoded.append(Segment(left, right, True,
                                     signed_left / factor,
                                     (signed_right - 1) / factor))

    endpoints = {0, modulus}
    for seg in legal_encoded:
        endpoints.add(seg.left)
        endpoints.add(seg.right)
    ordered = sorted(endpoints)

    def nearest_fill(left: int, right: int) -> float:
        if fill_policy == "zero":
            return 0.0
        mid = (left + right - 1) // 2
        signed_mid = polyfit.signed_from_twos(mid, bin_bits)
        real_mid = signed_mid / factor
        clamped = min(max(real_mid, domain[0]), domain[1])
        return func(clamped)

    result: List[Segment] = []
    legal_by_range = {(seg.left, seg.right): seg for seg in legal_encoded}
    for left, right in zip(ordered, ordered[1:]):
        if left >= right:
            continue
        seg = legal_by_range.get((left, right))
        if seg is not None:
            result.append(seg)
            continue
        signed_left = polyfit.signed_from_twos(left, bin_bits)
        signed_right = polyfit.signed_from_twos(right - 1, bin_bits)
        result.append(Segment(left, right, False,
                              signed_left / factor,
                              signed_right / factor,
                              nearest_fill(left, right)))
    return result


def fit_segment(segment: Segment, func_expr: str, remez_expr: Optional[str],
                func: Callable[[float], float], degree: int, scale: int,
                bout: int, backend: str, lolremez: Optional[str],
                extra_args: Sequence[str], samples_per_segment: int) -> Tuple[List[float], List[int], Dict]:
    if not segment.legal:
        value = 0.0 if segment.fill_value is None else segment.fill_value
        coeffs = [value] + [0.0] * degree
        return coeffs, polyfit.quantize_coefficients(coeffs, scale, bout), {
            "backend": "invalid-domain-fill",
            "fill_value": value,
        }

    effective_degree = degree
    if segment.right - segment.left <= degree or segment.real_left >= segment.real_right:
        effective_degree = max(0, min(degree, segment.right - segment.left - 1))
    if effective_degree < degree:
        if effective_degree == 0:
            coeffs = [func(segment.real_left)]
        else:
            samples = max(effective_degree + 1, segment.right - segment.left)
            coeffs = polyfit.fit_least_squares(
                func, segment.real_left, segment.real_right,
                effective_degree, samples)
        padded = coeffs + [0.0] * (degree - effective_degree)
        return padded, polyfit.quantize_coefficients(padded, scale, bout), {
            "backend": "least-squares-padded-low-degree",
            "effective_degree": effective_degree,
        }

    expr_for_remez = remez_expr or func_expr
    command = None
    raw_output = None
    remez_error = None
    coeffs = None
    executable = polyfit.find_lolremez(lolremez)
    if backend in ("auto", "remez") and executable and remez_expr is not None:
        try:
            coeffs, command, raw_output = polyfit.run_lolremez(
                executable, expr_for_remez, segment.real_left,
                segment.real_right, degree, extra_args)
        except Exception as exc:  # noqa: BLE001
            remez_error = f"{type(exc).__name__}: {exc}"
            if backend == "remez":
                raise
    if coeffs is None:
        if backend == "remez":
            raise RuntimeError(
                f"function {func_expr!r} has no usable lolremez expression")
        samples = samples_per_segment or max(degree + 1, min(segment.right - segment.left, 128))
        coeffs = polyfit.fit_least_squares(
            func, segment.real_left, segment.real_right, degree, samples)
        used = "least-squares"
    else:
        used = "remez"

    return coeffs, polyfit.quantize_coefficients(coeffs, scale, bout), {
        "backend": used,
        "command": command,
        "lolremez_output": raw_output,
        "lolremez_error": remez_error,
    }


def eval_fixed_poly(encoded_x: int, segments: Sequence[Segment],
                    coefficients: Sequence[int], bin_bits: int, bout: int,
                    scale: int, degree: int) -> Tuple[int, float]:
    segment_index = 0
    for idx, segment in enumerate(segments):
        if segment.left <= encoded_x < segment.right:
            segment_index = idx
            break
    x = polyfit.signed_from_twos(encoded_x, bin_bits)
    total = 0
    power = 1
    for i in range(degree + 1):
        raw = coefficients[segment_index * (degree + 1) + i]
        coeff = polyfit.signed_from_twos(raw, bout)
        total += (coeff << ((degree - i) * scale)) * power
        power *= x
    shift = degree * scale
    if shift:
        if total >= 0:
            total = total >> shift
        else:
            total = -((-total + (1 << shift) - 1) >> shift)
    encoded = polyfit.twos_from_signed(total, bout)
    return encoded, polyfit.signed_from_twos(encoded, bout) / float(1 << scale)


def sample_legal_inputs(segments: Sequence[Segment], samples_per_segment: int) -> List[int]:
    inputs = set()
    for segment in segments:
        if not segment.legal:
            continue
        width = segment.right - segment.left
        count = max(2, min(samples_per_segment, width))
        for i in range(count):
            x = segment.left + ((width - 1) * i) // (count - 1)
            inputs.add(x)
    return sorted(inputs)


def measure_accuracy(segments: Sequence[Segment], coefficients: Sequence[int],
                     func: Callable[[float], float], bin_bits: int, bout: int,
                     scale: int, degree: int, samples_per_segment: int) -> Dict:
    factor = float(1 << scale)
    max_abs_error = 0.0
    max_fixed_error = 0.0
    max_fixed_units = 0
    worst = None
    for encoded_x in sample_legal_inputs(segments, samples_per_segment):
        real_x = polyfit.signed_from_twos(encoded_x, bin_bits) / factor
        target = func(real_x)
        target_units = math.floor(target * factor)
        _, poly_real = eval_fixed_poly(
            encoded_x, segments, coefficients, bin_bits, bout, scale, degree)
        poly_units = math.floor(poly_real * factor)
        abs_error = abs(poly_real - target)
        fixed_units = abs(poly_units - target_units)
        fixed_error = fixed_units / factor
        if abs_error > max_abs_error:
            max_abs_error = abs_error
            worst = {
                "encoded_x": encoded_x,
                "real_x": real_x,
                "target": target,
                "poly_real": poly_real,
            }
        max_fixed_error = max(max_fixed_error, fixed_error)
        max_fixed_units = max(max_fixed_units, fixed_units)
    return {
        "max_abs_error": max_abs_error,
        "max_fixed_error": max_fixed_error,
        "max_fixed_units": max_fixed_units,
        "worst_abs_error_point": worst,
        "samples": len(sample_legal_inputs(segments, samples_per_segment)),
    }


def write_lut(path: Path, bin_bits: int, bout: int, values: Sequence[int]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as f:
        for value in (
                PUBLIC_LUT_MAGIC,
                PUBLIC_LUT_VERSION,
                bin_bits,
                bout,
                len(values),
        ):
            f.write(value.to_bytes(8, "little", signed=False))
        for value in values:
            f.write((value & ((1 << 64) - 1)).to_bytes(8, "little", signed=False))


def generate_lut(spec: FunctionSpec, func: Callable[[float], float],
                 bin_bits: int, bout: int, scale: int, output_dir: Path,
                 fill_policy: str, domain: Tuple[float, float]) -> CandidateResult:
    factor = float(1 << scale)
    modulus = 1 << bin_bits
    range_left, range_right = signed_range(bin_bits)
    representable_domain = [range_left / factor, (range_right - 1) / factor]
    effective_domain = [
        max(domain[0], representable_domain[0]),
        min(domain[1], representable_domain[1]),
    ]
    values: List[int] = []
    max_abs_error = 0.0
    max_fixed_units = 0
    for encoded_x in range(modulus):
        real_x = polyfit.signed_from_twos(encoded_x, bin_bits) / factor
        if domain[0] <= real_x <= domain[1]:
            target = func(real_x)
        elif fill_policy == "clamp":
            target = func(min(max(real_x, domain[0]), domain[1]))
        else:
            target = 0.0
        units = math.floor(target * factor)
        values.append(polyfit.twos_from_signed(units, bout))
        if domain[0] <= real_x <= domain[1]:
            output_real = polyfit.signed_from_twos(values[-1], bout) / factor
            max_abs_error = max(max_abs_error, abs(output_real - target))
            max_fixed_units = max(
                max_fixed_units, abs(math.floor(output_real * factor) - units))

    name = f"{spec.name}_lut_Bin{bin_bits}_Bout{bout}_S{scale}"
    bin_path = output_dir / spec.name / f"{name}.bin"
    meta_path = output_dir / spec.name / f"{name}.json"
    write_lut(bin_path, bin_bits, bout, values)
    metadata = {
        "format": "PublicLUTData",
        "function": spec.name,
        "python_expr": spec.python_expr,
        "bin": bin_bits,
        "bout": bout,
        "scale": scale,
        "input_encoding": "signed_twos_complement_fixed_point",
        "output_encoding": "signed_twos_complement_fixed_point",
        "requested_domain": list(domain),
        "representable_domain": representable_domain,
        "effective_legal_domain": effective_domain,
        "fill_policy": fill_policy,
        "entry_count": len(values),
        "accuracy": {
            "max_abs_error": max_abs_error,
            "max_fixed_error": max_fixed_units / factor,
            "max_fixed_units": max_fixed_units,
        },
    }
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return CandidateResult(True, bin_path, meta_path, metadata, max_abs_error,
                           max_fixed_units / factor, max_fixed_units)


def generate_poly_candidate(spec: FunctionSpec, func: Callable[[float], float],
                            bin_bits: int, bout: int, scale: int, degree: int,
                            segment_count: int, grid: str, backend: str,
                            lolremez: Optional[str], extra_args: Sequence[str],
                            samples_per_segment: int, accuracy_samples: int,
                            fill_policy: str, domain: Tuple[float, float],
                            output_dir: Path) -> CandidateResult:
    wide_bits = bout + degree * scale
    if bin_bits <= 0 or bin_bits > 23:
        raise ValueError(
            "profile is not protocol-loadable in the current implementation: "
            "MIC PolyEval's signed extension uses an iDPF over Bin+1 bits, "
            f"so Bin must be <= 23, got Bin={bin_bits}")
    if wide_bits < bin_bits or wide_bits <= 0 or wide_bits > 63:
        raise ValueError(
            "profile is not protocol-loadable by current MIC PolyEval: "
            "the widened polynomial ring must satisfy "
            "Bin <= wideBits = Bout + degree*scale <= 63. "
            "This is not a general DPF requirement. Got "
            f"Bin={bin_bits}, Bout={bout}, degree={degree}, scale={scale}, "
            f"wideBits={wide_bits}")
    if degree * scale > 23:
        raise ValueError(
            "profile is not protocol-loadable in the current implementation: "
            "MIC signed truncation uses an iDPF over degree*scale+1 bits, "
            "so degree*scale must be <= 23, got "
            f"degree={degree}, scale={scale}")

    segments = encoded_segments(
        domain, bin_bits, scale, segment_count, grid, spec.critical_points,
        spec.singleton_points, fill_policy, func)
    breakpoints = [segments[0].left] + [segment.right for segment in segments]
    if breakpoints[0] != 0 or breakpoints[-1] != (1 << bin_bits):
        raise RuntimeError("encoded segments do not cover full domain")

    all_coefficients: List[int] = []
    segment_meta = []
    for idx, segment in enumerate(segments):
        coeffs, quantized, fit_meta = fit_segment(
            segment, spec.python_expr, spec.remez_expr, func, degree, scale,
            bout, backend, lolremez, extra_args, samples_per_segment)
        all_coefficients.extend(quantized)
        segment_meta.append({
            "segment": idx,
            "encoded_range": [segment.left, segment.right],
            "real_range": [segment.real_left, segment.real_right],
            "legal": segment.legal,
            "coefficients_real_degree_ascending": coeffs,
            "coefficients_encoded_degree_ascending": quantized,
            **fit_meta,
        })

    accuracy = measure_accuracy(
        segments, all_coefficients, func, bin_bits, bout, scale, degree,
        accuracy_samples)
    factor = float(1 << scale)
    range_left, range_right = signed_range(bin_bits)
    representable_domain = [range_left / factor, (range_right - 1) / factor]
    legal_segments = [segment for segment in segments if segment.legal]
    effective_domain = [
        min(segment.real_left for segment in legal_segments),
        max(segment.real_right for segment in legal_segments),
    ]
    name = (
        f"{spec.name}_poly_Bin{bin_bits}_Bout{bout}_S{scale}"
        f"_d{degree}_seg{segment_count}_{grid}"
    )
    bin_path = output_dir / spec.name / f"{name}.bin"
    meta_path = output_dir / spec.name / f"{name}.json"
    bin_path.parent.mkdir(parents=True, exist_ok=True)
    polyfit.write_public_piecewise_poly(
        bin_path, bin_bits, bout, scale, degree, breakpoints, all_coefficients)

    used_backends = sorted({
        item["backend"] for item in segment_meta if item["backend"] != "invalid-domain-fill"
    })
    metadata = {
        "format": "PublicPiecewisePolyData",
        "output": str(bin_path),
        "function": spec.name,
        "python_expr": spec.python_expr,
        "remez_expr": spec.remez_expr,
        "notes": spec.notes,
        "bin": bin_bits,
        "bout": bout,
        "scale": scale,
        "input_encoding": "signed_twos_complement_fixed_point",
        "output_encoding": "signed_twos_complement_fixed_point",
        "degree": degree,
        "requested_legal_segments": segment_count,
        "actual_total_segments": len(segments),
        "grid": grid,
        "requested_domain": list(domain),
        "representable_domain": representable_domain,
        "effective_legal_domain": effective_domain,
        "fill_policy": fill_policy,
        "breakpoints": breakpoints,
        "backend_requested": backend,
        "backend_used": "+".join(used_backends) if used_backends else "fill-only",
        "lolremez_executable": polyfit.find_lolremez(lolremez),
        "lolremez_extra_args": list(extra_args),
        "segments": segment_meta,
        "accuracy": accuracy,
    }
    meta_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return CandidateResult(True, bin_path, meta_path, metadata,
                           accuracy["max_abs_error"],
                           accuracy["max_fixed_error"],
                           accuracy["max_fixed_units"])


def choose_poly(spec: FunctionSpec, func: Callable[[float], float],
                args: argparse.Namespace, domain: Tuple[float, float]) -> CandidateResult:
    degrees = parse_int_list(args.degrees) if args.degrees else spec.default_degrees
    segments = parse_int_list(args.segments) if args.segments else spec.default_segments
    grid = args.grid if args.grid != "preset" else spec.preferred_grid
    target_fixed_units = (
        args.target_max_fixed_units
        if args.target_max_fixed_units is not None
        else max(1, math.ceil(args.target_max_abs_error * (1 << args.scale)))
    )

    best: Optional[CandidateResult] = None
    failures = []
    for degree in degrees:
        for segment_count in segments:
            try:
                candidate = generate_poly_candidate(
                    spec, func, args.bin_bits, args.bout, args.scale, degree,
                    segment_count, grid, args.backend, args.lolremez,
                    args.lolremez_extra_arg, args.samples_per_segment,
                    args.accuracy_samples_per_segment, args.fill_policy,
                    domain, args.output_dir)
            except Exception as exc:  # noqa: BLE001
                failures.append({
                    "degree": degree,
                    "segments": segment_count,
                    "error": f"{type(exc).__name__}: {exc}",
                })
                continue
            if best is None or candidate.max_abs_error < best.max_abs_error:
                best = candidate
            if (candidate.max_abs_error <= args.target_max_abs_error and
                    candidate.max_fixed_units <= target_fixed_units):
                candidate.metadata["selection"] = {
                    "selected": True,
                    "reason": "met_accuracy_target",
                    "target_max_abs_error": args.target_max_abs_error,
                    "target_max_fixed_units": target_fixed_units,
                    "failures_before_selection": failures,
                }
                candidate.meta_path.write_text(
                    json.dumps(candidate.metadata, indent=2), encoding="utf-8")
                return candidate

    if best is None:
        raise RuntimeError(f"all candidates failed: {failures}")

    best.metadata["selection"] = {
        "selected": args.allow_low_accuracy,
        "reason": "best_candidate_but_target_not_met",
        "target_max_abs_error": args.target_max_abs_error,
        "target_max_fixed_units": target_fixed_units,
        "failures": failures,
    }
    best.meta_path.write_text(json.dumps(best.metadata, indent=2), encoding="utf-8")
    if not args.allow_low_accuracy:
        raise RuntimeError(
            "accuracy target not met; best "
            f"max_abs_error={best.max_abs_error:.6g}, "
            f"max_fixed_units={best.max_fixed_units}. "
            "Use larger --segments/--degrees or --allow-low-accuracy.")
    return best


def main() -> int:
    specs = build_specs()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--function", required=True,
                        choices=sorted(specs.keys()) + ["list"])
    parser.add_argument("--construction", choices=["poly", "lut"], default="poly")
    parser.add_argument("--bin", type=int, required=False, default=16,
                        dest="bin_bits")
    parser.add_argument("--bout", type=int, default=24)
    parser.add_argument("--scale", type=int, default=12)
    parser.add_argument("--domain", default=None,
                        help="override legal real domain as left:right")
    parser.add_argument("--degrees", default=None,
                        help="comma-separated degree candidates")
    parser.add_argument("--segments", default=None,
                        help="comma-separated legal segment-count candidates")
    parser.add_argument("--grid", choices=[
        "preset", "uniform", "chebyshev", "left-geometric", "right-geometric",
    ], default="preset")
    parser.add_argument("--backend",
                        choices=["auto", "remez", "least-squares"],
                        default="auto")
    parser.add_argument("--lolremez", default=None)
    parser.add_argument("--lolremez-extra-arg", action="append", default=[])
    parser.add_argument("--samples-per-segment", type=int, default=0)
    parser.add_argument("--accuracy-samples-per-segment", type=int, default=257)
    parser.add_argument("--target-max-abs-error", type=float, default=1e-2)
    parser.add_argument(
        "--target-max-fixed-units",
        type=int,
        default=None,
        help="optional fixed-point unit error cap; default is ceil(abs_error*2^scale)",
    )
    parser.add_argument("--allow-low-accuracy", action="store_true")
    parser.add_argument("--fill-policy", choices=["zero", "clamp"], default="zero")
    parser.add_argument("--max-lut-bin", type=int, default=16)
    parser.add_argument("--output-dir", type=Path,
                        default=REPO_ROOT / "generated_public_data")
    args = parser.parse_args()

    if args.function == "list":
        for name in sorted(specs):
            spec = specs[name]
            print(f"{name}: domain={spec.domain}, degrees={spec.default_degrees}, "
                  f"segments={spec.default_segments}, grid={spec.preferred_grid}")
        return 0

    spec = specs[args.function]
    domain = parse_domain(args.domain) if args.domain else spec.domain
    func = make_function(spec.python_expr)

    if args.construction == "lut":
        if args.bin_bits > args.max_lut_bin:
            raise ValueError(
                f"LUT generation refuses Bin={args.bin_bits}; raise "
                "--max-lut-bin explicitly if this is intentional")
        result = generate_lut(spec, func, args.bin_bits, args.bout, args.scale,
                              args.output_dir, args.fill_policy, domain)
    else:
        result = choose_poly(spec, func, args, domain)

    print(f"wrote {result.bin_path}")
    print(f"wrote {result.meta_path}")
    print(
        "accuracy "
        f"max_abs_error={result.max_abs_error:.8g} "
        f"max_fixed_error={result.max_fixed_error:.8g} "
        f"max_fixed_units={result.max_fixed_units}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
