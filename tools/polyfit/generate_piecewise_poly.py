#!/usr/bin/env python3
"""Generate PublicPiecewisePolyData binary files.

The protocol consumes only the binary PublicPiecewisePolyData format. This
script is a decoupled coefficient generator with optional lolremez support and
a least-squares fallback.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import shutil
import struct
import subprocess
from pathlib import Path
from typing import Callable, Iterable, List, Sequence, Tuple


PUBLIC_POLY_MAGIC = 0x594C4F5042555044  # DF-PUBPOLY
PUBLIC_POLY_VERSION = 1


def signed_from_twos(value: int, bits: int) -> int:
    if bits == 64:
        if value >= (1 << 63):
            return value - (1 << 64)
        return value
    sign = 1 << (bits - 1)
    modulus = 1 << bits
    return value - modulus if value & sign else value


def twos_from_signed(value: int, bits: int) -> int:
    if bits == 64:
        return value & ((1 << 64) - 1)
    return value & ((1 << bits) - 1)


def parse_breakpoints(text: str) -> List[int]:
    values = [int(part.strip(), 0) for part in text.split(",") if part.strip()]
    if len(values) < 2:
        raise ValueError("at least two breakpoints are required")
    for i in range(1, len(values)):
        if values[i - 1] >= values[i]:
            raise ValueError("breakpoints must be strictly increasing")
    return values


def make_function(expr: str) -> Callable[[float], float]:
    allowed = {
        name: getattr(math, name)
        for name in dir(math)
        if not name.startswith("_")
    }
    allowed.update({"abs": abs, "min": min, "max": max, "pow": pow})

    code = compile(expr, "<function>", "eval")

    def func(x: float) -> float:
        return float(eval(code, {"__builtins__": {}}, {**allowed, "x": x}))

    return func


def solve_linear_system(matrix: List[List[float]], rhs: List[float]) -> List[float]:
    n = len(rhs)
    for col in range(n):
        pivot = max(range(col, n), key=lambda row: abs(matrix[row][col]))
        if abs(matrix[pivot][col]) < 1e-18:
            raise ValueError("least-squares matrix is singular")
        if pivot != col:
            matrix[pivot], matrix[col] = matrix[col], matrix[pivot]
            rhs[pivot], rhs[col] = rhs[col], rhs[pivot]
        divisor = matrix[col][col]
        for j in range(col, n):
            matrix[col][j] /= divisor
        rhs[col] /= divisor
        for row in range(n):
            if row == col:
                continue
            factor = matrix[row][col]
            for j in range(col, n):
                matrix[row][j] -= factor * matrix[col][j]
            rhs[row] -= factor * rhs[col]
    return rhs


def fit_least_squares(
    func: Callable[[float], float],
    left: float,
    right: float,
    degree: int,
    samples: int,
) -> List[float]:
    samples = max(samples, degree + 1)
    coeff_count = degree + 1
    normal = [[0.0 for _ in range(coeff_count)] for _ in range(coeff_count)]
    rhs = [0.0 for _ in range(coeff_count)]
    for s in range(samples):
        x = left if samples == 1 else left + (right - left) * s / (samples - 1)
        y = func(x)
        powers = [1.0]
        for _ in range(2 * degree):
            powers.append(powers[-1] * x)
        for row in range(coeff_count):
            rhs[row] += y * powers[row]
            for col in range(coeff_count):
                normal[row][col] += powers[row + col]
    return solve_linear_system(normal, rhs)


NUMBER_PATTERN = (
    r"[-+]?(?:"
    r"0[xX](?:[0-9a-fA-F]+(?:\.[0-9a-fA-F]*)?|\.[0-9a-fA-F]+)"
    r"[pP][-+]?\d+"
    r"|"
    r"(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?"
    r")(?:[fFlL])?"
)
INIT_U_RE = re.compile(
    rf"\b(?:float|double|long\s+double)\s+u\s*=\s*({NUMBER_PATTERN})\s*;"
)
UPDATE_U_RE = re.compile(
    rf"\bu\s*=\s*u\s*\*\s*[A-Za-z_][A-Za-z0-9_]*\s*\+\s*({NUMBER_PATTERN})\s*;"
)
RETURN_U_RE = re.compile(
    rf"\breturn\s+u\s*\*\s*[A-Za-z_][A-Za-z0-9_]*\s*\+\s*({NUMBER_PATTERN})\s*;"
)
RETURN_CONST_RE = re.compile(rf"\breturn\s+({NUMBER_PATTERN})\s*;")


def parse_c_float(text: str) -> float:
    value = text.strip()
    if value and value[-1] in "fFlL":
        value = value[:-1]
    if value.lower().lstrip("+-").startswith("0x"):
        return float.fromhex(value)
    return float(value)


def parse_lolremez_coefficients(output: str, degree: int) -> List[float]:
    values: List[float] = []
    for line in output.splitlines():
        match = INIT_U_RE.search(line)
        if match:
            values.append(parse_c_float(match.group(1)))
            continue
        match = UPDATE_U_RE.search(line)
        if match:
            values.append(parse_c_float(match.group(1)))
            continue
        match = RETURN_U_RE.search(line)
        if match:
            values.append(parse_c_float(match.group(1)))
            continue
        if degree == 0:
            match = RETURN_CONST_RE.search(line)
            if match:
                values.append(parse_c_float(match.group(1)))
    if len(values) != degree + 1:
        raise ValueError(
            f"could not parse lolremez coefficients: expected {degree + 1}, "
            f"got {len(values)}"
        )
    return list(reversed(values))


def run_lolremez(
    executable: str,
    expr: str,
    left: float,
    right: float,
    degree: int,
    extra_args: Sequence[str],
) -> Tuple[List[float], List[str], str]:
    command = [
        executable,
        "--double",
        *extra_args,
        "-d",
        str(degree),
        "-r",
        f"{left}:{right}",
        expr,
    ]
    proc = subprocess.run(
        command,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return parse_lolremez_coefficients(proc.stdout, degree), command, proc.stdout


def find_lolremez(explicit_path: str | None) -> str | None:
    if explicit_path:
        return explicit_path
    executable = shutil.which("lolremez")
    if executable:
        return executable

    repo_root = Path(__file__).resolve().parents[2]
    for candidate in (
        repo_root / "thirdparty" / "lolremez" / "lolremez",
        repo_root / "thirdparty" / "lolremez" / "lolremez.exe",
    ):
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def quantize_coefficients(coeffs: Iterable[float], scale: int, bout: int) -> List[int]:
    factor = 1 << scale
    return [twos_from_signed(math.floor(c * factor), bout) for c in coeffs]


def segment_real_range(bin_bits: int, scale: int, left: int, right: int) -> Tuple[float, float]:
    factor = float(1 << scale)
    real_left = signed_from_twos(left, bin_bits) / factor
    real_right = signed_from_twos(right - 1, bin_bits) / factor
    if real_right < real_left:
        real_left, real_right = real_right, real_left
    return real_left, real_right


def write_public_piecewise_poly(
    path: Path,
    bin_bits: int,
    bout: int,
    scale: int,
    degree: int,
    breakpoints: Sequence[int],
    coefficients: Sequence[int],
) -> None:
    segment_count = len(breakpoints) - 1
    expected = segment_count * (degree + 1)
    if len(coefficients) != expected:
        raise ValueError("coefficient count mismatch")
    with path.open("wb") as f:
        values = [
            PUBLIC_POLY_MAGIC,
            PUBLIC_POLY_VERSION,
            bin_bits,
            bout,
            scale,
            degree,
            segment_count,
        ]
        for value in values:
            f.write(struct.pack("<Q", value))
        for breakpoint in breakpoints:
            f.write(struct.pack("<Q", breakpoint))
        for coefficient in coefficients:
            f.write(struct.pack("<Q", coefficient & ((1 << 64) - 1)))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin", type=int, required=True, dest="bin_bits")
    parser.add_argument("--bout", type=int, required=True)
    parser.add_argument("--scale", type=int, required=True)
    parser.add_argument("--degree", type=int, required=True)
    parser.add_argument("--breakpoints", required=True)
    parser.add_argument("--function", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--backend",
        choices=["auto", "remez", "least-squares"],
        default="auto",
    )
    parser.add_argument("--lolremez", default=None)
    parser.add_argument(
        "--lolremez-extra-arg",
        action="append",
        default=[],
        help="extra argument passed to lolremez; repeat for multiple arguments",
    )
    parser.add_argument("--samples-per-segment", type=int, default=0)
    parser.add_argument("--metadata", default=None)
    args = parser.parse_args()

    breakpoints = parse_breakpoints(args.breakpoints)
    if breakpoints[0] != 0 or breakpoints[-1] != (1 << args.bin_bits):
        raise ValueError("breakpoints must cover [0, 2^Bin)")

    func = make_function(args.function)
    executable = find_lolremez(args.lolremez)
    all_coefficients: List[int] = []
    segments = []
    segment_backends = []

    for m, (left_enc, right_enc) in enumerate(zip(breakpoints, breakpoints[1:])):
        left, right = segment_real_range(
            args.bin_bits, args.scale, left_enc, right_enc
        )
        command = None
        raw_output = None
        remez_error = None
        coeffs = None
        if args.backend in ("auto", "remez") and executable:
            try:
                coeffs, command, raw_output = run_lolremez(
                    executable,
                    args.function,
                    left,
                    right,
                    args.degree,
                    args.lolremez_extra_arg,
                )
            except Exception as exc:
                remez_error = f"{type(exc).__name__}: {exc}"
                if args.backend == "remez":
                    raise
        if coeffs is None:
            if args.backend == "remez":
                raise RuntimeError("lolremez executable not found")
            samples = args.samples_per_segment or max(
                args.degree + 1, min(right_enc - left_enc, 64)
            )
            coeffs = fit_least_squares(func, left, right, args.degree, samples)
            segment_backend = "least-squares"
        else:
            segment_backend = "remez"
        segment_backends.append(segment_backend)

        quantized = quantize_coefficients(coeffs, args.scale, args.bout)
        all_coefficients.extend(quantized)
        segments.append(
            {
                "segment": m,
                "encoded_range": [left_enc, right_enc],
                "real_range": [left, right],
                "backend": segment_backend,
                "command": command,
                "coefficients_real_degree_ascending": coeffs,
                "coefficients_encoded_degree_ascending": quantized,
                "lolremez_output": raw_output,
                "lolremez_error": remez_error,
            }
        )

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    write_public_piecewise_poly(
        output,
        args.bin_bits,
        args.bout,
        args.scale,
        args.degree,
        breakpoints,
        all_coefficients,
    )

    metadata_path = Path(args.metadata) if args.metadata else output.with_suffix(output.suffix + ".json")
    if all(backend == "remez" for backend in segment_backends):
        backend_used = "remez"
    elif all(backend == "least-squares" for backend in segment_backends):
        if args.backend == "least-squares":
            backend_used = "least-squares"
        elif executable:
            backend_used = "auto-fallback-least-squares"
        else:
            backend_used = "auto-no-lolremez-least-squares"
    else:
        backend_used = "mixed-remez-least-squares"
    metadata = {
        "format": "PublicPiecewisePolyData",
        "output": str(output),
        "backend_requested": args.backend,
        "backend_used": backend_used,
        "lolremez_executable": executable,
        "lolremez_extra_args": args.lolremez_extra_arg,
        "bin": args.bin_bits,
        "bout": args.bout,
        "scale": args.scale,
        "degree": args.degree,
        "breakpoints": breakpoints,
        "function": args.function,
        "segments": segments,
    }
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(f"wrote {output}")
    print(f"wrote {metadata_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
