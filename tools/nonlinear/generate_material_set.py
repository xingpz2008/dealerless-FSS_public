#!/usr/bin/env python3
"""Generate a reproducible nonlinear public-data material set.

The individual generator intentionally handles one function/profile at a time.
This script records the first broad material batch used for dFSS-extension
experiments under the current full-tree iDPF/MIC limits.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[1]
GENERATOR = SCRIPT_DIR / "generate_public_nonlinear_data.py"


EXACT_POLY = [
    "abs",
    "relu",
    "relu6",
    "leaky_relu",
    "relu2",
    "hardsigmoid",
    "hardswish",
    "hardtanh",
    "hardshrink",
    "softshrink",
    "signum",
    "positive",
    "negative",
    "nonnegative",
    "nonpositive",
    "zero",
    "nonzero",
]

SMOOTH_POLY = [
    "sigmoid",
    "tanh",
    "erf",
    "erfc",
    "softplus",
    "softminus",
    "softsign",
    "elu",
    "celu",
    "silu",
    "gelu",
    "mish",
    "lecun_tanh",
    "tanh_exp",
    "tanhshrink",
    "serf",
    "logsigmoid",
    "sin",
    "cos",
    "tan",
    "asin",
    "acos",
    "atan",
    "asinh",
]

RESTRICTED_POLY = [
    "ln",
    "log2",
    "log10",
    "sqrt",
    "cbrt",
    "reciprocal",
    "isqrt",
    "acosh",
    "atanh",
]

SMALL_LUT = [
    "abs",
    "relu",
    "signum",
    "positive",
    "negative",
    "zero",
    "nonzero",
]

TABLEIV_MATCHED = [
    "relu",
    "relu6",
    "hardsigmoid",
    "hardswish",
    "sigmoid",
    "tanh",
    "gelu",
    "silu",
    "softplus",
    "softsign",
    "sin",
    "cos",
    "ln",
    "sqrt",
    "reciprocal",
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run_case(command: List[str]) -> Dict:
    proc = subprocess.run(
        command,
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    row: Dict = {
        "command": command,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }
    if proc.returncode == 0:
        meta_path = None
        for line in proc.stdout.splitlines():
            if line.startswith("wrote ") and line.endswith(".json"):
                meta_path = Path(line[len("wrote "):])
        if meta_path is not None and meta_path.is_file():
            metadata = json.loads(meta_path.read_text(encoding="utf-8"))
            row.update({
                "status": "ok",
                "metadata_path": str(meta_path),
                "data_path": metadata.get("output", str(meta_path.with_suffix(""))),
                "function": metadata.get("function"),
                "format": metadata.get("format"),
                "bin": metadata.get("bin"),
                "bout": metadata.get("bout"),
                "scale": metadata.get("scale"),
                "degree": metadata.get("degree"),
                "segments": metadata.get("requested_legal_segments"),
                "actual_total_segments": metadata.get("actual_total_segments"),
                "backend_used": metadata.get("backend_used"),
                "accuracy": metadata.get("accuracy"),
                "selection": metadata.get("selection"),
            })
        else:
            row["status"] = "ok-no-metadata"
    else:
        row["status"] = "failed"
    return row


def append_profile(command: List[str], args: argparse.Namespace,
                   construction: str, function: str, extra: List[str]) -> List[str]:
    base = [
        sys.executable,
        str(GENERATOR),
        "--function",
        function,
        "--construction",
        construction,
        "--output-dir",
        str(args.output_dir),
    ]
    return base + command + extra


def parse_functions(text: Optional[str], default: Iterable[str]) -> List[str]:
    if not text:
        return list(default)
    return [item.strip() for item in text.split(",") if item.strip()]


def material_sha256(row: Dict, key: str) -> str:
    path = row.get(key)
    if not path:
        return ""
    p = Path(path)
    if not p.is_file():
        return ""
    return sha256_file(p)


def write_status_csv(path: Path, rows: List[Dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "function",
        "bin",
        "bout",
        "scale",
        "degree",
        "requested_segments",
        "generation_status",
        "selection_status",
        "low_accuracy_allowed",
        "generator_max_abs_error",
        "generator_max_fixed_units",
        "actual_total_segments",
        "backend",
        "metadata_path",
        "bin_path",
        "json_sha256",
        "bin_sha256",
        "command",
        "stdout",
        "stderr",
        "returncode",
    ]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            selection = row.get("selection") or {}
            accuracy = row.get("accuracy") or {}
            command = row.get("command", [])
            function = row.get("function", "")
            if not function and "--function" in command:
                function = command[command.index("--function") + 1]
            writer.writerow({
                "function": function,
                "bin": row.get("bin", ""),
                "bout": row.get("bout", ""),
                "scale": row.get("scale", ""),
                "degree": row.get("degree", ""),
                "requested_segments": row.get("segments", ""),
                "generation_status": row.get("status", ""),
                "selection_status": selection.get("reason", ""),
                "low_accuracy_allowed": row.get("low_accuracy_allowed", ""),
                "generator_max_abs_error": accuracy.get("max_abs_error", ""),
                "generator_max_fixed_units": accuracy.get("max_fixed_units", ""),
                "actual_total_segments": row.get("actual_total_segments", ""),
                "backend": row.get("backend_used", ""),
                "metadata_path": row.get("metadata_path", ""),
                "bin_path": row.get("data_path", ""),
                "json_sha256": material_sha256(row, "metadata_path"),
                "bin_sha256": material_sha256(row, "data_path"),
                "command": " ".join(str(part) for part in command),
                "stdout": row.get("stdout", ""),
                "stderr": row.get("stderr", ""),
                "returncode": row.get("returncode", ""),
            })


def generate_tableiv_matched(args: argparse.Namespace) -> List[Dict]:
    profile = [
        "--bin", "16",
        "--bout", "16",
        "--scale", "7",
        "--backend", "least-squares",
        "--degrees", "3",
        "--segments", "32",
        "--accuracy-samples-per-segment", "65",
        "--target-max-abs-error", "0.05",
    ]
    extra = ["--allow-low-accuracy"] if args.allow_low_accuracy else []
    functions = parse_functions(args.functions, TABLEIV_MATCHED)
    rows = [
        run_case(append_profile(profile, args, "poly", function, extra))
        for function in functions
    ]
    for row in rows:
        row["low_accuracy_allowed"] = args.allow_low_accuracy
    return rows


def generate_current(args: argparse.Namespace) -> List[Dict]:
    exact = EXACT_POLY[:6] if args.quick else EXACT_POLY
    smooth = SMOOTH_POLY[:5] if args.quick else SMOOTH_POLY
    restricted = RESTRICTED_POLY[:3] if args.quick else RESTRICTED_POLY
    lut = SMALL_LUT[:3] if args.quick else SMALL_LUT

    rows: List[Dict] = []

    exact_profile = [
        "--bin", "15",
        "--bout", "24",
        "--scale", "11",
        "--target-max-abs-error", "0.005",
    ]
    for function in exact:
        rows.append(run_case(append_profile(exact_profile, args, "poly", function, [])))

    smooth_profile = [
        "--bin", "15",
        "--bout", "24",
        "--scale", "11",
        "--backend", "least-squares",
        "--degrees", "2",
        "--segments", "32,64",
        "--accuracy-samples-per-segment", "33",
        "--target-max-abs-error", "0.05",
    ]
    smooth_extra = ["--allow-low-accuracy"] if args.allow_low_accuracy else []
    for function in smooth:
        rows.append(run_case(append_profile(
            smooth_profile, args, "poly", function, smooth_extra)))

    restricted_profile = [
        "--bin", "15",
        "--bout", "24",
        "--scale", "11",
        "--backend", "least-squares",
        "--degrees", "2",
        "--segments", "64",
        "--accuracy-samples-per-segment", "33",
        "--target-max-abs-error", "0.05",
    ]
    restricted_extra = ["--allow-low-accuracy"] if args.allow_low_accuracy else []
    for function in restricted:
        rows.append(run_case(append_profile(
            restricted_profile, args, "poly", function, restricted_extra)))

    lut_profile = [
        "--bin", "8",
        "--bout", "16",
        "--scale", "4",
        "--target-max-abs-error", "0.0625",
    ]
    for function in lut:
        rows.append(run_case(append_profile(lut_profile, args, "lut", function, [])))
    for row in rows:
        row["low_accuracy_allowed"] = args.allow_low_accuracy
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path,
                        default=REPO_ROOT / "generated_public_data")
    parser.add_argument("--manifest", type=Path, default=None)
    parser.add_argument("--profile", choices=["current", "tableiv-matched"],
                        default="current")
    parser.add_argument("--functions", default=None,
                        help="comma-separated override for smoke/debug runs")
    parser.add_argument("--status-csv", type=Path, default=None)
    parser.add_argument("--quick", action="store_true",
                        help="generate a smaller smoke subset")
    parser.add_argument("--allow-low-accuracy", action="store_true",
                        help="keep best smooth/restricted candidates if target is not met")
    args = parser.parse_args()

    rows = (
        generate_tableiv_matched(args)
        if args.profile == "tableiv-matched"
        else generate_current(args)
    )

    ok_count = sum(1 for row in rows if row["status"].startswith("ok"))
    failed_count = sum(1 for row in rows if row["status"] == "failed")
    manifest = {
        "description": (
            "Table-IV-matched nonlinear public-data material set"
            if args.profile == "tableiv-matched"
            else "Current nonlinear public-data material set"
        ),
        "profile": args.profile,
        "full_tree_cap_assumption": 24,
        "profiles": {
            "tableiv_matched": [
                "--bin", "16", "--bout", "16", "--scale", "7",
                "--degrees", "3", "--segments", "32",
                "--backend", "least-squares",
            ] if args.profile == "tableiv-matched" else None,
            "current": "see generate_material_set.py",
        },
        "counts": {
            "total": len(rows),
            "ok": ok_count,
            "failed": failed_count,
        },
        "rows": rows,
    }

    manifest_path = args.manifest or args.output_dir / "material_manifest_current.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    if args.status_csv is not None:
        write_status_csv(args.status_csv, rows)

    print(f"wrote {manifest_path}")
    print(f"ok={ok_count} failed={failed_count} total={len(rows)}")
    if failed_count:
        print("failed functions:")
        for row in rows:
            if row["status"] == "failed":
                function = "unknown"
                command = row.get("command", [])
                if "--function" in command:
                    function = command[command.index("--function") + 1]
                print(f"  {function}: {row.get('stderr', '').splitlines()[-1:]}")
    return 0 if failed_count == 0 or args.allow_low_accuracy else 1


if __name__ == "__main__":
    raise SystemExit(main())
