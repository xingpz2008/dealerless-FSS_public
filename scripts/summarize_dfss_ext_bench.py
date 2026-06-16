#!/usr/bin/env python3
"""Aggregate per-party dFSS extension benchmark rows.

Raw benchmark rows are intentionally emitted separately by each party.  For
paper-facing communication, count each wire byte once by summing the bytes sent
by both parties.  Time and round counts use the slower party's value.
"""

import csv
import os
import sys
from collections import defaultdict


NUMERIC_STATIC_COLUMNS = {
    "Bin",
    "Bout",
    "repeat",
    "suffixBits",
    "lambdaBits",
    "degree",
    "scale",
    "segments",
    "intervalCount",
    "evaluatedPoints",
}

METRIC_COLUMNS = {
    "party",
    "time_us",
    "bytes_sent",
    "bytes_received",
    "comm_bytes",
    "peer_rounds",
    "reconstruct_rounds",
    "plaintext_max_abs_error",
    "ciphertext_vs_plaintext_max_abs_error",
    "status",
    "notes",
}


def as_int(row, name):
    return int(row[name]) if row.get(name) not in (None, "") else 0


def as_float(row, name):
    return float(row[name]) if row.get(name) not in (None, "") else 0.0


def key_for(row, fieldnames):
    return tuple((name, row[name]) for name in fieldnames if name not in METRIC_COLUMNS)


def normalize_note(note):
    volatile_prefixes = (
        "time_us_per_conversion=",
        "raw_party_comm_bytes_per_conversion=",
        "comm_bytes_per_conversion=",
    )
    parts = [
        part
        for part in note.split(";")
        if not any(part.startswith(prefix) for prefix in volatile_prefixes)
    ]
    return ";".join(parts)


def sortable_key(key):
    converted = []
    for name, value in key:
        if name in NUMERIC_STATIC_COLUMNS:
            try:
                converted.append((name, int(value)))
                continue
            except ValueError:
                pass
        converted.append((name, value))
    return tuple(converted)


def denominator(row):
    repeat = max(1, as_int(row, "repeat"))
    evaluated = max(1, as_int(row, "evaluatedPoints"))
    group = row.get("group", "")
    if group == "poly":
        # Poly rows set evaluatedPoints to the number of evaluated inputs.
        return evaluated
    return repeat * evaluated


def aggregate_rows(rows, fieldnames):
    groups = defaultdict(list)
    for row in rows:
        groups[key_for(row, fieldnames)].append(row)

    static_columns = [name for name in fieldnames if name not in METRIC_COLUMNS]
    out_rows = []
    for key, items in sorted(groups.items(), key=lambda item: sortable_key(item[0])):
        base = dict(key)
        parties = sorted({row["party"] for row in items})
        bytes_sent_by_party = {row["party"]: as_int(row, "bytes_sent") for row in items}
        bytes_received_by_party = {
            row["party"]: as_int(row, "bytes_received") for row in items
        }
        total_comm = sum(bytes_sent_by_party.values())
        max_time = max(as_int(row, "time_us") for row in items)
        max_sent = max(bytes_sent_by_party.values()) if items else 0
        max_rounds = max(as_int(row, "peer_rounds") for row in items)
        max_reconstruct = max(as_int(row, "reconstruct_rounds") for row in items)
        raw_comm_sum = sum(as_int(row, "comm_bytes") for row in items)
        denom = max(1, denominator(items[0]))
        statuses = sorted({row["status"] for row in items})
        notes = sorted(
            {normalize_note(row["notes"]) for row in items if row.get("notes")}
        )

        out = {name: base.get(name, "") for name in static_columns}
        out.update(
            {
                "parties": "+".join(parties),
                "time_us_max": str(max_time),
                "time_us_per_item": f"{max_time / denom:.10g}",
                "total_comm_bytes_sum_sent": str(total_comm),
                "total_comm_bytes_per_item": f"{total_comm / denom:.10g}",
                "max_party_sent_bytes": str(max_sent),
                "raw_comm_bytes_sum": str(raw_comm_sum),
                "peer_rounds_max": str(max_rounds),
                "reconstruct_rounds_max": str(max_reconstruct),
                "bytes_sent_party2": str(bytes_sent_by_party.get("2", 0)),
                "bytes_sent_party3": str(bytes_sent_by_party.get("3", 0)),
                "bytes_received_party2": str(bytes_received_by_party.get("2", 0)),
                "bytes_received_party3": str(bytes_received_by_party.get("3", 0)),
                "plaintext_max_abs_error": f"{max(as_float(row, 'plaintext_max_abs_error') for row in items):.17g}",
                "ciphertext_vs_plaintext_max_abs_error": f"{max(as_float(row, 'ciphertext_vs_plaintext_max_abs_error') for row in items):.17g}",
                "status": "ok" if statuses == ["ok"] else "|".join(statuses),
                "notes": "|".join(notes),
            }
        )
        out_rows.append(out)
    return static_columns, out_rows


def protocol_family(protocol):
    aliases = {
        "correlated_dpf": "correlated_dpf_lsb_trick",
    }
    return aliases.get(protocol, protocol)


def compact_note(note):
    keep = []
    for part in note.split(";"):
        if part.startswith(("time_us_", "raw_party_", "total_conversions=")):
            continue
        if len(keep) < 3 and part:
            keep.append(part)
    return ";".join(keep)


def row_int(row, name):
    try:
        return int(row.get(name, "0"))
    except ValueError:
        return 0


def row_float(row, name):
    try:
        return float(row.get(name, "0"))
    except ValueError:
        return 0.0


def aggregate_denominator(row):
    repeat = max(1, row_int(row, "repeat"))
    evaluated = max(1, row_int(row, "evaluatedPoints"))
    if row.get("group") == "poly":
        return evaluated
    return repeat * evaluated


def write_compact_summary(path, rows):
    fieldnames = [
        "group",
        "protocol",
        "phase",
        "Bin",
        "Bout",
        "suffixBits",
        "degree",
        "scale",
        "segments",
        "intervalCount",
        "repeat",
        "items_per_repeat",
        "total_items",
        "time_ms_per_item",
        "comm_KiB_per_item",
        "rounds_per_repeat_or_batch",
        "status",
        "plaintext_max_abs_error",
        "ciphertext_vs_plaintext_max_abs_error",
        "short_notes",
    ]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            repeat = max(1, row_int(row, "repeat"))
            total_items = aggregate_denominator(row)
            items_per_repeat = max(1, total_items // repeat)
            out = {
                "group": row.get("group", ""),
                "protocol": row.get("protocol", ""),
                "phase": row.get("phase", ""),
                "Bin": row.get("Bin", ""),
                "Bout": row.get("Bout", ""),
                "suffixBits": row.get("suffixBits", ""),
                "degree": row.get("degree", ""),
                "scale": row.get("scale", ""),
                "segments": row.get("segments", ""),
                "intervalCount": row.get("intervalCount", ""),
                "repeat": row.get("repeat", ""),
                "items_per_repeat": str(items_per_repeat),
                "total_items": str(total_items),
                "time_ms_per_item": f"{row_float(row, 'time_us_per_item') / 1000:.6g}",
                "comm_KiB_per_item": f"{row_float(row, 'total_comm_bytes_per_item') / 1024:.6g}",
                "rounds_per_repeat_or_batch": f"{row_float(row, 'peer_rounds_max') / repeat:.6g}",
                "status": row.get("status", ""),
                "plaintext_max_abs_error": row.get("plaintext_max_abs_error", ""),
                "ciphertext_vs_plaintext_max_abs_error": row.get(
                    "ciphertext_vs_plaintext_max_abs_error", ""
                ),
                "short_notes": compact_note(row.get("notes", "")),
            }
            writer.writerow(out)


def paper_params(row):
    params = []
    group = row.get("group", "")

    if group in {"et_primitive", "et_sweep", "et_gen_sweep", "lut"}:
        suffix = row.get("suffixBits", "")
        if suffix not in {"", "-1"}:
            params.append(f"suffixBits={suffix}")

    if group == "mic" or (
        group == "comparison"
    ):
        intervals = row.get("intervalCount", "")
        if intervals not in {"", "-1"}:
            params.append(f"intervalCount={intervals}")

    if group == "poly":
        for name in ("degree", "scale", "segments"):
            value = row.get(name, "")
            if value not in {"", "-1"}:
                params.append(f"{name}={value}")

    if group == "payload_conversion":
        batch = row.get("evaluatedPoints", "")
        if batch not in {"", "-1"}:
            params.append(f"batch={batch}")

    lambda_bits = row.get("lambdaBits", "")
    if lambda_bits not in {"", "128"}:
        params.append(f"lambdaBits={lambda_bits}")

    return ";".join(params)


def paper_config_key(row):
    return (
        row.get("group", ""),
        row.get("protocol", ""),
        row.get("Bin", ""),
        row.get("Bout", ""),
        paper_params(row),
    )


def average_per_repeat(row, column, scale):
    repeat = max(1, row_int(row, "repeat"))
    return row_float(row, column) / repeat / scale


def paper_metric(row, column, scale):
    if row is None:
        return ""
    return f"{average_per_repeat(row, column, scale):.6g}"


def paper_error(row, column):
    if row is None:
        return ""
    value = row_float(row, column)
    if row.get("group") != "poly" and value == 0.0:
        return ""
    return f"{value:.6g}"


def paper_status(offline_row, online_row):
    statuses = []
    if offline_row is not None and offline_row.get("status", "") != "ok":
        statuses.append(f"offline={offline_row.get('status', '')}")
    if online_row is not None and online_row.get("status", "") != "ok":
        statuses.append(f"online={online_row.get('status', '')}")
    return ";".join(statuses) if statuses else "ok"


def write_paper_summary(path, rows):
    fieldnames = [
        "group",
        "protocol",
        "Bin",
        "Bout",
        "params",
        "online_mode",
        "offline_time_ms",
        "offline_comm_KiB",
        "offline_rounds",
        "online_time_ms",
        "online_comm_KiB",
        "online_rounds",
        "plaintext_max_abs_error",
        "ciphertext_vs_plaintext_max_abs_error",
        "status",
    ]

    by_config = defaultdict(dict)
    for row in rows:
        by_config[paper_config_key(row)][row.get("phase", "")] = row

    online_phases = ("online", "single_eval", "full_domain_eval", "prefix_eval", "total")
    out_rows = []
    for key in sorted(by_config):
        phases = by_config[key]
        offline_row = phases.get("offline") or phases.get("gen")
        emitted = False
        for online_phase in online_phases:
            online_row = phases.get(online_phase)
            if online_row is None:
                continue
            emitted = True
            accuracy_row = online_row or offline_row
            out_rows.append(
                {
                    "group": key[0],
                    "protocol": key[1],
                    "Bin": key[2],
                    "Bout": key[3],
                    "params": key[4],
                    "online_mode": online_phase,
                    "offline_time_ms": paper_metric(
                        offline_row, "time_us_max", 1000.0
                    ),
                    "offline_comm_KiB": paper_metric(
                        offline_row, "total_comm_bytes_sum_sent", 1024.0
                    ),
                    "offline_rounds": paper_metric(
                        offline_row, "peer_rounds_max",
                        max(1, row_int(offline_row, "repeat"))
                    ),
                    "online_time_ms": paper_metric(
                        online_row, "time_us_max", 1000.0
                    ),
                    "online_comm_KiB": paper_metric(
                        online_row, "total_comm_bytes_sum_sent", 1024.0
                    ),
                    "online_rounds": paper_metric(
                        online_row, "peer_rounds_max",
                        max(1, row_int(online_row, "repeat"))
                    ),
                    "plaintext_max_abs_error": paper_error(
                        accuracy_row, "plaintext_max_abs_error"
                    ),
                    "ciphertext_vs_plaintext_max_abs_error": paper_error(
                        accuracy_row, "ciphertext_vs_plaintext_max_abs_error"
                    ),
                    "status": paper_status(offline_row, online_row),
                }
            )
        if not emitted and offline_row is not None:
            out_rows.append(
                {
                    "group": key[0],
                    "protocol": key[1],
                    "Bin": key[2],
                    "Bout": key[3],
                    "params": key[4],
                    "online_mode": "",
                    "offline_time_ms": paper_metric(
                        offline_row, "time_us_max", 1000.0
                    ),
                    "offline_comm_KiB": paper_metric(
                        offline_row, "total_comm_bytes_sum_sent", 1024.0
                    ),
                    "offline_rounds": paper_metric(
                        offline_row, "peer_rounds_max",
                        max(1, row_int(offline_row, "repeat"))
                    ),
                    "online_time_ms": "",
                    "online_comm_KiB": "",
                    "online_rounds": "",
                    "plaintext_max_abs_error": paper_error(
                        offline_row, "plaintext_max_abs_error"
                    ),
                    "ciphertext_vs_plaintext_max_abs_error": paper_error(
                        offline_row, "ciphertext_vs_plaintext_max_abs_error"
                    ),
                    "status": paper_status(offline_row, None),
                }
            )

    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(out_rows)


def ratio_key(row):
    protocol = protocol_family(row.get("protocol", ""))
    suffix = row.get("suffixBits", "")
    return (
        row.get("group", ""),
        row.get("phase", ""),
        row.get("Bin", ""),
        row.get("Bout", ""),
        suffix,
        row.get("degree", ""),
        row.get("scale", ""),
        row.get("segments", ""),
        row.get("intervalCount", ""),
    )


def ratio_value(num, den, name):
    denominator_value = row_float(den, name)
    if denominator_value == 0:
        return ""
    return f"{row_float(num, name) / denominator_value:.6g}"


def write_ratio_summary(path, rows):
    by_key = defaultdict(dict)
    for row in rows:
        by_key[ratio_key(row)][protocol_family(row.get("protocol", ""))] = row

    comparisons = [
        ("correlated_dpf_lsb_trick", "dpf_et", "correlated_over_et"),
        ("xing_cmp2bit_mux_total", "parallel_mux", "xing_cmp2bit_over_parallel_mux"),
    ]

    fieldnames = [
        "comparison",
        "group",
        "phase",
        "Bin",
        "Bout",
        "suffixBits",
        "degree",
        "scale",
        "segments",
        "intervalCount",
        "numerator_protocol",
        "denominator_protocol",
        "time_ratio",
        "comm_ratio",
        "round_ratio",
        "numerator_status",
        "denominator_status",
    ]
    out_rows = []
    for key, protocols in sorted(by_key.items()):
        for numerator, denominator, label in comparisons:
            if numerator not in protocols or denominator not in protocols:
                continue
            nrow = protocols[numerator]
            drow = protocols[denominator]
            out_rows.append(
                {
                    "comparison": label,
                    "group": key[0],
                    "phase": key[1],
                    "Bin": key[2],
                    "Bout": key[3],
                    "suffixBits": key[4],
                    "degree": key[5],
                    "scale": key[6],
                    "segments": key[7],
                    "intervalCount": key[8],
                    "numerator_protocol": numerator,
                    "denominator_protocol": denominator,
                    "time_ratio": ratio_value(nrow, drow, "time_us_per_item"),
                    "comm_ratio": ratio_value(
                        nrow, drow, "total_comm_bytes_per_item"
                    ),
                    "round_ratio": ratio_value(nrow, drow, "peer_rounds_max"),
                    "numerator_status": nrow.get("status", ""),
                    "denominator_status": drow.get("status", ""),
                }
            )

    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(out_rows)


def main():
    if len(sys.argv) != 3:
        print(
            "Usage: summarize_dfss_ext_bench.py RAW_RESULTS.csv AGGREGATE_RESULTS.csv",
            file=sys.stderr,
        )
        return 2

    raw_path, out_path = sys.argv[1], sys.argv[2]
    with open(raw_path, newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        fieldnames = reader.fieldnames or []

    static_columns, out_rows = aggregate_rows(rows, fieldnames)
    metric_columns = [
        "parties",
        "time_us_max",
        "time_us_per_item",
        "total_comm_bytes_sum_sent",
        "total_comm_bytes_per_item",
        "max_party_sent_bytes",
        "raw_comm_bytes_sum",
        "peer_rounds_max",
        "reconstruct_rounds_max",
        "bytes_sent_party2",
        "bytes_sent_party3",
        "bytes_received_party2",
        "bytes_received_party3",
        "plaintext_max_abs_error",
        "ciphertext_vs_plaintext_max_abs_error",
        "status",
        "notes",
    ]
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=static_columns + metric_columns)
        writer.writeheader()
        writer.writerows(out_rows)

    out_dir = os.path.dirname(os.path.abspath(out_path))
    write_compact_summary(os.path.join(out_dir, "summary_compact.csv"), out_rows)
    write_paper_summary(os.path.join(out_dir, "paper_summary.csv"), out_rows)
    write_ratio_summary(os.path.join(out_dir, "summary_ratios.csv"), out_rows)


if __name__ == "__main__":
    raise SystemExit(main())
