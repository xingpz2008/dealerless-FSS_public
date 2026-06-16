#include "report.h"

// User-facing table/CSV emission and phase/correctness labels.

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <vector>

namespace {

std::vector<Row> g_emitted_rows;

double per_repeat(uint64_t value, int repeat) {
    return static_cast<double>(value) / static_cast<double>(std::max(1, repeat));
}

std::string table_check_label(const Row& row) {
    if (row.status != "ok") {
        return row.status;
    }
    if (row.notes.find("correctness_skipped") != std::string::npos) {
        return "skipped";
    }
    if (row.notes.find("offline_only_keygen_ok") != std::string::npos) {
        return "keygen_ok";
    }
    if (row.notes.find("correctness_checked") != std::string::npos) {
        return "pass";
    }
    return "ok";
}

std::string csv_escape(const std::string& input) {
    if (input.find_first_of(",\"\n") == std::string::npos) {
        return input;
    }
    std::string out = "\"";
    for (char c : input) {
        if (c == '"') {
            out += "\"\"";
        } else {
            out += c;
        }
    }
    out += '"';
    return out;
}

}  // namespace

void emit_row(const Row& row) {
    if (party != SERVER && party != CLIENT) {
        return;
    }
    Row normalized = row;
    normalized.phase = user_phase(normalized.phase);
    g_emitted_rows.push_back(normalized);
    if (!output_wants_csv(g_bench_config)) {
        return;
    }
    std::cout << "CSV,"
              << party << ','
              << csv_escape(normalized.group) << ','
              << csv_escape(normalized.protocol) << ','
              << csv_escape(normalized.phase) << ','
              << normalized.Bin << ','
              << normalized.Bout << ','
              << normalized.repeat << ','
              << normalized.suffixBits << ','
              << normalized.lambdaBits << ','
              << normalized.degree << ','
              << normalized.scale << ','
              << normalized.segments << ','
              << normalized.intervalCount << ','
              << normalized.evaluatedPoints << ','
              << normalized.metric.time_us << ','
              << normalized.metric.sent << ','
              << normalized.metric.received << ','
              << (normalized.metric.sent + normalized.metric.received) << ','
              << normalized.metric.peer_rounds << ','
              << normalized.metric.reconstruct_rounds << ','
              << std::setprecision(17) << normalized.plaintextMaxAbsError << ','
              << std::setprecision(17)
              << normalized.ciphertextVsPlaintextMaxAbsError << ','
              << csv_escape(normalized.status) << ','
              << csv_escape(normalized.notes) << '\n';
}

void emit_table_summary() {
    if (!output_wants_table(g_bench_config) || g_emitted_rows.empty()) {
        return;
    }
    std::cout << "\n";
    std::cout << "protocol                         phase       avg_time_ms"
              << "    avg_sent_B    avg_recv_B    avg_rounds    check\n";
    std::cout << "--------------------------------------------------------------------------\n";
    for (const Row& row : g_emitted_rows) {
        const int repeat = std::max(1, row.repeat);
        std::cout << std::left << std::setw(32) << row.protocol
                  << std::setw(12) << row.phase
                  << std::right << std::setw(12) << std::fixed
                  << std::setprecision(3)
                  << (per_repeat(row.metric.time_us, repeat) / 1000.0)
                  << std::setw(14) << std::setprecision(1)
                  << per_repeat(row.metric.sent, repeat)
                  << std::setw(14)
                  << per_repeat(row.metric.received, repeat)
                  << std::setw(14)
                  << per_repeat(row.metric.peer_rounds, repeat)
                  << "    " << table_check_label(row) << "\n";
    }
    bool ok = true;
    for (const Row& row : g_emitted_rows) {
        ok = ok && row.status == "ok";
    }
    std::cout << "status: " << (ok ? "ok" : "failed") << "\n";
}

void emit_dpf_metric_row(const std::string& group,
                         const std::string& protocol,
                         const std::string& phase, int Bin, int Bout,
                         int repeat, const PhaseMetric& metric,
                         int evaluatedPoints, const std::string& notes,
                         int suffixBits) {
    Row row;
    row.group = group;
    row.protocol = protocol;
    row.phase = phase;
    row.Bin = Bin;
    row.Bout = Bout;
    row.repeat = repeat;
    row.suffixBits = suffixBits;
    row.evaluatedPoints = evaluatedPoints;
    row.metric = metric;
    row.notes = notes;
    emit_row(row);
}

std::string user_phase(std::string phase) {
    return phase == "gen" ? "offline" : phase;
}

bool phase_runs_offline(const BenchConfig& config) {
    return config.phase == "all" || config.phase == "offline";
}

bool phase_runs_online(const BenchConfig& config) {
    return config.phase == "all";
}

bool output_wants_csv(const BenchConfig& config) {
    return config.output == "csv" || config.output == "both";
}

bool output_wants_table(const BenchConfig& config) {
    return config.output == "table" || config.output == "both";
}

std::string correctness_note(const BenchConfig& config,
                             const std::string& checked_note) {
    if (!config.checkCorrectness) {
        return "correctness_skipped";
    }
    if (!phase_runs_online(config)) {
        return "offline_only_keygen_ok";
    }
    return checked_note;
}
