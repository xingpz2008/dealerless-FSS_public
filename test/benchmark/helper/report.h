#pragma once

#include "common.h"

#include <string>

void emit_row(const Row& row);
void emit_table_summary();
void emit_dpf_metric_row(const std::string& group,
                         const std::string& protocol,
                         const std::string& phase, int Bin, int Bout,
                         int repeat, const PhaseMetric& metric,
                         int evaluatedPoints, const std::string& notes,
                         int suffixBits = -1);
std::string user_phase(std::string phase);
bool phase_runs_offline(const BenchConfig& config);
bool phase_runs_online(const BenchConfig& config);
bool output_wants_csv(const BenchConfig& config);
bool output_wants_table(const BenchConfig& config);
std::string correctness_note(
    const BenchConfig& config,
    const std::string& checked_note = "correctness_checked");
