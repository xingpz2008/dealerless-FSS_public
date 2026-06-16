#include "benchmarks.h"
#include "common.h"
#include "report.h"

// API-layer benchmark groups: LUT, MIC,
// comparison, and polynomial evaluation.

#include <algorithm>
#include <cmath>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

PublicLUTData make_bench_lut(int Bin, int Bout) {
    return generatePublicLUT(Bin, Bout, [Bout](uint64_t x) {
        return (3 * x * x + 5 * x + 7) & mask_for_bits(Bout);
    });
}

std::vector<uint64_t> make_breakpoints(int Bin, int segments) {
    const uint64_t domain = uint64_t(1) << Bin;
    std::vector<uint64_t> breakpoints(segments + 1);
    for (int i = 0; i <= segments; i++) {
        breakpoints[i] = (domain * static_cast<uint64_t>(i)) /
                         static_cast<uint64_t>(segments);
    }
    breakpoints.front() = 0;
    breakpoints.back() = domain;
    return breakpoints;
}

PublicPiecewisePolyData make_exact_poly(int Bin, int Bout, int scale,
                                        int degree, int segments) {
    const std::vector<uint64_t> breakpoints = make_breakpoints(Bin, segments);
    return generatePublicPiecewisePolynomial(
        Bin, Bout, scale, degree, breakpoints,
        [Bout, scale, degree](int segment, int power) -> uint64_t {
            if (degree == 0) {
                const int64_t c = (segment % 2 == 0)
                                      ? (int64_t(1) << scale)
                                      : -(int64_t(1) << (scale - 1));
                return twos_from_signed(c, Bout);
            }
            int64_t encoded = 0;
            if (power == 0) {
                encoded = (int64_t(1) << scale) + segment;
            } else if (power == 1) {
                encoded = int64_t(1) << std::max(0, scale - 2);
            } else if (power == 2) {
                encoded = 0;
            } else {
                encoded = 0;
            }
            return twos_from_signed(encoded, Bout);
        });
}

long double floor_div_pow2_i128(__int128 value, int shift) {
    if (shift == 0) {
        return static_cast<long double>(value);
    }
    const __int128 divisor = __int128(1) << shift;
    if (value >= 0) {
        return static_cast<long double>(value >> shift);
    }
    return static_cast<long double>(-(((-value) + divisor - 1) >> shift));
}

uint64_t eval_plain_poly_fixed(uint64_t input,
                               const PublicPiecewisePolyData& poly) {
    int segment = 0;
    for (int m = 0; m + 1 < static_cast<int>(poly.breakpoints.size()); m++) {
        if (poly.breakpoints[m] <= input && input < poly.breakpoints[m + 1]) {
            segment = m;
            break;
        }
    }
    const int64_t x = signed_from_twos(input, poly.Bin);
    __int128 total = 0;
    __int128 xPower = 1;
    for (int i = 0; i <= poly.degree; i++) {
        const GroupElement coeff =
            poly.coefficients[segment * (poly.degree + 1) + i];
        const int64_t signedCoeff = signed_from_twos(coeff.value, poly.Bout);
        const int shift = (poly.degree - i) * poly.scale;
        total += (static_cast<__int128>(signedCoeff) << shift) * xPower;
        xPower *= x;
    }
    const auto scaled = static_cast<int64_t>(
        floor_div_pow2_i128(total, poly.degree * poly.scale));
    return twos_from_signed(scaled, poly.Bout);
}

double eval_real_poly(uint64_t input, const PublicPiecewisePolyData& poly) {
    int segment = 0;
    for (int m = 0; m + 1 < static_cast<int>(poly.breakpoints.size()); m++) {
        if (poly.breakpoints[m] <= input && input < poly.breakpoints[m + 1]) {
            segment = m;
            break;
        }
    }
    const double x = real_from_fixed(input, poly.Bin, poly.scale);
    double total = 0.0;
    double power = 1.0;
    const double factor = static_cast<double>(uint64_t(1) << poly.scale);
    for (int i = 0; i <= poly.degree; i++) {
        const GroupElement coeff =
            poly.coefficients[segment * (poly.degree + 1) + i];
        const double c =
            static_cast<double>(signed_from_twos(coeff.value, poly.Bout)) /
            factor;
        total += c * power;
        power *= x;
    }
    return total;
}

}  // namespace

void run_lut_bench(const BenchConfig& config) {
    const int Bin = config.Bin;
    const int Bout = config.Bout;
    const PublicLUTData table = make_bench_lut(Bin, Bout);
    const uint64_t domain = uint64_t(1) << Bin;
    const uint64_t input = domain / 5;
    const bool runAllProtocols = config.protocol == "all";

    auto emit = [&](const std::string& protocol, const std::string& phase,
                    const PhaseMetric& metric, bool ok,
                    const std::string& notes, int suffix) {
        Row row;
        row.group = "lut";
        row.protocol = protocol;
        row.phase = phase;
        row.Bin = Bin;
        row.Bout = Bout;
        row.repeat = config.repeat;
        row.suffixBits = suffix;
        row.evaluatedPoints = static_cast<int>(domain);
        row.metric = metric;
        row.status = ok ? "ok" : "correctness_failed";
        row.notes = notes + ";" + correctness_note(config);
        emit_row(row);
    };

    if (config.et && (runAllProtocols || config.protocol == "et")) {
        const int suffix = config_suffix_bits(config);
        PhaseMetric offline, online;
        bool ok = true;
        for (int i = 0; i < config.repeat; i++) {
            dfss::PublicLutOptions options;
            options.early_termination = true;
            options.suffix_bits = config.suffixBits;
            PublicLutKeyPack key;
            add_metric(offline, measure_offline_phase([&] {
                           key = dfss::publicLutOffline(party, table, options);
                       }));
            if (phase_runs_online(config)) {
                GroupElement out(0, Bout);
                add_metric(online, measure_online_phase([&] {
                               out = dfss::publicLut(
                                   party,
                                   split_share(input, Bin, input + 11 + i),
                                   table, key);
                           }));
                if (config.checkCorrectness) {
                    reconstruct_for_check(out);
                    ok = ok && out.value == table.values[input].value;
                }
            }
            freePublicLutKeyPack(key);
        }
        emit("dfss::publicLut_et", "offline", offline, ok,
             config.suffixBits < 0 ? "default_suffix" : "explicit_suffix",
             suffix);
        if (phase_runs_online(config)) {
            emit("dfss::publicLut_et", "online", online, ok,
                 "single_lookup", suffix);
        }
    }

    if ((!config.et && runAllProtocols) || config.protocol == "full" ||
        config.protocol == "baseline" ||
        (runAllProtocols && config.et)) {
        PhaseMetric offline, online;
        bool ok = true;
        for (int i = 0; i < config.repeat; i++) {
            dfss::PublicLutOptions options;
            options.early_termination = false;
            PublicLutKeyPack key;
            add_metric(offline, measure_offline_phase([&] {
                           key = dfss::publicLutOffline(party, table, options);
                       }));
            if (phase_runs_online(config)) {
                GroupElement out(0, Bout);
                add_metric(online, measure_online_phase([&] {
                               out = dfss::publicLut(
                                   party,
                                   split_share(input, Bin, input + 13 + i),
                                   table, key);
                           }));
                if (config.checkCorrectness) {
                    reconstruct_for_check(out);
                    ok = ok && out.value == table.values[input].value;
                }
            }
            freePublicLutKeyPack(key);
        }
        emit("dfss::publicLut_full", "offline", offline, ok,
             "full_dpf_lut", -1);
        if (phase_runs_online(config)) {
            emit("dfss::publicLut_full", "online", online, ok,
                 "single_lookup", -1);
        }
    }
}

void run_equality_bench(const BenchConfig& config) {
    const int Bin = config.Bin;
    const int Bout = config.Bout;
    const uint64_t domain = uint64_t(1) << Bin;
    const uint64_t point = domain / 3;
    const bool runAllProtocols = config.protocol == "all";

    if (runAllProtocols || config.protocol == "dfss" ||
        config.protocol == "arithmetic") {
        PhaseMetric offline, online;
        bool ok = true;
        for (int i = 0; i < config.repeat; i++) {
            EqualityKey key;
            add_metric(offline, measure_offline_phase([&] {
                           key = dfss::equalityOffline(
                               party, split_share(point, Bin, point + 810 + i),
                               split_share(1, Bout, 830 + i));
                       }));
            if (phase_runs_online(config)) {
                const uint64_t query =
                    (i % 2 == 0) ? point : ((point + 1) & (domain - 1));
                GroupElement output(0, Bout);
                add_metric(online, measure_online_phase([&] {
                               output = dfss::equality(
                                   party,
                                   split_share(query, Bin, query + 850 + i),
                                   key);
                           }));
                if (config.checkCorrectness) {
                    reconstruct_for_check(output);
                    ok = ok && output.value == (query == point ? 1U : 0U);
                }
            }
            freeEqualityKey(key);
        }

        Row row;
        row.group = "equality";
        row.protocol = "dfss::equality";
        row.phase = "offline";
        row.Bin = Bin;
        row.Bout = Bout;
        row.repeat = config.repeat;
        row.evaluatedPoints = 1;
        row.metric = offline;
        row.status = ok ? "ok" : "correctness_failed";
        row.notes = "arithmetic_output;equality_api;" +
                    correctness_note(config);
        emit_row(row);
        if (phase_runs_online(config)) {
            row.phase = "online";
            row.metric = online;
            emit_row(row);
        }
    }

    if (runAllProtocols || config.protocol == "bit" ||
        config.protocol == "boolean") {
        PhaseMetric offline, online;
        bool ok = true;
        for (int i = 0; i < config.repeat; i++) {
            EqualityKey key;
            add_metric(offline, measure_offline_phase([&] {
                           key = dfss::equalityBitOffline(
                               party,
                               split_share(point, Bin, point + 1810 + i));
                       }));
            if (phase_runs_online(config)) {
                const uint64_t query =
                    (i % 2 == 0) ? point : ((point + 1) & (domain - 1));
                BooleanElement output = 0;
                add_metric(online, measure_online_phase([&] {
                               output = dfss::equalityBit(
                                   party,
                                   split_share(query, Bin, query + 1850 + i),
                                   key);
                           }));
                if (config.checkCorrectness) {
                    reconstruct(&output);
                    ok = ok && output == static_cast<BooleanElement>(
                                          query == point ? 1U : 0U);
                }
            }
            freeEqualityKey(key);
        }

        Row row;
        row.group = "equality";
        row.protocol = "dfss::equalityBit";
        row.phase = "offline";
        row.Bin = Bin;
        row.Bout = 1;
        row.repeat = config.repeat;
        row.evaluatedPoints = 1;
        row.metric = offline;
        row.status = ok ? "ok" : "correctness_failed";
        row.notes = "boolean_output;equality_bit_api;" +
                    correctness_note(config);
        emit_row(row);
        if (phase_runs_online(config)) {
            row.phase = "online";
            row.metric = online;
            emit_row(row);
        }
    }
}

void run_mic_bench(const BenchConfig& config) {
    const int Bin = config.Bin;
    const int Bout = config.Bout;
    const int intervalsCount = config.parts > 0 ? config.parts : 1;
    const uint64_t domain = uint64_t(1) << Bin;
    std::vector<PublicInterval> intervals(intervalsCount);
    for (int i = 0; i < intervalsCount; i++) {
        const uint64_t left = (domain * static_cast<uint64_t>(i)) /
                              static_cast<uint64_t>(intervalsCount + 2);
        const uint64_t width = std::max<uint64_t>(1, domain / 8);
        intervals[i] = {left, std::min(domain, left + width)};
    }

    PhaseMetric offline, online;
    bool ok = true;
    for (int i = 0; i < config.repeat; i++) {
        MICKeyPack key;
        add_metric(offline, measure_offline_phase([&] {
                       key = dfss::micOffline(
                           party, Bin, Bout, split_share(1, Bout, 50 + i));
                   }));
        if (phase_runs_online(config)) {
            std::vector<GroupElement> output(intervalsCount);
            const uint64_t input = (domain / 3 + i) & (domain - 1);
            add_metric(online, measure_online_phase([&] {
                           dfss::mic(
                               party,
                               split_share(input, Bin, input + 70 + i),
                               intervals.data(), intervalsCount,
                               output.data(), key);
                       }));
            if (config.checkCorrectness) {
                reconstruct(intervalsCount, output.data(), Bout);
                for (int j = 0; j < intervalsCount; j++) {
                    const bool inside =
                        intervals[j].left <= input && input < intervals[j].right;
                    ok = ok && output[j].value == (inside ? 1U : 0U);
                }
            }
        }
        freeMICKeyPack(key);
    }

    Row row;
    row.group = "mic";
    row.protocol = "mic";
    row.phase = "offline";
    row.Bin = Bin;
    row.Bout = Bout;
    row.repeat = config.repeat;
    row.intervalCount = intervalsCount;
    row.metric = offline;
    row.status = ok ? "ok" : "correctness_failed";
    row.notes = "parts_as_interval_count;" + correctness_note(config);
    emit_row(row);
    if (phase_runs_online(config)) {
        row.phase = "online";
        row.metric = online;
        emit_row(row);
    }
}

void run_comparison_bench(const BenchConfig& config) {
    const int Bin = config.Bin;
    const int Bout = config.Bout;
    const uint64_t domain = uint64_t(1) << Bin;
    const uint64_t threshold = domain / 2;
    const bool runAllProtocols = config.protocol == "all";

    if (runAllProtocols || config.protocol == "dfss" ||
        config.protocol == "arithmetic") {
        PhaseMetric offline, online;
        bool ok = true;
        for (int i = 0; i < config.repeat; i++) {
            ComparisonKeyPack key;
            add_metric(offline, measure_offline_phase([&] {
                key = dfss::comparisonOffline(
                    party, Bin, Bout, split_share(1, Bout, 910 + i));
            }));
            if (phase_runs_online(config)) {
                const uint64_t input = (threshold - 3 + i) & (domain - 1);
                GroupElement output(0, Bout);
                add_metric(online, measure_online_phase([&] {
                    output = dfss::comparison(
                        party, split_share(input, Bin, input + 920 + i),
                        threshold, key);
                }));
                if (config.checkCorrectness) {
                    reconstruct_for_check(output);
                    ok = ok && output.value == (input < threshold ? 1U : 0U);
                }
            }
            freeComparisonKeyPack(key);
        }

        Row row;
        row.group = "comparison";
        row.protocol = "dfss::comparison";
        row.phase = "offline";
        row.Bin = Bin;
        row.Bout = Bout;
        row.repeat = config.repeat;
        row.intervalCount = 1;
        row.metric = offline;
        row.status = ok ? "ok" : "correctness_failed";
        row.notes = "arithmetic_output;single_threshold;" +
                    correctness_note(config);
        emit_row(row);
        if (phase_runs_online(config)) {
            row.phase = "online";
            row.metric = online;
            emit_row(row);
        }
    }

    if (runAllProtocols || config.protocol == "bit" ||
        config.protocol == "boolean") {
        PhaseMetric offline, online;
        bool ok = true;
        for (int i = 0; i < config.repeat; i++) {
            ComparisonBitKeyPack key;
            add_metric(offline, measure_offline_phase([&] {
                key = dfss::comparisonBitOffline(party, Bin);
            }));
            if (phase_runs_online(config)) {
                const uint64_t input = (threshold - 3 + i) & (domain - 1);
                BooleanElement output = 0;
                add_metric(online, measure_online_phase([&] {
                    output = dfss::comparisonBit(
                        party, split_share(input, Bin, input + 1920 + i),
                        threshold, key);
                }));
                if (config.checkCorrectness) {
                    reconstruct(&output);
                    ok = ok && output == static_cast<BooleanElement>(
                                          input < threshold ? 1U : 0U);
                }
            }
            freeComparisonBitKeyPack(key);
        }

        Row row;
        row.group = "comparison";
        row.protocol = "dfss::comparisonBit";
        row.phase = "offline";
        row.Bin = Bin;
        row.Bout = 1;
        row.repeat = config.repeat;
        row.intervalCount = 1;
        row.metric = offline;
        row.status = ok ? "ok" : "correctness_failed";
        row.notes = "boolean_output;single_threshold;comparison_bit_api;" +
                    correctness_note(config);
        emit_row(row);
        if (phase_runs_online(config)) {
            row.phase = "online";
            row.metric = online;
            emit_row(row);
        }
    }
}

void run_poly_bench(const BenchConfig& config) {
    const int Bin = config.Bin;
    const int Bout = config.Bout;
    const int scale = config.scale;
    const int degree = config.degree;
    const int segments = config.parts;
    PublicPiecewisePolyData poly =
        make_exact_poly(Bin, Bout, scale, degree, segments);
    const uint64_t domain = uint64_t(1) << Bin;
    PhaseMetric offline, online;
    bool ok = true;
    double plainMax = 0.0;
    double cipherPlainMax = 0.0;

    for (int i = 0; i < config.repeat; i++) {
        MICPolyEvalKeyPack key;
        add_metric(offline, measure_offline_phase([&] {
                       key = dfss::micPolyEvalOffline(party, poly);
                   }));
        if (phase_runs_online(config)) {
            const uint64_t input =
                (domain * static_cast<uint64_t>(i + 1)) /
                static_cast<uint64_t>(config.repeat + 1);
            GroupElement secureOut(0, Bout);
            add_metric(online, measure_online_phase([&] {
                           secureOut = dfss::micPolyEval(
                               party,
                               split_share(input, Bin, input + 90 + i),
                               poly, key);
                       }));
            if (config.checkCorrectness) {
                reconstruct_for_check(secureOut);
                const uint64_t plainFixed = eval_plain_poly_fixed(input, poly);
                const double plainReal = eval_real_poly(input, poly);
                const double plainFixedReal =
                    real_from_fixed(plainFixed, Bout, scale);
                const double secureReal =
                    real_from_fixed(secureOut.value, Bout, scale);
                plainMax =
                    std::max(plainMax, std::abs(plainReal - plainFixedReal));
                cipherPlainMax = std::max(
                    cipherPlainMax, std::abs(secureReal - plainFixedReal));
                ok = ok && secureOut.value == plainFixed;
            }
        }
        freeMICPolyEvalKeyPack(key);
    }

    Row row;
    row.group = "poly";
    row.protocol = "dfss::micPolyEval";
    row.phase = "offline";
    row.Bin = Bin;
    row.Bout = Bout;
    row.repeat = config.repeat;
    row.degree = degree;
    row.scale = scale;
    row.segments = segments;
    row.evaluatedPoints = config.repeat;
    row.metric = offline;
    row.plaintextMaxAbsError = plainMax;
    row.ciphertextVsPlaintextMaxAbsError = cipherPlainMax;
    row.status = ok ? "ok" : "correctness_failed";
    row.notes = "parts_as_segments;exact_public_polynomial;" +
                correctness_note(config);
    emit_row(row);
    if (phase_runs_online(config)) {
        row.phase = "online";
        row.metric = online;
        emit_row(row);
    }
}
