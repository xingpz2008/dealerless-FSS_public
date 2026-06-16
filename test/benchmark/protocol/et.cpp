#include "benchmarks.h"
#include "common.h"
#include "report.h"

// DPF-ET primitive benchmark.

#include <string>
#include <vector>

using namespace osuCrypto;

void run_et_bench(const BenchConfig& config) {
    const int Bin = config.Bin;
    const int Bout = config.Bout;
    const int suffix = config_suffix_bits(config);
    const uint64_t domain = uint64_t(1) << Bin;
    const uint64_t point = domain / 3;
    const uint64_t payload = 11;
    const bool runAllProtocols = config.protocol == "all";

    auto emit = [&](const std::string& protocol, const std::string& phase,
                    const PhaseMetric& metric, bool ok,
                    const std::string& notes) {
        Row row;
        row.group = "et";
        row.protocol = protocol;
        row.phase = phase;
        row.Bin = Bin;
        row.Bout = Bout;
        row.repeat = config.repeat;
        row.suffixBits = suffix;
        row.evaluatedPoints = 1;
        row.metric = metric;
        row.status = ok ? "ok" : "correctness_failed";
        row.notes = notes + ";" + correctness_note(config);
        emit_row(row);
    };

    if (runAllProtocols || config.protocol == "dpf_et" ||
        config.protocol == "et") {
        PhaseMetric offline, online;
        bool ok = true;
        for (int i = 0; i < config.repeat; i++) {
            DPFETKeyPack key;
            add_metric(offline, measure_offline_phase([&] {
                           if (config.suffixBits < 0) {
                               key = keyGenDPFET(
                                   party, Bin, Bout,
                                   split_share(point, Bin, point + 100 + i),
                                   split_share(payload, Bout, 200 + i));
                           } else {
                               key = keyGenDPFET(
                                   party, Bin, Bout, config.suffixBits,
                                   split_share(point, Bin, point + 100 + i),
                                   split_share(payload, Bout, 200 + i));
                           }
                       }));
            if (phase_runs_online(config)) {
                GroupElement out(0, Bout);
                add_metric(online, measure_online_phase([&] {
                               out = evalDPFET(party, point, key);
                           }));
                if (config.checkCorrectness) {
                    reconstruct_for_check(out);
                    ok = ok && out.value == (payload & mask_for_bits(Bout));
                }
            }
            freeDPFETKeyPack(key);
        }
        emit("dpf_et", "offline", offline, ok,
             config.suffixBits < 0 ? "default_suffix" : "explicit_suffix");
        if (phase_runs_online(config)) {
            emit("dpf_et", "online", online, ok, "single_point_eval");
        }
    }

    if (runAllProtocols || config.protocol == "correlated" ||
        config.protocol == "correlated_dpf") {
        PhaseMetric offline, online;
        bool ok = true;
        for (int i = 0; i < config.repeat; i++) {
            DPFKeyPack key;
            add_metric(offline, measure_offline_phase([&] {
                           key = keyGenCorrelatedDPF(
                               party, Bin, Bout,
                               split_share(point, Bin, point + 300 + i),
                               split_share(payload, Bout, 400 + i), false);
                       }));
            if (phase_runs_online(config)) {
                GroupElement out(0, Bout);
                add_metric(online, measure_online_phase([&] {
                               evalCorrelatedDPF(party, &out,
                                                 GroupElement(point, Bin),
                                                 key, false);
                           }));
                if (config.checkCorrectness) {
                    reconstruct_for_check(out);
                    ok = ok && out.value == (payload & mask_for_bits(Bout));
                }
            }
            freeDPFKeyPack(key);
        }
        emit("correlated_dpf", "offline", offline, ok, "baseline_for_et");
        if (phase_runs_online(config)) {
            emit("correlated_dpf", "online", online, ok, "single_point_eval");
        }
    }

    if (runAllProtocols || config.protocol == "full_ggm") {
        PhaseMetric offline, online;
        bool ok = true;
        for (int i = 0; i < config.repeat; i++) {
            DPFKeyPack key;
            add_metric(offline, measure_offline_phase([&] {
                           key = dfss::keyGenArithmeticDPF(
                               party, split_share(point, Bin, point + 500 + i),
                               split_share(payload, Bout, 600 + i), false,
                               false);
                       }));
            if (phase_runs_online(config)) {
                GroupElement out(0, Bout);
                add_metric(online, measure_online_phase([&] {
                               out = dfss::evalArithmeticDPF(
                                   party, GroupElement(point, Bin), key, false,
                                   false);
                           }));
                if (config.checkCorrectness) {
                    reconstruct_for_check(out);
                    ok = ok && out.value == (payload & mask_for_bits(Bout));
                }
            }
            freeDPFKeyPack(key);
        }
        emit("full_ggm_dpf", "offline", offline, ok,
             "dfss_full_ggm_point_baseline_for_et");
        if (phase_runs_online(config)) {
            emit("full_ggm_dpf", "online", online, ok, "single_point_eval");
        }
    }
}
