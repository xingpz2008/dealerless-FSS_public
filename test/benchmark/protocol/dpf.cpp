#include "benchmarks.h"
#include "common.h"
#include "report.h"

// DPF and iDPF benchmarks.

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

namespace {

std::vector<u8> msb_bits_from_value(uint64_t value, int bits) {
    std::vector<u8> output(bits);
    for (int i = 0; i < bits; i++) {
        output[i] = static_cast<u8>((value >> (bits - 1 - i)) & 1);
    }
    return output;
}

std::vector<u8> split_bit_share(uint64_t value, int bits,
                                uint64_t server_share) {
    const uint64_t local_share =
        party == SERVER ? server_share : (value ^ server_share);
    return msb_bits_from_value(local_share, bits);
}

block split_block_share(block value, block server_share) {
    return party == SERVER ? server_share : (value ^ server_share);
}

}  // namespace

void run_dpf_bench(const BenchConfig& config) {
    if (config.et) {
        run_et_bench(config);
        return;
    }
    const int Bin = config.Bin;
    const int Bout = config.Bout;
    const uint64_t domain = uint64_t(1) << Bin;
    const uint64_t point = domain / 3;
    const uint64_t payload = 11;
    const bool runAllProtocols = config.protocol == "all";

    auto emit = [&](const std::string& protocol, const std::string& phase,
                    const PhaseMetric& metric, bool ok,
                    const std::string& notes, int rowBout) {
        Row row;
        row.group = "dpf";
        row.protocol = protocol;
        row.phase = phase;
        row.Bin = Bin;
        row.Bout = rowBout;
        row.repeat = config.repeat;
        row.evaluatedPoints = 1;
        row.metric = metric;
        row.status = ok ? "ok" : "correctness_failed";
        row.notes = notes + ";" + correctness_note(config);
        emit_row(row);
    };

    if (runAllProtocols || config.protocol == "correlated" ||
        config.protocol == "correlated_dpf") {
        PhaseMetric offline, online;
        bool ok = true;
        for (int i = 0; i < config.repeat; i++) {
            DPFKeyPack key;
            add_metric(offline, measure_offline_phase([&] {
                           key = keyGenCorrelatedDPF(
                               party, Bin, Bout,
                               split_share(point, Bin, point + 2100 + i),
                               split_share(payload, Bout, 2200 + i), false);
                       }));
            if (phase_runs_online(config)) {
                GroupElement out(0, Bout);
                add_metric(online, measure_online_phase([&] {
                               evalCorrelatedDPF(
                                   party, &out, GroupElement(point, Bin),
                                   key, false);
                           }));
                if (config.checkCorrectness) {
                    reconstruct_for_check(out);
                    ok = ok && out.value == (payload & mask_for_bits(Bout));
                }
            }
            freeDPFKeyPack(key);
        }
        emit("correlated_dpf_lsb_trick", "offline", offline, ok,
             "second_lsb_payload_choice", Bout);
        if (phase_runs_online(config)) {
            emit("correlated_dpf_lsb_trick", "online", online, ok,
                 "single_point_eval", Bout);
        }
    }

    if (runAllProtocols || config.protocol == "full_ggm") {
        PhaseMetric offline, online;
        bool ok = true;
        for (int i = 0; i < config.repeat; i++) {
            DPFKeyPack key;
            add_metric(offline, measure_offline_phase([&] {
                           key = dfss::keyGenArithmeticDPF(
                               party,
                               split_share(point, Bin, point + 2300 + i),
                               split_share(payload, Bout, 2400 + i), false,
                               false);
                       }));
            if (phase_runs_online(config)) {
                GroupElement out(0, Bout);
                add_metric(online, measure_online_phase([&] {
                               out = dfss::evalArithmeticDPF(
                                   party, GroupElement(point, Bin), key,
                                   false, false);
                           }));
                if (config.checkCorrectness) {
                    reconstruct_for_check(out);
                    ok = ok && out.value == (payload & mask_for_bits(Bout));
                }
            }
            freeDPFKeyPack(key);
        }
        emit("full_ggm_dpf", "offline", offline, ok,
             "arithmetic_payload_conversion", Bout);
        if (phase_runs_online(config)) {
            emit("full_ggm_dpf", "online", online, ok, "single_point_eval",
                 Bout);
        }
    }

    if (runAllProtocols || config.protocol == "boolean" ||
        config.protocol == "block") {
        const block blockPayload =
            osuCrypto::toBlock(0x123456789abcdef0ULL,
                               0x0fedcba987654321ULL);
        const block blockPayloadServerShare =
            osuCrypto::toBlock(0x1111222233334444ULL,
                               0x5555666677778888ULL);
        PhaseMetric offline, online;
        bool ok = true;
        for (int i = 0; i < config.repeat; i++) {
            BooleanDPFKeyPack key;
            add_metric(offline, measure_offline_phase([&] {
                           std::vector<u8> pointBits =
                               split_bit_share(point, Bin, point + 2500 + i);
                           key = dfss::wrapper::keyGenDPF(
                               party, Bin, pointBits.data(),
                               split_block_share(blockPayload,
                                                 blockPayloadServerShare),
                               false);
                       }));
            if (phase_runs_online(config)) {
                block out = ZeroBlock;
                add_metric(online, measure_online_phase([&] {
                               std::vector<u8> queryBits =
                                   split_bit_share(point, Bin,
                                                   point + 2600 + i);
                               out = dfss::wrapper::evalDPFBlock(
                                   party, queryBits.data(), key, false);
                           }));
                if (config.checkCorrectness) {
                    reconstruct(&out);
                    ok = ok && memcmp(&out, &blockPayload, sizeof(block)) == 0;
                }
            }
            freeBooleanDPFKeyPack(key);
        }
        emit("block_correlated_dpf_xor_payload", "offline", offline, ok,
             "block_xor_payload", 128);
        if (phase_runs_online(config)) {
            emit("block_correlated_dpf_xor_payload", "online", online, ok,
                 "single_point_eval", 128);
        }
    }
}

void run_idpf_bench(const BenchConfig& config) {
    const int Bin = config.Bin;
    const int Bout = config.Bout;
    const uint64_t domain = uint64_t(1) << Bin;
    const uint64_t point = domain / 3;
    PhaseMetric offline, online;
    bool ok = true;
    for (int i = 0; i < config.repeat; i++) {
        std::vector<GroupElement> payloads(Bin);
        std::vector<uint64_t> expected(Bin);
        for (int level = 0; level < Bin; level++) {
            expected[level] = (uint64_t(3 + level + i) & mask_for_bits(Bout));
            payloads[level] =
                split_share(expected[level], Bout, 2500 + 17 * level + i);
        }

        DPFKeyPack key;
        add_metric(offline, measure_offline_phase([&] {
                       key = keyGeniDPF(
                           party, Bin, Bout,
                           split_share(point, Bin, point + 2600 + i),
                           payloads.data(), false, false);
                   }));
        if (phase_runs_online(config)) {
            std::vector<GroupElement> output;
            add_metric(online, measure_online_phase([&] {
                           output = evaliDPF(
                               party, GroupElement(point, Bin), key, false);
                       }));
            if (config.checkCorrectness) {
                reconstruct(static_cast<int>(output.size()), output.data(),
                            Bout);
                ok = ok && check_reconstructed_vector(output, expected);
            }
        }
        freeDPFKeyPack(key);
    }

    Row row;
    row.group = "idpf";
    row.protocol = "idpf_pure_ggm_per_level_payload";
    row.phase = "offline";
    row.Bin = Bin;
    row.Bout = Bout;
    row.repeat = config.repeat;
    row.evaluatedPoints = 1;
    row.metric = offline;
    row.status = ok ? "ok" : "correctness_failed";
    row.notes = "ordinary_ggm;per_level_payloads;" + correctness_note(config);
    emit_row(row);
    if (phase_runs_online(config)) {
        row.phase = "online";
        row.evaluatedPoints = Bin;
        row.metric = online;
        emit_row(row);
    }
}
