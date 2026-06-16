#include "cases.h"

// Primitive FSS correctness cases for key generation and evaluation paths.

#include <string>
#include <vector>

namespace {

block split_block_share(block value, block server_share) {
    return party == SERVER ? server_share : value ^ server_share;
}

}  // namespace

void check_correlated_dpf(ResultLog& log) {
    constexpr uint64_t payload = 13;
    constexpr int entries = 1 << kBin;
    for (uint64_t point : {uint64_t(0), uint64_t(6), uint64_t(entries - 1)}) {
        DPFKeyPack key = keyGenCorrelatedDPF(
            party, kBin, kBout, split_share(point, kBin, point + 5),
            split_share(payload, kBout, 211 + point), false);
        std::vector<GroupElement> outputs(entries);
        std::vector<uint64_t> expected(entries);
        for (int i = 0; i < entries; ++i) {
            evalCorrelatedDPF(party, &outputs[i], GroupElement(i, kBin), key,
                              false);
            expected[i] = i == static_cast<int>(point) ? payload : 0;
        }
        log.check_vector("correlated DPF full domain point " +
                             std::to_string(point),
                         outputs.data(), expected, kBout);

        std::vector<GroupElement> eval_all_outputs(entries);
        for (int i = 0; i < entries; ++i) {
            eval_all_outputs[i] = GroupElement(0, kBout);
        }
        evalAllCorrelatedDPF(party, eval_all_outputs.data(), key, kBin);
        log.check_vector("correlated DPF evalAll point " +
                             std::to_string(point),
                         eval_all_outputs.data(), expected, kBout);

        std::vector<GroupElement> unified_eval_all_outputs(entries);
        for (int i = 0; i < entries; ++i) {
            unified_eval_all_outputs[i] = GroupElement(0, kBout);
        }
        evalAllDPF(party, unified_eval_all_outputs.data(), key);
        log.check_vector("correlated DPF unified evalAll point " +
                             std::to_string(point),
                         unified_eval_all_outputs.data(), expected, kBout);
        free_dpf_key(key);
    }

    DPFKeyPack masked_key = keyGenCorrelatedDPF(
        party, kBin, kBout, split_share(9, kBin, 27),
        split_share(payload, kBout, 77), true);
    GroupElement masked_hit =
        evalCorrelatedDPF(party, split_share(9, kBin, 31), masked_key, true);
    GroupElement masked_miss =
        evalCorrelatedDPF(party, split_share(10, kBin, 31), masked_key, true);
    log.check_scalar("correlated DPF masked hit", masked_hit, payload);
    log.check_scalar("correlated DPF masked miss", masked_miss, 0);
    free_dpf_key(masked_key);

    std::vector<u8> point_bits = split_bit_share(9, kBin, 5);
    DPFKeyPack masked_bits_key = dfss::wrapper::keyGenDPF(
        party, kBin, point_bits.data(), split_share(payload, kBout, 91),
        {true, true, -1});
    std::vector<u8> hit_bits = split_bit_share(9, kBin, 12);
    std::vector<u8> miss_bits = split_bit_share(10, kBin, 12);
    GroupElement masked_bits_hit = dfss::wrapper::evalDPF(
        party, hit_bits.data(), masked_bits_key, {true, true, -1});
    GroupElement masked_bits_miss = dfss::wrapper::evalDPF(
        party, miss_bits.data(), masked_bits_key, {true, true, -1});
    GroupElement masked_bits_void_hit(0, kBout);
    dfss::wrapper::evalDPF(party, &masked_bits_void_hit, hit_bits.data(),
                           masked_bits_key, {true, true, -1});
    log.check_scalar("correlated DPF Boolean-share masked hit",
                     masked_bits_hit, payload);
    log.check_scalar("correlated DPF Boolean-share masked miss",
                     masked_bits_miss, 0);
    log.check_scalar("correlated DPF Boolean-share masked void hit",
                     masked_bits_void_hit, payload);
    free_dpf_key(masked_bits_key);

    point_bits = split_bit_share(7, kBin, 3);
    DPFKeyPack unmasked_bits_key = dfss::wrapper::keyGenDPF(
        party, kBin, point_bits.data(), split_share(payload, kBout, 53),
        {false, true, -1});
    hit_bits = split_bit_share(7, kBin, 6);
    miss_bits = split_bit_share(8, kBin, 6);
    GroupElement unmasked_bits_hit = dfss::wrapper::evalDPF(
        party, hit_bits.data(), unmasked_bits_key, {false, true, -1});
    GroupElement unmasked_bits_miss = dfss::wrapper::evalDPF(
        party, miss_bits.data(), unmasked_bits_key, {false, true, -1});
    log.check_scalar("correlated DPF Boolean-share unmasked hit",
                     unmasked_bits_hit, payload);
    log.check_scalar("correlated DPF Boolean-share unmasked miss",
                     unmasked_bits_miss, 0);
    free_dpf_key(unmasked_bits_key);

    point_bits = split_bit_share(11, kBin, 4);
    DPFKeyPack from_bits_key = dfss::keyGenCorrelatedDPF(
        party, kBin, kBout, point_bits.data(),
        split_share(payload, kBout, 61));
    GroupElement from_bits_hit = dfss::evalCorrelatedDPF(
        party, GroupElement(11, kBin), from_bits_key);
    GroupElement from_bits_miss = dfss::evalCorrelatedDPF(
        party, GroupElement(12, kBin), from_bits_key);
    log.check_scalar("fss/dpf arithmetic hit", from_bits_hit,
                     payload);
    log.check_scalar("fss/dpf arithmetic miss", from_bits_miss, 0);
    free_dpf_key(from_bits_key);

    DPFKeyPack wrapper_key = dfss::keyGenArithmeticDPF(
        party, split_share(2, kBin, 15), split_share(payload, kBout, 17),
        true, false);
    GroupElement wrapper_hit = dfss::evalCorrelatedDPF(
        party, GroupElement(2, kBin), wrapper_key);
    GroupElement wrapper_miss = dfss::evalCorrelatedDPF(
        party, GroupElement(3, kBin), wrapper_key);
    GroupElement wrapper_void_hit(0, kBout);
    dfss::wrapper::evalDPF(party, &wrapper_void_hit, GroupElement(2, kBin),
                           wrapper_key, {false, true, -1});
    log.check_scalar("fss/wrapper arithmetic hit", wrapper_hit, payload);
    log.check_scalar("fss/wrapper arithmetic miss", wrapper_miss, 0);
    log.check_scalar("fss/wrapper arithmetic void hit", wrapper_void_hit,
                     payload);
    free_dpf_key(wrapper_key);

    dfss::wrapper::DPFOptions full_ggm_options;
    full_ggm_options.masked = true;
    full_ggm_options.correlated = false;
    DPFKeyPack full_ggm_wrapper_key = dfss::wrapper::keyGenDPF(
        party, split_share(9, kBin, 27), split_share(payload, kBout, 31),
        full_ggm_options);
    GroupElement full_ggm_wrapper_hit = dfss::wrapper::evalDPF(
        party, split_share(9, kBin, 29), full_ggm_wrapper_key,
        full_ggm_options);
    GroupElement full_ggm_wrapper_miss = dfss::wrapper::evalDPF(
        party, split_share(10, kBin, 29), full_ggm_wrapper_key,
        full_ggm_options);
    log.check_scalar("fss/wrapper full-GGM arithmetic hit",
                     full_ggm_wrapper_hit, payload);
    log.check_scalar("fss/wrapper full-GGM arithmetic miss",
                     full_ggm_wrapper_miss, 0);
    free_dpf_key(full_ggm_wrapper_key);

    DPFKeyPack bit_key = keyGenCorrelatedDPFBit(
        party, kBin, split_share(6, kBin, 41), true);
    u8 bit_hit = evalCorrelatedDPFBit(
        party, split_share(6, kBin, 43), bit_key, true);
    u8 bit_miss = evalCorrelatedDPFBit(
        party, split_share(7, kBin, 43), bit_key, true);
    log.check_bit("correlated DPF bit masked hit", bit_hit, 1);
    log.check_bit("correlated DPF bit masked miss", bit_miss, 0);
    free_dpf_key(bit_key);

    DPFKeyPack wrapper_bit_key =
        dfss::wrapper::keyGenDPF(party, split_share(12, kBin, 47), true);
    u8 wrapper_bit_hit = dfss::wrapper::evalDPFBit(
        party, split_share(12, kBin, 49), wrapper_bit_key, true);
    u8 wrapper_bit_miss = dfss::wrapper::evalDPFBit(
        party, split_share(13, kBin, 49), wrapper_bit_key, true);
    log.check_bit("fss/wrapper Boolean hit", wrapper_bit_hit, 1);
    log.check_bit("fss/wrapper Boolean miss", wrapper_bit_miss, 0);
    free_dpf_key(wrapper_bit_key);

    point_bits = split_bit_share(6, kBin, 2);
    DPFKeyPack bit_path_key =
        dfss::wrapper::keyGenDPF(party, kBin, point_bits.data(), true);
    hit_bits = split_bit_share(6, kBin, 9);
    miss_bits = split_bit_share(7, kBin, 9);
    u8 bit_path_hit =
        dfss::wrapper::evalDPFBit(party, hit_bits.data(), bit_path_key, true);
    u8 bit_path_miss =
        dfss::wrapper::evalDPFBit(party, miss_bits.data(), bit_path_key, true);
    log.check_bit("correlated DPF bit Boolean-share masked hit",
                  bit_path_hit, 1);
    log.check_bit("correlated DPF bit Boolean-share masked miss",
                  bit_path_miss, 0);
    free_dpf_key(bit_path_key);

    point_bits = split_bit_share(3, kBin, 2);
    DPFKeyPack bit_from_bits_key =
        dfss::keyGenCorrelatedDPFBit(party, kBin, point_bits.data());
    u8 bit_from_bits_hit = dfss::evalCorrelatedDPFBit(
        party, GroupElement(3, kBin), bit_from_bits_key);
    u8 bit_from_bits_miss = dfss::evalCorrelatedDPFBit(
        party, GroupElement(4, kBin), bit_from_bits_key);
    log.check_bit("fss/dpf Boolean hit", bit_from_bits_hit, 1);
    log.check_bit("fss/dpf Boolean miss", bit_from_bits_miss, 0);
    free_dpf_key(bit_from_bits_key);
}

void check_boolean_correlated_dpf(ResultLog& log) {
    const block payload = osuCrypto::toBlock(0x123456789abcdef0ULL,
                                             0x0fedcba987654321ULL);
    const block server_payload_share =
        osuCrypto::toBlock(0x1111222233334444ULL, 0x5555666677778888ULL);
    struct BooleanDpfCase {
        uint64_t point;
        uint64_t query;
    };
    const BooleanDpfCase cases[] = {
        {0, 0},
        {0, 1},
        {6, 6},
        {6, 7},
        {uint64_t((1 << kBin) - 1), uint64_t((1 << kBin) - 1)},
        {uint64_t((1 << kBin) - 1), 0},
    };

    for (const auto& test : cases) {
        BooleanDPFKeyPack masked_key = keyGenBooleanCorrelatedDPF(
            party, kBin, split_share(test.point, kBin, test.point + 13),
            split_block_share(payload, server_payload_share), true);
        block masked_output = evalBooleanCorrelatedDPF(
            party, split_share(test.query, kBin, test.query + 19), masked_key,
            true);
        log.check_block("Boolean correlated DPF masked point " +
                            std::to_string(test.point) + " query " +
                            std::to_string(test.query),
                        masked_output,
                        test.point == test.query ? payload : ZeroBlock);
        freeBooleanDPFKeyPack(masked_key);

        BooleanDPFKeyPack unmasked_key = keyGenBooleanCorrelatedDPF(
            party, kBin, split_share(test.point, kBin, test.point + 23),
            split_block_share(payload, server_payload_share),
            false);
        block unmasked_output = evalBooleanCorrelatedDPF(
            party, GroupElement(test.query, kBin), unmasked_key, false);
        log.check_block("Boolean correlated DPF unmasked point " +
                            std::to_string(test.point) + " query " +
                            std::to_string(test.query),
                        unmasked_output,
                        test.point == test.query ? payload : ZeroBlock);
        freeBooleanDPFKeyPack(unmasked_key);
    }

    std::vector<u8> point_bits = split_bit_share(6, kBin, 3);
    BooleanDPFKeyPack masked_bits_key = dfss::wrapper::keyGenDPF(
        party, kBin, point_bits.data(),
        split_block_share(payload, server_payload_share), true);
    std::vector<u8> hit_bits = split_bit_share(6, kBin, 10);
    std::vector<u8> miss_bits = split_bit_share(7, kBin, 10);
    block masked_bits_hit = dfss::wrapper::evalDPFBlock(
        party, hit_bits.data(), masked_bits_key, true);
    block masked_bits_miss = dfss::wrapper::evalDPFBlock(
        party, miss_bits.data(), masked_bits_key, true);
    log.check_block("Boolean correlated DPF Boolean-share masked hit",
                    masked_bits_hit, payload);
    log.check_block("Boolean correlated DPF Boolean-share masked miss",
                    masked_bits_miss, ZeroBlock);
    freeBooleanDPFKeyPack(masked_bits_key);

    point_bits = split_bit_share(5, kBin, 1);
    BooleanDPFKeyPack unmasked_bits_key = dfss::wrapper::keyGenDPF(
        party, kBin, point_bits.data(),
        split_block_share(payload, server_payload_share), false);
    hit_bits = split_bit_share(5, kBin, 14);
    miss_bits = split_bit_share(4, kBin, 14);
    block unmasked_bits_hit = dfss::wrapper::evalDPFBlock(
        party, hit_bits.data(), unmasked_bits_key, false);
    block unmasked_bits_miss = dfss::wrapper::evalDPFBlock(
        party, miss_bits.data(), unmasked_bits_key, false);
    log.check_block("Boolean correlated DPF Boolean-share unmasked hit",
                    unmasked_bits_hit, payload);
    log.check_block("Boolean correlated DPF Boolean-share unmasked miss",
                    unmasked_bits_miss, ZeroBlock);
    freeBooleanDPFKeyPack(unmasked_bits_key);

    point_bits = split_bit_share(9, kBin, 6);
    BooleanDPFKeyPack from_bits_key = dfss::keyGenBooleanCorrelatedDPF(
        party, kBin, point_bits.data(),
        split_block_share(payload, server_payload_share));
    block from_bits_hit = dfss::evalBooleanCorrelatedDPF(
        party, GroupElement(9, kBin), from_bits_key);
    block from_bits_miss = dfss::evalBooleanCorrelatedDPF(
        party, GroupElement(10, kBin), from_bits_key);
    log.check_block("fss/dpf block hit", from_bits_hit, payload);
    log.check_block("fss/dpf block miss", from_bits_miss, ZeroBlock);
    freeBooleanDPFKeyPack(from_bits_key);

    BooleanDPFKeyPack wrapper_key = dfss::wrapper::keyGenDPF(
        party, split_share(2, kBin, 18),
        split_block_share(payload, server_payload_share), true);
    block wrapper_hit = dfss::wrapper::evalDPFBlock(
        party, split_share(2, kBin, 21), wrapper_key, true);
    block wrapper_miss = dfss::wrapper::evalDPFBlock(
        party, split_share(3, kBin, 21), wrapper_key, true);
    log.check_block("fss/wrapper block hit", wrapper_hit, payload);
    log.check_block("fss/wrapper block miss", wrapper_miss, ZeroBlock);
    freeBooleanDPFKeyPack(wrapper_key);
}

namespace {

std::vector<uint64_t> expected_idpf_outputs(
    uint64_t point, uint64_t query,
    const std::vector<uint64_t>& payloads, int bits) {
    std::vector<uint64_t> expected(payloads.size(), 0);
    bool prefix_matches = true;
    for (int level = 0; level < bits; level++) {
        const int shift = bits - 1 - level;
        const uint64_t point_bit = (point >> shift) & 1;
        const uint64_t query_bit = (query >> shift) & 1;
        prefix_matches = prefix_matches && (point_bit == query_bit);
        expected[level] = prefix_matches ? payloads[level] : 0;
    }
    return expected;
}

}  // namespace

void check_idpf(ResultLog& log) {
    const std::vector<uint64_t> payload_values = {3, 5, 7, 11};
    GroupElement payloads[kBin];
    for (int i = 0; i < kBin; i++) {
        payloads[i] = split_share(payload_values[i], kBout, 101 + i);
    }

    struct IdpfCase {
        uint64_t point;
        uint64_t query;
    };
    const IdpfCase cases[] = {
        {0, 0},
        {0, 1},
        {10, 10},
        {10, 11},
        {10, 2},
        {15, 14},
        {15, 15},
    };

    for (const auto& test : cases) {
        DPFKeyPack key = keyGeniDPF(
            party, kBin, kBout, split_share(test.point, kBin, test.point + 3),
            payloads, false, false);
        std::vector<GroupElement> output =
            evaliDPF(party, GroupElement(test.query, kBin), key, false);
        std::vector<uint64_t> expected =
            expected_idpf_outputs(test.point, test.query, payload_values, kBin);
        log.check_vector("iDPF point " + std::to_string(test.point) +
                             " query " + std::to_string(test.query),
                         output.data(), expected, kBout);
        free_dpf_key(key);
    }

    std::vector<u8> point_bits = split_bit_share(10, kBin, 12);
    DPFKeyPack from_bits_key = dfss::keyGeniDPF(
        party, kBin, kBout, point_bits.data(), payloads);
    std::vector<GroupElement> from_bits_output =
        dfss::evaliDPF(party, GroupElement(10, kBin), from_bits_key);
    std::vector<uint64_t> from_bits_expected =
        expected_idpf_outputs(10, 10, payload_values, kBin);
    log.check_vector("fss/idpf point 10 query 10",
                     from_bits_output.data(), from_bits_expected, kBout);
    free_dpf_key(from_bits_key);
}

void check_dpf_et(ResultLog& log) {
    constexpr uint64_t payload_value = 23;
    constexpr int entries = 1 << kBin;
    for (int suffix_bits : {0, 1, 2, 3}) {
        for (uint64_t point : {uint64_t(0), uint64_t(5),
                               uint64_t(entries - 1)}) {
            DPFETKeyPack key = keyGenDPFET(
                party, kBin, kBout, suffix_bits,
                split_share(point, kBin, point + 7),
                split_share(payload_value, kBout, 149 + point));

            std::vector<GroupElement> outputs(entries);
            for (int i = 0; i < entries; i++) {
                outputs[i] = GroupElement(0, kBout);
            }
            evalAllDPFET(party, outputs.data(), key);

            std::vector<uint64_t> expected(entries, 0);
            expected[point] = payload_value;
            log.check_vector("DPF-ET suffix " + std::to_string(suffix_bits) +
                                 " point " + std::to_string(point),
                             outputs.data(), expected, kBout);

            std::vector<GroupElement> unified_outputs(entries);
            for (int i = 0; i < entries; i++) {
                unified_outputs[i] = GroupElement(0, kBout);
            }
            evalAllDPF(party, unified_outputs.data(), key);
            log.check_vector("DPF unified evalAll suffix " +
                                 std::to_string(suffix_bits) + " point " +
                                 std::to_string(point),
                             unified_outputs.data(), expected, kBout);

            GroupElement single_hit = evalDPFET(party, point, key);
            log.check_scalar("DPF-ET single hit suffix " +
                                 std::to_string(suffix_bits) + " point " +
                                 std::to_string(point),
                             single_hit, payload_value);
            const uint64_t miss_point = (point + 1) % entries;
            GroupElement single_miss = evalDPFET(party, miss_point, key);
            log.check_scalar("DPF-ET single miss suffix " +
                                 std::to_string(suffix_bits) + " point " +
                                 std::to_string(point),
                             single_miss, 0);
            freeDPFETKeyPack(key);
        }
    }

    std::vector<u8> point_bits = split_bit_share(9, kBin, 5);
    DPFETKeyPack from_bits_key = dfss::keyGenET(
        party, kBin, kBout, 2, point_bits.data(),
        split_share(payload_value, kBout, 157));
    std::vector<GroupElement> from_bits_outputs(entries);
    dfss::evalAllET(party, from_bits_outputs.data(), from_bits_key);
    std::vector<uint64_t> from_bits_expected(entries, 0);
    from_bits_expected[9] = payload_value;
    log.check_vector("fss/dpf ET from bits", from_bits_outputs.data(),
                     from_bits_expected, kBout);
    GroupElement from_bits_single = dfss::evalET(party, 9, from_bits_key);
    log.check_scalar("fss/dpf ET from bits single", from_bits_single,
                     payload_value);
    freeDPFETKeyPack(from_bits_key);

    DPFKeyPack wrapper_default_et = dfss::wrapper::keyGenDPF(
        party, split_share(11, kBin, 25),
        split_share(payload_value, kBout, 159), true);
    GroupElement wrapper_default_hit = dfss::wrapper::evalDPF(
        party, split_share(11, kBin, 27), wrapper_default_et);
    GroupElement wrapper_default_miss = dfss::wrapper::evalDPF(
        party, split_share(12, kBin, 27), wrapper_default_et);
    log.check_scalar("fss/wrapper ET default hit", wrapper_default_hit,
                     payload_value);
    log.check_scalar("fss/wrapper ET default miss", wrapper_default_miss, 0);
    freeDPFKeyPack(wrapper_default_et);

    DPFKeyPack wrapper_suffix_et = dfss::wrapper::keyGenDPF(
        party, split_share(13, kBin, 31),
        split_share(payload_value, kBout, 163), 2);
    GroupElement wrapper_suffix_hit = dfss::wrapper::evalDPF(
        party, split_share(13, kBin, 33), wrapper_suffix_et);
    log.check_scalar("fss/wrapper ET suffix hit", wrapper_suffix_hit,
                     payload_value);
    freeDPFKeyPack(wrapper_suffix_et);

    constexpr int default_bin = 5;
    constexpr int default_entries = 1 << default_bin;
    constexpr uint64_t default_point = 17;
    DPFETKeyPack default_key = keyGenDPFET(
        party, default_bin, kBout,
        split_share(default_point, default_bin, default_point + 7),
        split_share(payload_value, kBout, 173));
    std::vector<GroupElement> default_outputs(default_entries);
    for (int i = 0; i < default_entries; i++) {
        default_outputs[i] = GroupElement(0, kBout);
    }
    evalAllDPFET(party, default_outputs.data(), default_key);
    std::vector<uint64_t> default_expected(default_entries, 0);
    default_expected[default_point] = payload_value;
    log.check_vector("DPF-ET default suffix " +
                         std::to_string(default_key.suffixBits),
                     default_outputs.data(), default_expected, kBout);
    GroupElement default_single =
        evalDPFET(party, default_point, default_key);
    log.check_scalar("DPF-ET default suffix single", default_single,
                     payload_value);
    freeDPFETKeyPack(default_key);

    constexpr int large_bin = 9;
    constexpr int large_suffix_bits = 7;
    constexpr int large_entries = 1 << large_bin;
    constexpr uint64_t large_point = 257;
    DPFETKeyPack large_key = keyGenDPFET(
        party, large_bin, kBout, large_suffix_bits,
        split_share(large_point, large_bin, large_point + 31),
        split_share(payload_value, kBout, 191));
    std::vector<GroupElement> large_outputs(large_entries);
    for (int i = 0; i < large_entries; i++) {
        large_outputs[i] = GroupElement(0, kBout);
    }
    evalAllDPFET(party, large_outputs.data(), large_key);
    std::vector<uint64_t> large_expected(large_entries, 0);
    large_expected[large_point] = payload_value;
    log.check_vector("DPF-ET larger suffix " +
                         std::to_string(large_suffix_bits),
                     large_outputs.data(), large_expected, kBout);
    GroupElement large_single = evalDPFET(party, large_point, large_key);
    log.check_scalar("DPF-ET larger suffix single", large_single,
                     payload_value);
    freeDPFETKeyPack(large_key);
}
