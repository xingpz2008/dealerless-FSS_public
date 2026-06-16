#include "legacy_correctness_common.h"

#include <string>
#include <vector>

namespace {

void check_dcf_domain(ResultLog& log, int bitsize, uint64_t threshold,
                      GroupElement threshold_share) {
    constexpr uint64_t payload = 7;
    const int entries = 1 << bitsize;
    newDCFKeyPack key = keyGenNewDCF(party, bitsize, kBout, threshold_share,
                                     split_share(payload, kBout, 91 + bitsize));
    std::vector<newDCFKeyPack> keys(entries);
    std::vector<GroupElement> queries(entries);
    std::vector<GroupElement> outputs(entries);
    std::vector<uint64_t> expected(entries);
    for (int i = 0; i < entries; ++i) {
        keys[i] = key;
        queries[i] = GroupElement(i, bitsize);
        outputs[i] = GroupElement(0, kBout);
        expected[i] = i < threshold ? payload : 0;
    }

    evalNewDCF(party, outputs.data(), queries.data(), keys.data(), entries,
               bitsize);
    log.check_vector("DCF " + std::to_string(bitsize) +
                         "-bit full domain threshold " +
                         std::to_string(threshold),
                     outputs.data(), expected, kBout);
    freeNewDCFKeyPack(key);
}

void check_spline_poly_approx_case(ResultLog& log, const std::string& name,
                                   GroupElement* coefficients, uint64_t input,
                                   uint64_t expected, int output_bits) {
    constexpr int seg_num = 2;
    constexpr int degree = 2;
    SplinePolyApproxKeyPack key = dfss::legacy::splinePolyApproxOffline(
        party, kBin, output_bits, coefficients, degree, seg_num);
    GroupElement output = dfss::legacy::splinePolyApprox(
        party, split_share(input, kBin, input + 5), key);
    log.check_scalar(name, output, expected);
}

uint64_t spline_expected(uint64_t input, uint64_t a_lower, uint64_t a_upper,
                         uint64_t b_lower, uint64_t b_upper,
                         uint64_t c_lower, uint64_t c_upper,
                         int output_bits) {
    const bool upper_segment = input >= (uint64_t(1) << (kBin - 1));
    const uint64_t a = upper_segment ? a_upper : a_lower;
    const uint64_t b = upper_segment ? b_upper : b_lower;
    const uint64_t c = upper_segment ? c_upper : c_lower;
    return reduce_to_bits(a * input * input + b * input + c, output_bits);
}

}  // namespace

void check_dpf(ResultLog& log) {
    constexpr uint64_t payload = 9;
    constexpr int entries = 1 << kBin;
    for (uint64_t point : {uint64_t(0), uint64_t(5), uint64_t(entries - 1)}) {
        DPFKeyPack key = keyGenDPF(
            party, kBin, kBout, split_share(point, kBin, point + 3),
            split_share(payload, kBout, 173 + point), false);
        std::vector<GroupElement> outputs(entries);
        std::vector<uint64_t> expected(entries);
        for (int i = 0; i < entries; ++i) {
            evalDPF(party, &outputs[i], GroupElement(i, kBin), key, false);
            expected[i] = i == static_cast<int>(point) ? payload : 0;
        }
        log.check_vector("DPF full domain point " + std::to_string(point),
                         outputs.data(), expected, kBout);

        std::vector<GroupElement> eval_all_outputs(entries);
        for (int i = 0; i < entries; ++i) {
            eval_all_outputs[i] = GroupElement(0, kBout);
        }
        evalAll(party, eval_all_outputs.data(), key, kBin);
        log.check_vector("DPF evalAll point " + std::to_string(point),
                         eval_all_outputs.data(), expected, kBout);
        free_dpf_key(key);
    }
}

void check_dcf(ResultLog& log) {
    check_dcf_domain(log, kBin, 0, split_share(0, kBin, 5));
    check_dcf_domain(log, 1, 1, split_share(1, 1, 1));
    check_dcf_domain(log, 2, 2, split_share(2, 2, 3));
    check_dcf_domain(log, 3, 3, split_share(3, 3, 6));
    check_dcf_domain(log, kBin, 6, split_share(6, kBin, 11));
    check_dcf_domain(log, kBin, 6, GroupElement(party == SERVER ? 2 : 4, kBin));
    check_dcf_domain(log, kBin, (1 << kBin) - 1,
                     split_share((1 << kBin) - 1, kBin, 10));
}

void check_legacy_comparison(ResultLog& log) {
    GroupElement payload = public_share(11, kBout);
    LegacyComparisonKeyPack below_key = dfss::legacy::legacyComparisonOffline(
        party, kBin, kBout, split_share(6, kBin, 11), &payload, true);
    GroupElement below(0, kBout);
    dfss::legacy::legacyComparison(
        party, &below, split_share(4, kBin, 9), below_key);
    log.check_scalar("legacy comparison x < threshold", below, 11);
    freeLegacyComparisonKeyPack(below_key);

    LegacyComparisonKeyPack above_key = dfss::legacy::legacyComparisonOffline(
        party, kBin, kBout, split_share(6, kBin, 11), &payload, true);
    GroupElement above(0, kBout);
    dfss::legacy::legacyComparison(
        party, &above, split_share(9, kBin, 14), above_key);
    log.check_scalar("legacy comparison x >= threshold", above, 0);
    freeLegacyComparisonKeyPack(above_key);

    LegacyComparisonKeyPack full_domain_key =
        dfss::legacy::legacyComparisonOffline(
            party, kBin, kBout, public_share(15, kBin), &payload, true);
    GroupElement full_domain_output[1 << kBin];
    std::vector<uint64_t> expected_full_domain(1 << kBin, 11);
    expected_full_domain.back() = 0;
    for (int i = 0; i < (1 << kBin); i++) {
        full_domain_output[i] = GroupElement(0, kBout);
        dfss::legacy::legacyComparison(
            party, &full_domain_output[i],
            split_share(i, kBin, 3 * i + 5), full_domain_key);
    }
    log.check_vector("legacy comparison full domain threshold 15",
                     full_domain_output, expected_full_domain, kBout);
    freeLegacyComparisonKeyPack(full_domain_key);

    LegacyComparisonKeyPack zero_threshold_key =
        dfss::legacy::legacyComparisonOffline(
            party, kBin, kBout, public_share(0, kBin), &payload, true);
    GroupElement zero_threshold_output[1 << kBin];
    std::vector<uint64_t> expected_zero_threshold(1 << kBin, 0);
    for (int i = 0; i < (1 << kBin); i++) {
        zero_threshold_output[i] = GroupElement(0, kBout);
        dfss::legacy::legacyComparison(
            party, &zero_threshold_output[i],
            split_share(i, kBin, 5 * i + 1), zero_threshold_key);
    }
    log.check_vector("legacy comparison full domain threshold 0",
                     zero_threshold_output, expected_zero_threshold, kBout);
    freeLegacyComparisonKeyPack(zero_threshold_key);

    GroupElement split_threshold(party == SERVER ? 5 : 1, kBin);
    GroupElement secret_payload(party == SERVER ? 7 : 4, kBout);
    LegacyComparisonKeyPack secret_payload_key =
        dfss::legacy::legacyComparisonOffline(
            party, kBin, kBout, split_threshold, &secret_payload, false);
    GroupElement secret_payload_output(0, kBout);
    dfss::legacy::legacyComparison(
        party, &secret_payload_output, split_share(4, kBin, 9),
        secret_payload_key);
    log.check_scalar("legacy comparison split threshold secret payload",
                     secret_payload_output, 11);
    freeLegacyComparisonKeyPack(secret_payload_key);

    GroupElement wide_payload = public_share(5, kBout);
    LegacyComparisonKeyPack wide_below_key =
        dfss::legacy::legacyComparisonOffline(
            party, 7, kBout, public_share(48, 7), &wide_payload, true);
    GroupElement wide_below(0, kBout);
    dfss::legacy::legacyComparison(
        party, &wide_below, split_share(16, 7, 91), wide_below_key);
    log.check_scalar("legacy comparison 7-bit 16 < 48", wide_below, 5);
    freeLegacyComparisonKeyPack(wide_below_key);

    LegacyComparisonKeyPack wide_above_key =
        dfss::legacy::legacyComparisonOffline(
            party, 7, kBout, public_share(48, 7), &wide_payload, true);
    GroupElement wide_above(0, kBout);
    dfss::legacy::legacyComparison(
        party, &wide_above, split_share(56, 7, 91), wide_above_key);
    log.check_scalar("legacy comparison 7-bit 56 >= 48", wide_above, 0);
    freeLegacyComparisonKeyPack(wide_above_key);

    GroupElement small_payload = public_share(1, 3);
    LegacyComparisonKeyPack threshold_three_key =
        dfss::legacy::legacyComparisonOffline(
            party, 3, 3, public_share(3, 3), &small_payload, true);
    for (uint64_t input : {uint64_t(1), uint64_t(3), uint64_t(4)}) {
        GroupElement out(0, 3);
        dfss::legacy::legacyComparison(
            party, &out, split_share(input, 3, input + 5),
            threshold_three_key);
        log.check_scalar("legacy comparison 3-bit threshold 3 input " +
                             std::to_string(input),
                         out, input < 3 ? 1 : 0);
    }
    freeLegacyComparisonKeyPack(threshold_three_key);

    LegacyComparisonKeyPack threshold_four_key =
        dfss::legacy::legacyComparisonOffline(
            party, 3, 3, public_share(4, 3), &small_payload, true);
    for (uint64_t input : {uint64_t(1), uint64_t(3), uint64_t(4)}) {
        GroupElement out(0, 3);
        dfss::legacy::legacyComparison(
            party, &out, split_share(input, 3, input + 7),
            threshold_four_key);
        log.check_scalar("legacy comparison 3-bit threshold 4 input " +
                             std::to_string(input),
                         out, input < 4 ? 1 : 0);
    }
    freeLegacyComparisonKeyPack(threshold_four_key);
}

void check_legacy_modular(ResultLog& log) {
    constexpr uint64_t modulus = 8;
    for (uint64_t input : {uint64_t(0), uint64_t(7), uint64_t(8),
                           uint64_t(15)}) {
        LegacyModularKeyPack key = dfss::legacy::modularOffline(
            party, GroupElement(modulus, kBin), kBout);
        GroupElement output = dfss::legacy::modular(
            party, split_share(input, kBin, input + 6), modulus, key);
        log.check_scalar("legacy modular reduction " +
                             std::to_string(input) + " mod " +
                             std::to_string(modulus),
                         output, input % modulus);
        freeLegacyModularKeyPack(key);
    }
}

void check_legacy_truncate_and_reduce(ResultLog& log) {
    constexpr int input_bits = 5;
    constexpr int truncated_bits = 2;
    for (uint64_t input : {uint64_t(0), uint64_t(1), uint64_t(13),
                           uint64_t((1 << input_bits) - 1)}) {
        LegacyTRKeyPack key =
            dfss::legacy::truncateOffline(party, input_bits, truncated_bits);
        GroupElement output = dfss::legacy::truncate(
            party, split_share(input, input_bits, input + 19),
            truncated_bits, key);
        log.check_scalar("legacy truncate and reduce " +
                             std::to_string(input),
                         output, input >> truncated_bits);
        freeLegacyTRKeyPack(key);
    }
}

void check_containment(ResultLog& log) {
    GroupElement knots[] = {
        GroupElement(4, kBin),
        GroupElement(8, kBin),
        GroupElement(12, kBin),
    };
    struct ContainmentCase {
        uint64_t input;
        std::vector<uint64_t> expected;
    };
    const ContainmentCase cases[] = {
        {0, {1, 0, 0, 0}},
        {3, {1, 0, 0, 0}},
        {4, {0, 1, 0, 0}},
        {7, {0, 1, 0, 0}},
        {8, {0, 0, 1, 0}},
        {9, {0, 0, 1, 0}},
        {12, {0, 0, 0, 1}},
        {15, {0, 0, 0, 1}},
    };
    for (const auto& test : cases) {
        ContainmentKeyPack key =
            dfss::legacy::containmentOfflinePublic(party, kBout, knots, 3);
        GroupElement output[] = {
            GroupElement(0, kBout),
            GroupElement(0, kBout),
            GroupElement(0, kBout),
            GroupElement(0, kBout),
        };
        dfss::legacy::containment(
            party, split_share(test.input, kBin, test.input + 7), output, 3,
            key);
        log.check_vector("legacy containment interval vector " +
                             std::to_string(test.input),
                         output, test.expected, kBout);
    }

    GroupElement trig_knots[] = {
        GroupElement(16, 7),
        GroupElement(32, 7),
        GroupElement(48, 7),
    };
    struct TrigContainmentCase {
        uint64_t input;
        std::vector<uint64_t> expected;
    };
    const TrigContainmentCase trig_cases[] = {
        {8, {1, 0, 0, 0}},
        {24, {0, 1, 0, 0}},
        {40, {0, 0, 1, 0}},
        {56, {0, 0, 0, 1}},
    };
    for (const auto& test : trig_cases) {
        ContainmentKeyPack key =
            dfss::legacy::containmentOfflinePublic(party, kBout, trig_knots, 3);
        GroupElement output[] = {
            GroupElement(0, kBout),
            GroupElement(0, kBout),
            GroupElement(0, kBout),
            GroupElement(0, kBout),
        };
        dfss::legacy::containment(
            party, split_share(test.input, 7, test.input + 65), output, 3,
            key);
        log.check_vector("legacy containment 7-bit trig interval " +
                             std::to_string(test.input),
                         output, test.expected, kBout);
    }
}

void check_legacy_digdec(ResultLog& log) {
    constexpr int digit_bits = 2;
    struct DigDecCase {
        uint64_t input;
        std::vector<uint64_t> expected;
    };
    const DigDecCase cases[] = {
        {0, {0, 0}},
        {1, {1, 0}},
        {13, {1, 3}},
        {15, {3, 3}},
    };
    for (const auto& test : cases) {
        LegacyDigDecKeyPack key =
            dfss::legacy::digdecOffline(party, kBin, digit_bits);
        GroupElement output[] = {
            GroupElement(0, digit_bits),
            GroupElement(0, digit_bits),
        };
        dfss::legacy::digdec(
            party, split_share(test.input, kBin, test.input + 11), output,
            digit_bits, key);
        log.check_vector("legacy digit decomposition low to high " +
                             std::to_string(test.input),
                         output, test.expected, digit_bits);
        freeLegacyDigDecKeyPack(key);
    }
}

void check_legacy_public_lut(ResultLog& log) {
    constexpr int entries = 1 << kBin;
    std::vector<GroupElement> table(entries);
    std::vector<GroupElement> shifted(entries);
    for (int i = 0; i < entries; i++) {
        table[i] = GroupElement(3 * i + 1, kBout);
        shifted[i] = GroupElement(0, kBout);
    }

    for (uint64_t input : {uint64_t(0), uint64_t(3),
                           uint64_t(entries - 1)}) {
        LegacyPublicLutKeyPack key =
            dfss::legacy::publicLutOffline(party, kBin, kBout);
        GroupElement output = dfss::legacy::publicLut(
            party, split_share(input, kBin, input + 9), table.data(),
            shifted.data(), entries, kBout, key);
        log.check_scalar("legacy public LUT lookup " + std::to_string(input),
                         output, 3 * input + 1);
        freeLegacyPublicLutKeyPack(key);
    }
}

void check_legacy_private_lut(ResultLog& log) {
    constexpr int entries = 1 << kBin;
    GroupElement table[entries];
    for (int i = 0; i < entries; ++i) {
        table[i] = split_share(2 * i + 5, kBout, 37 + i);
    }

    for (uint64_t input : {uint64_t(0), uint64_t(7), uint64_t(entries - 1)}) {
        LegacyPrivateLutKey key =
            dfss::legacy::privateLutOffline(party, kBin, kBout, table);
        GroupElement output = dfss::legacy::privateLut(
            party, split_share(input, kBin, input + 13), key);
        log.check_scalar("legacy private LUT lookup " + std::to_string(input),
                         output, 2 * input + 5);
        freeLegacyPrivateLutKey(key);
    }
}

void check_spline_poly_approx(ResultLog& log) {
    GroupElement constant_coefficients[] = {
        GroupElement(0, kBin), GroupElement(0, kBin),
        GroupElement(0, kBin), GroupElement(0, kBin),
        GroupElement(5, kBin), GroupElement(9, kBin),
    };
    for (uint64_t input : {uint64_t(0), uint64_t(7), uint64_t(8), uint64_t(12),
                           uint64_t(15)}) {
        check_spline_poly_approx_case(
            log, "spline same-ring constant input " + std::to_string(input),
            constant_coefficients, input,
            spline_expected(input, 0, 0, 0, 0, 5, 9, kBin), kBin);
    }

    GroupElement linear_coefficients[] = {
        GroupElement(0, kBin), GroupElement(0, kBin),
        GroupElement(1, kBin), GroupElement(2, kBin),
        GroupElement(3, kBin), GroupElement(4, kBin),
    };
    for (uint64_t input : {uint64_t(0), uint64_t(7), uint64_t(8), uint64_t(12),
                           uint64_t(15)}) {
        check_spline_poly_approx_case(
            log, "spline same-ring linear input " + std::to_string(input),
            linear_coefficients, input,
            spline_expected(input, 0, 0, 1, 2, 3, 4, kBin), kBin);
    }

    GroupElement quadratic_coefficients[] = {
        GroupElement(0, kBin), GroupElement(1, kBin),
        GroupElement(0, kBin), GroupElement(2, kBin),
        GroupElement(5, kBin), GroupElement(1, kBin),
    };
    for (uint64_t input : {uint64_t(0), uint64_t(7), uint64_t(8), uint64_t(12),
                           uint64_t(15)}) {
        check_spline_poly_approx_case(
            log, "spline same-ring quadratic input " + std::to_string(input),
            quadratic_coefficients, input,
            spline_expected(input, 0, 1, 0, 2, 5, 1, kBin), kBin);
    }

    for (uint64_t input : {uint64_t(0), uint64_t(7), uint64_t(8), uint64_t(12),
                           uint64_t(15)}) {
        check_spline_poly_approx_case(
            log, "spline wider-ring constant input " + std::to_string(input),
            constant_coefficients, input,
            spline_expected(input, 0, 0, 0, 0, 5, 9, kBout), kBout);
        check_spline_poly_approx_case(
            log, "spline wider-ring linear input " + std::to_string(input),
            linear_coefficients, input,
            spline_expected(input, 0, 0, 1, 2, 3, 4, kBout), kBout);
        check_spline_poly_approx_case(
            log, "spline wider-ring quadratic input " + std::to_string(input),
            quadratic_coefficients, input,
            spline_expected(input, 0, 1, 0, 2, 5, 1, kBout), kBout);
    }
}
