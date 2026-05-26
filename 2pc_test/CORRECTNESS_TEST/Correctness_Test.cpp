#include "2pc_api.h"
#include "2pc_dcf.h"
#include "2pc_idpf.h"
#include "2pc_cleartext.h"
#include "2pc_math.h"
#include "ArgMapping.h"
#include "api.h"
#include "comms.h"

#include <cmath>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

using namespace sci;

int party_instance = 0;
int party = 0;
int32_t bitlength = 32;
int num_threads = 1;
int port = 32000;
std::string address = "127.0.0.1";
int num_argmax = 1000;
uint8_t choice_bit = 0;
bool verbose = false;
int length = 1;
Peer* client = nullptr;
Peer* server = nullptr;
Dealer* dealer = nullptr;
Peer* peer = nullptr;

namespace {

constexpr int kBin = 4;
constexpr int kBout = 8;
constexpr double kPi = 3.141592653589793238462643383279502884;

uint64_t reduce_to_bits(uint64_t value, int bitsize) {
    if (bitsize == 64) {
        return value;
    }
    return value & ((uint64_t(1) << bitsize) - 1);
}

GroupElement public_share(uint64_t value, int bitsize) {
    return GroupElement(value * static_cast<uint64_t>(party - SERVER), bitsize);
}

GroupElement split_share(uint64_t value, int bitsize, uint64_t server_share) {
    if (party == SERVER) {
        return GroupElement(server_share, bitsize);
    }
    return GroupElement(value - server_share, bitsize);
}

void free_dpf_key(DPFKeyPack& key) {
    freeDPFKeyPack(key);
}

class ResultLog {
public:
    void check_scalar(const std::string& name, GroupElement actual, uint64_t expected) {
        reconstruct(&actual);
        const bool ok = actual.value == expected;
        print(name, ok, actual.value, expected);
        failures_ += ok ? 0 : 1;
    }

    void check_vector(const std::string& name, GroupElement* actual,
                      const std::vector<uint64_t>& expected, int bitsize) {
        reconstruct(static_cast<int32_t>(expected.size()), actual, bitsize);
        bool ok = true;
        for (size_t i = 0; i < expected.size(); ++i) {
            ok = ok && actual[i].value == expected[i];
        }
        if (party == SERVER) {
            std::cout << (ok ? "[PASS] " : "[FAIL] ") << name << " actual=[";
            for (size_t i = 0; i < expected.size(); ++i) {
                std::cout << actual[i].value << (i + 1 == expected.size() ? "" : ", ");
            }
            std::cout << "] expected=[";
            for (size_t i = 0; i < expected.size(); ++i) {
                std::cout << expected[i] << (i + 1 == expected.size() ? "" : ", ");
            }
            std::cout << "]\n";
        }
        failures_ += ok ? 0 : 1;
    }

    void check_bit(const std::string& name, u8 actual, u8 expected) {
        reconstruct(&actual);
        const bool ok = actual == expected;
        print(name, ok, actual, expected);
        failures_ += ok ? 0 : 1;
    }

    void check_public_scalar_near(const std::string& name, uint64_t actual,
                                  uint64_t expected, int bitsize,
                                  uint64_t tolerance) {
        const uint64_t modulus = uint64_t(1) << bitsize;
        uint64_t delta = (actual + modulus - expected) % modulus;
        if (delta >= (uint64_t(1) << (bitsize - 1))) {
            delta = modulus - delta;
        }
        const bool ok = delta <= tolerance;
        if (party == SERVER) {
            std::cout << (ok ? "[PASS] " : "[FAIL] ") << name
                      << " actual=" << actual << " expected=" << expected
                      << " tolerance=" << tolerance << '\n';
        }
        failures_ += ok ? 0 : 1;
    }

    int failures() const {
        return failures_;
    }

private:
    void print(const std::string& name, bool ok, uint64_t actual, uint64_t expected) const {
        if (party == SERVER) {
            std::cout << (ok ? "[PASS] " : "[FAIL] ") << name
                      << " actual=" << actual << " expected=" << expected << '\n';
        }
    }

    int failures_ = 0;
};

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

void check_constrained_comparison(ResultLog& log) {
    struct AdjacentCountCase {
        uint64_t server;
        uint64_t client;
        u8 expected;
    };
    const AdjacentCountCase cases[] = {
        {0, 1, 1}, {1, 0, 0},
        {1, 2, 1}, {2, 1, 0},
        {2, 3, 1}, {3, 2, 0},
        {3, 4, 1}, {4, 3, 0},
    };

    for (const auto& test : cases) {
        const uint64_t local_value = party == SERVER ? test.server : test.client;
        const u8 high_bit = (local_value >> 1) & 1;
        const u8 low_bit = local_value & 1;
        const u8 output = cmp_2bit_opt(party, high_bit, low_bit, peer);
        log.check_bit("constrained comparison " + std::to_string(test.server) +
                          " < " + std::to_string(test.client),
                      output, test.expected);
    }
}

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

    evalNewDCF(party, outputs.data(), queries.data(), keys.data(), entries, bitsize);
    log.check_vector("DCF " + std::to_string(bitsize) + "-bit full domain threshold " +
                         std::to_string(threshold),
                     outputs.data(), expected, kBout);
    freeNewDCFKeyPack(key);
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

void check_comparison(ResultLog& log) {
    GroupElement payload = public_share(11, kBout);
    ComparisonKeyPack below_key = comparison_offline(
        party, kBin, kBout, split_share(6, kBin, 11), &payload, true);
    GroupElement below(0, kBout);
    comparison(party, &below, split_share(4, kBin, 9), below_key);
    log.check_scalar("comparison x < threshold", below, 11);
    freeComparisonKeyPack(below_key);

    ComparisonKeyPack above_key = comparison_offline(
        party, kBin, kBout, split_share(6, kBin, 11), &payload, true);
    GroupElement above(0, kBout);
    comparison(party, &above, split_share(9, kBin, 14), above_key);
    log.check_scalar("comparison x >= threshold", above, 0);
    freeComparisonKeyPack(above_key);

    ComparisonKeyPack full_domain_key = comparison_offline(
        party, kBin, kBout, public_share(15, kBin), &payload, true);
    GroupElement full_domain_output[1 << kBin];
    std::vector<uint64_t> expected_full_domain(1 << kBin, 11);
    expected_full_domain.back() = 0;
    for (int i = 0; i < (1 << kBin); i++){
        full_domain_output[i] = GroupElement(0, kBout);
        comparison(party, &full_domain_output[i],
                   split_share(i, kBin, 3 * i + 5),
                   full_domain_key);
    }
    log.check_vector("comparison full domain threshold 15", full_domain_output,
                     expected_full_domain, kBout);
    freeComparisonKeyPack(full_domain_key);

    ComparisonKeyPack zero_threshold_key = comparison_offline(
        party, kBin, kBout, public_share(0, kBin), &payload, true);
    GroupElement zero_threshold_output[1 << kBin];
    std::vector<uint64_t> expected_zero_threshold(1 << kBin, 0);
    for (int i = 0; i < (1 << kBin); i++){
        zero_threshold_output[i] = GroupElement(0, kBout);
        comparison(party, &zero_threshold_output[i],
                   split_share(i, kBin, 5 * i + 1),
                   zero_threshold_key);
    }
    log.check_vector("comparison full domain threshold 0", zero_threshold_output,
                     expected_zero_threshold, kBout);
    freeComparisonKeyPack(zero_threshold_key);

    GroupElement split_threshold(party == SERVER ? 5 : 1, kBin);
    GroupElement secret_payload(party == SERVER ? 7 : 4, kBout);
    ComparisonKeyPack secret_payload_key = comparison_offline(
        party, kBin, kBout, split_threshold, &secret_payload, false);
    GroupElement secret_payload_output(0, kBout);
    comparison(party, &secret_payload_output, split_share(4, kBin, 9),
               secret_payload_key);
    log.check_scalar("comparison split threshold secret payload",
                     secret_payload_output, 11);
    freeComparisonKeyPack(secret_payload_key);

    GroupElement wide_payload = public_share(5, kBout);
    ComparisonKeyPack wide_below_key = comparison_offline(
        party, 7, kBout, public_share(48, 7), &wide_payload, true);
    GroupElement wide_below(0, kBout);
    comparison(party, &wide_below, split_share(16, 7, 91), wide_below_key);
    log.check_scalar("comparison 7-bit 16 < 48", wide_below, 5);
    freeComparisonKeyPack(wide_below_key);

    ComparisonKeyPack wide_above_key = comparison_offline(
        party, 7, kBout, public_share(48, 7), &wide_payload, true);
    GroupElement wide_above(0, kBout);
    comparison(party, &wide_above, split_share(56, 7, 91), wide_above_key);
    log.check_scalar("comparison 7-bit 56 >= 48", wide_above, 0);
    freeComparisonKeyPack(wide_above_key);
}

void check_modular(ResultLog& log) {
    constexpr uint64_t modulus = 8;
    for (uint64_t input : {uint64_t(0), uint64_t(7), uint64_t(8),
                           uint64_t(15)}) {
        ModularKeyPack key =
            modular_offline(party, GroupElement(modulus, kBin), kBout);
        GroupElement output =
            modular(party, split_share(input, kBin, input + 6), modulus, key);
        log.check_scalar("power-of-two modular reduction " +
                             std::to_string(input) + " mod " +
                             std::to_string(modulus),
                         output, input % modulus);
    }
}

void check_truncate_and_reduce(ResultLog& log) {
    constexpr int input_bits = 5;
    constexpr int truncated_bits = 2;
    for (uint64_t input : {uint64_t(0), uint64_t(1), uint64_t(13),
                           uint64_t((1 << input_bits) - 1)}) {
        TRKeyPack key = truncate_and_reduce_offline(party, input_bits, truncated_bits);
        GroupElement output = truncate_and_reduce(
            party, split_share(input, input_bits, input + 19), truncated_bits,
            key);
        log.check_scalar("truncate and reduce " + std::to_string(input),
                         output, input >> truncated_bits);
    }

    TRKeyPack top_bit_key = truncate_and_reduce_offline(party, kBin, kBin - 1);
    GroupElement top_bit = truncate_and_reduce(
        party, split_share(12, kBin, 7), kBin - 1, top_bit_key);
    log.check_scalar("truncate and reduce top bit", top_bit, 1);

    TRKeyPack carry_key = truncate_and_reduce_offline(party, input_bits, truncated_bits);
    GroupElement carry_input(party == SERVER ? 3 : 6, input_bits);
    GroupElement carry_output = truncate_and_reduce(
        party, carry_input, truncated_bits, carry_key);
    log.check_scalar("truncate and reduce low-share carry", carry_output, 2);
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
        ContainmentKeyPack key = containment_offline_public(party, kBout, knots, 3);
        GroupElement output[] = {
            GroupElement(0, kBout),
            GroupElement(0, kBout),
            GroupElement(0, kBout),
            GroupElement(0, kBout),
        };
        containment(party, split_share(test.input, kBin, test.input + 7),
                    output, 3, key);
        log.check_vector("containment interval vector " + std::to_string(test.input),
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
        ContainmentKeyPack key = containment_offline_public(party, kBout, trig_knots, 3);
        GroupElement output[] = {
            GroupElement(0, kBout),
            GroupElement(0, kBout),
            GroupElement(0, kBout),
            GroupElement(0, kBout),
        };
        containment(party, split_share(test.input, 7, test.input + 65),
                    output, 3, key);
        log.check_vector("containment 7-bit trig interval " +
                             std::to_string(test.input),
                         output, test.expected, kBout);
    }
}

void check_digdec(ResultLog& log) {
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
        DigDecKeyPack key = digdec_offline(party, kBin, digit_bits);
        GroupElement output[] = {
            GroupElement(0, digit_bits),
            GroupElement(0, digit_bits),
        };
        digdec(party, split_share(test.input, kBin, test.input + 11), output,
               digit_bits, key);
        log.check_vector("digit decomposition low to high " +
                             std::to_string(test.input),
                         output, test.expected, digit_bits);
    }
}

void check_public_lut(ResultLog& log) {
    constexpr int entries = 1 << kBin;
    GroupElement table[entries];
    GroupElement shifted[entries];
    for (int i = 0; i < entries; ++i) {
        table[i] = GroupElement(3 * i + 1, kBout);
        shifted[i] = GroupElement(0, kBout);
    }

    for (uint64_t input : {uint64_t(0), uint64_t(3), uint64_t(entries - 1)}) {
        DPFKeyPack key = pub_lut_offline(party, kBin, kBout);
        GroupElement output = pub_lut(party, split_share(input, kBin, input + 9), table,
                                      shifted, entries, kBout, key);
        log.check_scalar("public LUT lookup " + std::to_string(input), output,
                         3 * input + 1);
    }
}

void check_private_lut(ResultLog& log) {
    constexpr int entries = 1 << kBin;
    GroupElement table[entries];
    for (int i = 0; i < entries; ++i) {
        table[i] = split_share(2 * i + 5, kBout, 37 + i);
    }

    for (uint64_t input : {uint64_t(0), uint64_t(7), uint64_t(entries - 1)}) {
        PrivateLutKey key = pri_lut_offline(party, kBin, kBout, table);
        GroupElement output = pri_lut(party, split_share(input, kBin, input + 13),
                                      key);
        log.check_scalar("private LUT lookup " + std::to_string(input), output,
                         2 * input + 5);
        freePrivateLutKey(key);
    }

    GroupElement two_entry_table[] = {
        split_share(5, kBin, 12),
        split_share(9, kBin, 14),
    };
    PrivateLutKey public_index_key = pri_lut_offline(party, 1, kBin, two_entry_table);
    GroupElement public_index_output = pri_lut(party, public_share(1, 1), public_index_key);
    log.check_scalar("private LUT one-bit public index", public_index_output, 9);
    freePrivateLutKey(public_index_key);

    PrivateLutKey split_index_key = pri_lut_offline(party, 1, kBin, two_entry_table);
    GroupElement split_index(party == SERVER ? 1 : 0, 1);
    GroupElement split_index_output = pri_lut(party, split_index, split_index_key);
    log.check_scalar("private LUT one-bit split index", split_index_output, 9);
    freePrivateLutKey(split_index_key);

    TRKeyPack truncated_index_key = truncate_and_reduce_offline(party, kBin, kBin - 1);
    GroupElement truncated_index = truncate_and_reduce(
        party, split_share(12, kBin, 7), kBin - 1, truncated_index_key);
    PrivateLutKey truncated_lut_key = pri_lut_offline(party, 1, kBin, two_entry_table);
    GroupElement truncated_index_output = pri_lut(party, truncated_index, truncated_lut_key);
    log.check_scalar("private LUT truncated one-bit index", truncated_index_output, 9);
    freePrivateLutKey(truncated_lut_key);
}

void check_spline_poly_approx_case(ResultLog& log, const std::string& name,
                                   GroupElement* coefficients, uint64_t input,
                                   uint64_t expected, int output_bits) {
    constexpr int seg_num = 2;
    constexpr int degree = 2;
    SplinePolyApproxKeyPack key = spline_poly_approx_offline(
        party, kBin, output_bits, coefficients, degree, seg_num);
    GroupElement output =
        spline_poly_approx(party, split_share(input, kBin, input + 5), key);
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

void check_trigonometric(ResultLog& log) {
    constexpr int trig_bits = 8;
    constexpr int trig_scale = 5;
    constexpr int lut_digit_bits = 2;
    constexpr int approx_segments = 16;
    constexpr int approx_degree = 2;
    const uint64_t approx_tolerance = 8;

    const GroupElement sine_inputs[] = {
        GroupElement(0, trig_bits),
        GroupElement(4, trig_bits),
        GroupElement(1.75f, trig_bits, trig_scale),
        GroupElement(-0.25f, trig_bits, trig_scale),
        GroupElement(2.25f, trig_bits, trig_scale),
    };
    for (const auto& sine_input : sine_inputs) {
        for (bool using_lut : {true, false}) {
            SineKeyPack key = sine_offline(
                party, trig_bits, trig_bits, trig_scale, using_lut, lut_digit_bits,
                approx_segments, approx_degree);
            GroupElement output = sine(
                party,
                split_share(sine_input.value, trig_bits, sine_input.value + 71),
                key);
            GroupElement expected = cleartext_sin(sine_input, trig_scale, using_lut);
            log.check_scalar("sine " + std::string(using_lut ? "LUT" : "approx") +
                                 " input " + std::to_string(sine_input.value),
                             output, expected.value);
            GroupElement math_expected(
                std::sin(kPi * sine_input.value / double(uint64_t(1) << trig_scale)),
                trig_bits, trig_scale);
            log.check_public_scalar_near(
                "sine cleartext math sanity " +
                    std::string(using_lut ? "LUT" : "approx") +
                    " input " + std::to_string(sine_input.value),
                expected.value, math_expected.value, trig_bits,
                using_lut ? 0 : approx_tolerance);
        }
    }

    const GroupElement cosine_inputs[] = {
        GroupElement(0, trig_bits),
        GroupElement(12, trig_bits),
        GroupElement(1.75f, trig_bits, trig_scale),
        GroupElement(-0.25f, trig_bits, trig_scale),
        GroupElement(2.25f, trig_bits, trig_scale),
    };
    for (const auto& cosine_input : cosine_inputs) {
        for (bool using_lut : {true, false}) {
            CosineKeyPack key = cosine_offline(
                party, trig_bits, trig_bits, trig_scale, using_lut, lut_digit_bits,
                approx_segments, approx_degree);
            GroupElement output = cosine(
                party,
                split_share(cosine_input.value, trig_bits,
                            cosine_input.value + 73),
                key);
            GroupElement expected = cleartext_cosine(cosine_input, trig_scale, using_lut);
            log.check_scalar("cosine " + std::string(using_lut ? "LUT" : "approx") +
                                 " input " + std::to_string(cosine_input.value),
                             output, expected.value);
            GroupElement math_expected(
                std::cos(kPi * cosine_input.value / double(uint64_t(1) << trig_scale)),
                trig_bits, trig_scale);
            log.check_public_scalar_near(
                "cosine cleartext math sanity " +
                    std::string(using_lut ? "LUT" : "approx") +
                    " input " + std::to_string(cosine_input.value),
                expected.value, math_expected.value, trig_bits,
                using_lut ? 0 : approx_tolerance);
        }
    }

    const GroupElement tangent_inputs[] = {
        GroupElement(0, trig_bits),
        GroupElement(4, trig_bits),
        GroupElement(-0.25f, trig_bits, trig_scale),
        GroupElement(1.25f, trig_bits, trig_scale),
    };
    for (const auto& tangent_input : tangent_inputs) {
        for (bool using_lut : {true, false}) {
            TangentKeyPack key = tangent_offline(
                party, trig_bits, trig_bits, trig_scale, using_lut, approx_segments,
                approx_degree);
            GroupElement output = tangent(
                party,
                split_share(tangent_input.value, trig_bits,
                            tangent_input.value + 75),
                key);
            GroupElement expected = cleartext_tangent(tangent_input, trig_scale, using_lut);
            log.check_scalar("tangent " + std::string(using_lut ? "LUT" : "approx") +
                                 " input " + std::to_string(tangent_input.value),
                             output, expected.value);
            GroupElement math_expected(
                std::tan(kPi * tangent_input.value / double(uint64_t(1) << trig_scale)),
                trig_bits, trig_scale);
            log.check_public_scalar_near(
                "tangent cleartext math sanity " +
                    std::string(using_lut ? "LUT" : "approx") +
                    " input " + std::to_string(tangent_input.value),
                expected.value, math_expected.value, trig_bits,
                using_lut ? 0 : approx_tolerance);
        }
    }
}

GroupElement expected_proximity(GroupElement xA, GroupElement yA,
                                GroupElement xB, GroupElement yB,
                                int scale, bool using_lut) {
    GroupElement front_input = scale_mult(
        xA - xB, GroupElement(0.5f, xA.bitsize, scale), scale);
    GroupElement back_input = scale_mult(
        yA - yB, GroupElement(0.5f, xA.bitsize, scale), scale);

    GroupElement front_sin = cleartext_sin(front_input, scale, using_lut);
    GroupElement front_output = scale_mult(front_sin, front_sin, scale);

    GroupElement back_cos_0 = cleartext_cosine(xA, scale, using_lut);
    GroupElement back_cos_1 = cleartext_cosine(xB, scale, using_lut);
    GroupElement back_sin = cleartext_sin(back_input, scale, using_lut);
    GroupElement back_output_0 = scale_mult(back_cos_0, back_cos_1, scale);
    GroupElement back_output_1 = scale_mult(back_sin, back_sin, scale);
    GroupElement back_output = scale_mult(back_output_0, back_output_1, scale);

    return front_output + back_output;
}

void check_case_studies(ResultLog& log) {
    constexpr int trig_bits = 8;
    constexpr int trig_scale = 5;
    constexpr int lut_digit_bits = 2;
    constexpr int approx_segments = 16;
    constexpr int approx_degree = 2;

    struct ProximityCase {
        GroupElement xA;
        GroupElement yA;
        GroupElement xB;
        GroupElement yB;
        std::string name;
    };
    const ProximityCase cases[] = {
        {GroupElement(12, trig_bits), GroupElement(10, trig_bits),
         GroupElement(4, trig_bits), GroupElement(2, trig_bits), "interior"},
        {GroupElement(7, trig_bits), GroupElement(7, trig_bits),
         GroupElement(7, trig_bits), GroupElement(7, trig_bits), "zero-distance"},
        {GroupElement(15, trig_bits), GroupElement(14, trig_bits),
         GroupElement(1, trig_bits), GroupElement(3, trig_bits), "near-upper-domain"},
    };

    for (const auto& test : cases) {
        for (bool using_lut : {true, false}) {
            ProximityKeyPack key = proximity_offline(
                party, trig_bits, trig_scale, using_lut, lut_digit_bits,
                approx_segments, approx_degree);
            GroupElement output = proximity(
                party, split_share(test.xA.value, trig_bits, test.xA.value + 11),
                split_share(test.yA.value, trig_bits, test.yA.value + 13),
                split_share(test.xB.value, trig_bits, test.xB.value + 17),
                split_share(test.yB.value, trig_bits, test.yB.value + 19),
                key);
            GroupElement expected = expected_proximity(
                test.xA, test.yA, test.xB, test.yB, trig_scale, using_lut);
            log.check_scalar("proximity " + std::string(using_lut ? "LUT" : "approx") +
                                 " " + test.name,
                             output, expected.value);
        }
    }
}

}  // namespace

int main(int argc, char** argv) {
    int test_case = 0;
    ArgMapping amap;
    amap.arg("r", party, "Role of party: SERVER = 2; CLIENT = 3");
    amap.arg("p", port, "Port Number");
    amap.arg("t", test_case, "Case: all = 0; DPF = 1; DCF = 2; comparison = 3; "
                             "power-of-two modular = 4; truncate = 5; containment = 6; "
                             "public LUT = 7; private LUT = 8; spline = 9; "
                             "digdec = 10; constrained comparison = 11; "
                             "trigonometric = 12; proximity = 13");
    amap.parse(argc, argv);

    if (party == CLIENT) {
        server = new Peer(address, port);
        peer = server;
    } else if (party == SERVER) {
        client = waitForPeer(port);
        peer = client;
    } else {
        std::cerr << "Pass r=2 for SERVER or r=3 for CLIENT.\n";
        return 2;
    }

    ResultLog log;
    if (test_case == 0 || test_case == 1) {
        check_dpf(log);
    }
    if (test_case == 0 || test_case == 2) {
        check_dcf(log);
    }
    if (test_case == 0 || test_case == 3) {
        check_comparison(log);
    }
    if (test_case == 0 || test_case == 4) {
        check_modular(log);
    }
    if (test_case == 0 || test_case == 5) {
        check_truncate_and_reduce(log);
    }
    if (test_case == 0 || test_case == 6) {
        check_containment(log);
    }
    if (test_case == 0 || test_case == 7) {
        check_public_lut(log);
    }
    if (test_case == 0 || test_case == 8) {
        check_private_lut(log);
    }
    if (test_case == 0 || test_case == 9) {
        check_spline_poly_approx(log);
    }
    if (test_case == 0 || test_case == 10) {
        check_digdec(log);
    }
    if (test_case == 0 || test_case == 11) {
        check_constrained_comparison(log);
    }
    if (test_case == 0 || test_case == 12) {
        check_trigonometric(log);
    }
    if (test_case == 0 || test_case == 13) {
        check_case_studies(log);
    }

    if (party == SERVER) {
        std::cout << "Correctness checks: " << (log.failures() == 0 ? "PASS" : "FAIL")
                  << " (" << log.failures() << " failed)\n";
    }
    return log.failures() == 0 ? 0 : 1;
}
