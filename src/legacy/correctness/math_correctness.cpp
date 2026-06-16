#include "legacy_correctness_common.h"

// Math and case-study correctness cases built on the public API layer.

#include <cmath>
#include <string>

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
            GroupElement expected =
                cleartext_sin(sine_input, trig_scale, using_lut);
            log.check_scalar("sine " + std::string(using_lut ? "LUT" : "approx") +
                                 " input " + std::to_string(sine_input.value),
                             output, expected.value);
            GroupElement math_expected(
                std::sin(kPi * sine_input.value /
                         double(uint64_t(1) << trig_scale)),
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
            GroupElement expected =
                cleartext_cosine(cosine_input, trig_scale, using_lut);
            log.check_scalar("cosine " +
                                 std::string(using_lut ? "LUT" : "approx") +
                                 " input " + std::to_string(cosine_input.value),
                             output, expected.value);
            GroupElement math_expected(
                std::cos(kPi * cosine_input.value /
                         double(uint64_t(1) << trig_scale)),
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
                party, trig_bits, trig_bits, trig_scale, using_lut,
                approx_segments, approx_degree);
            GroupElement output = tangent(
                party,
                split_share(tangent_input.value, trig_bits,
                            tangent_input.value + 75),
                key);
            GroupElement expected =
                cleartext_tangent(tangent_input, trig_scale, using_lut);
            log.check_scalar("tangent " +
                                 std::string(using_lut ? "LUT" : "approx") +
                                 " input " + std::to_string(tangent_input.value),
                             output, expected.value);
            GroupElement math_expected(
                std::tan(kPi * tangent_input.value /
                         double(uint64_t(1) << trig_scale)),
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

namespace {

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

}  // namespace

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
         GroupElement(1, trig_bits), GroupElement(3, trig_bits),
         "near-upper-domain"},
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
            log.check_scalar("proximity " +
                                 std::string(using_lut ? "LUT" : "approx") +
                                 " " + test.name,
                             output, expected.value);
        }
    }
}
