#include "cases.h"

// dFSS extension correctness cases built on MIC, OHG, DPF-ET, and PolyEval.

#include <cerrno>
#include <cstdlib>
#include <fstream>
#include <stdexcept>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <vector>

namespace {

void ensureCorrectnessArtifactDir() {
    if (mkdir("build", 0755) != 0 && errno != EEXIST) {
        throw std::runtime_error("Failed to create build artifact directory");
    }
    if (mkdir("build/correctness-logs", 0755) != 0 && errno != EEXIST) {
        throw std::runtime_error(
            "Failed to create correctness artifact directory");
    }
}

std::string correctnessArtifactPath(const std::string& filename) {
    const char* artifact_dir = std::getenv("DFSS_CORRECTNESS_ARTIFACT_DIR");
    if (artifact_dir != nullptr && artifact_dir[0] != '\0') {
        return std::string(artifact_dir) + "/" + filename;
    }
    ensureCorrectnessArtifactDir();
    return "build/correctness-logs/" + filename;
}

}  // namespace

void check_mic(ResultLog& log) {
    constexpr uint64_t payload_value = 17;
    constexpr int interval_count = 6;
    const PublicInterval intervals[interval_count] = {
        {0, 4},
        {2, 6},
        {6, 12},
        {12, 16},
        {3, 3},
        {0, 16},
    };

    for (uint64_t input : {uint64_t(0), uint64_t(3), uint64_t(5),
                           uint64_t(11), uint64_t(12), uint64_t(15)}) {
        MICKeyPack key = dfss::micOffline(
            party, kBin, kBout, split_share(payload_value, kBout, 87));
        std::vector<GroupElement> output(interval_count);
        dfss::mic(party, split_share(input, kBin, input + 9), intervals,
            interval_count, output.data(), key);

        std::vector<uint64_t> expected(interval_count);
        for (int i = 0; i < interval_count; i++) {
            expected[i] =
                (intervals[i].left <= input && input < intervals[i].right)
                    ? payload_value
                    : 0;
        }
        log.check_vector("MIC multiple intervals input " + std::to_string(input),
                         output.data(), expected, kBout);
        freeMICKeyPack(key);
    }

    MICKeyPack wrap_key = dfss::micOffline(
        party, kBin, kBout, split_share(payload_value, kBout, 91));
    GroupElement rho_public = wrap_key.rho_share;
    reconstruct(&rho_public);
    const uint64_t wrap_input = (rho_public.value + 4) % (uint64_t(1) << kBin);
    std::vector<GroupElement> wrap_output(interval_count);
    dfss::mic(party, split_share(wrap_input, kBin, wrap_input + 11), intervals,
        interval_count, wrap_output.data(), wrap_key);
    std::vector<uint64_t> wrap_expected(interval_count);
    for (int i = 0; i < interval_count; i++) {
        wrap_expected[i] =
            (intervals[i].left <= wrap_input && wrap_input < intervals[i].right)
                ? payload_value
                : 0;
    }
    log.check_vector("MIC shifted wrapping delta 4", wrap_output.data(),
                     wrap_expected, kBout);
    freeMICKeyPack(wrap_key);

    for (uint64_t input : {uint64_t(0), uint64_t(3), uint64_t(5),
                           uint64_t(11), uint64_t(12), uint64_t(15)}) {
        MICBooleanKeyPack key = dfss::micBooleanOffline(party, kBin);
        std::vector<u8> output(interval_count, 0);
        dfss::micBoolean(party, split_share(input, kBin, input + 29), intervals,
                    interval_count, output.data(), key);

        for (int i = 0; i < interval_count; i++) {
            const u8 expected =
                static_cast<u8>(intervals[i].left <= input &&
                                input < intervals[i].right);
            log.check_bit("Boolean MIC interval " + std::to_string(i) +
                              " input " + std::to_string(input),
                          output[i], expected);
        }
        freeMICBooleanKeyPack(key);
    }
}

void check_comparison(ResultLog& log) {
    constexpr uint64_t payload_value = 19;
    const uint64_t thresholds[] = {0, 1, 6, uint64_t(1) << kBin};
    const uint64_t inputs[] = {0, 1, 5, 6, 7, 15};

    for (uint64_t threshold : thresholds) {
        for (uint64_t input : inputs) {
            ComparisonKeyPack key = dfss::comparisonOffline(
                party, kBin, kBout, split_share(payload_value, kBout, 113));
            const uint64_t expected =
                input < threshold ? payload_value : 0;

            GroupElement less = dfss::comparison(
                party, split_share(input, kBin, input + 19), threshold, key);
            log.check_scalar("comparison less scalar x " +
                                 std::to_string(input) + " threshold " +
                                 std::to_string(threshold),
                             less, expected);
            GroupElement less_void(0, kBout);
            dfss::comparison(
                party, &less_void,
                split_share(input, kBin, input + 19), threshold, key);
            log.check_scalar("comparison less void x " +
                                 std::to_string(input) + " threshold " +
                                 std::to_string(threshold),
                             less_void, expected);
            freeComparisonKeyPack(key);

            ComparisonBitKeyPack bit_key = dfss::comparisonBitOffline(
                party, kBin);
            u8 bit_less = dfss::comparisonBit(
                party, split_share(input, kBin, input + 37), threshold,
                bit_key);
            log.check_bit("comparison bit less scalar x " +
                              std::to_string(input) + " threshold " +
                              std::to_string(threshold),
                          bit_less, static_cast<u8>(input < threshold));
            freeComparisonBitKeyPack(bit_key);
        }
    }

    ComparisonKeyPack fixed_key = dfss::comparisonOffline(
        party, kBin, kBout, split_share(6, kBin, 211),
        split_share(payload_value, kBout, 127));
    GroupElement fixed_less =
        dfss::comparison(party, split_share(5, kBin, 39), fixed_key);
    log.check_scalar("comparison fixed threshold arithmetic", fixed_less,
                     payload_value);
    GroupElement fixed_less_void(0, kBout);
    dfss::comparison(party, &fixed_less_void, split_share(5, kBin, 39),
                     fixed_key);
    log.check_scalar("comparison fixed threshold arithmetic void",
                     fixed_less_void, payload_value);
    freeComparisonKeyPack(fixed_key);

    ComparisonBitKeyPack fixed_bit_key = dfss::comparisonBitOffline(
        party, kBin, split_share(6, kBin, 217));
    u8 fixed_bit_less =
        dfss::comparisonBit(party, split_share(7, kBin, 43), fixed_bit_key);
    log.check_bit("comparison fixed threshold bit", fixed_bit_less, 0);
    freeComparisonBitKeyPack(fixed_bit_key);

    constexpr int batch_size = 3;
    const uint64_t batch_inputs[batch_size] = {2, 5, 12};
    const uint64_t batch_thresholds[batch_size] = {3, 5, 13};
    ComparisonKeyPack batch_keys[batch_size];
    GroupElement batch_input_shares[batch_size];
    GroupElement batch_outputs[batch_size];
    std::vector<uint64_t> batch_expected(batch_size);
    for (int i = 0; i < batch_size; i++) {
        batch_keys[i] = dfss::comparisonOffline(
            party, kBin, kBout,
            split_share(batch_thresholds[i], kBin, 240 + i),
            split_share(payload_value, kBout, 250 + i));
        batch_input_shares[i] =
            split_share(batch_inputs[i], kBin, 260 + i);
        batch_outputs[i] = GroupElement(0, kBout);
        batch_expected[i] =
            batch_inputs[i] < batch_thresholds[i] ? payload_value : 0;
    }
    dfss::comparison(party, batch_outputs, batch_input_shares, batch_keys,
                     batch_size, kBin);
    log.check_vector("comparison batch overload", batch_outputs,
                     batch_expected, kBout);
    for (int i = 0; i < batch_size; i++) {
        freeComparisonKeyPack(batch_keys[i]);
    }

    ComparisonKeyPack extend_key =
        dfss::ringExtendOffline(party, kBin, kBout);
    for (uint64_t input : {uint64_t(0), uint64_t(7), uint64_t(15)}) {
        GroupElement extended = dfss::ringExtend(
            party, split_share(input, kBin, input + 51), kBout,
            extend_key);
        log.check_scalar("unsigned ring extension " +
                             std::to_string(input),
                         extended, input);
    }
    freeComparisonKeyPack(extend_key);
}

void check_signed_ring_ops(ResultLog& log) {
    constexpr int input_bits = 4;
    constexpr int output_bits = 8;
    const uint64_t extension_inputs[] = {0, 1, 7, 8, 9, 14, 15};
    for (uint64_t input : extension_inputs) {
        SignedRingExtensionKeyPack key =
            dfss::signedRingExtendOffline(party, input_bits, output_bits);
        GroupElement output = dfss::signedRingExtend(
            party, split_share(input, input_bits, input + 5), output_bits, key);
        const int64_t signed_value = signed_from_twos(input, input_bits);
        const uint64_t expected = twos_from_signed(signed_value, output_bits);
        log.check_scalar("signed ring extension " + std::to_string(input),
                         output, expected);
        freeSignedRingExtensionKeyPack(key);
    }

    constexpr int trunc_input_bits = 5;
    constexpr int trunc_shift = 2;
    constexpr int trunc_output_bits = trunc_input_bits - trunc_shift;
    const uint64_t trunc_inputs[] = {0, 1, 7, 8, 15, 16, 17, 27, 29, 31};
    for (uint64_t input : trunc_inputs) {
        SignedTruncateKeyPack key = dfss::signedTruncateOffline(
            party, trunc_input_bits, trunc_shift);
        GroupElement output = dfss::signedTruncate(
            party, split_share(input, trunc_input_bits, input + 23),
            trunc_shift, key);
        const int64_t signed_value = signed_from_twos(input, trunc_input_bits);
        const int64_t truncated = floor_div_pow2(signed_value, trunc_shift);
        const uint64_t expected =
            twos_from_signed(truncated, trunc_output_bits);
        log.check_scalar("signed truncate " + std::to_string(input),
                         output, expected);
        freeSignedTruncateKeyPack(key);
    }
}

void check_public_lut_et_mode(ResultLog& log) {
    const auto generator = [](uint64_t i) {
        return i * i + 3 * i + 5;
    };
    PublicLUTData generated = generatePublicLUT(kBin, kBout, generator);
    const std::string path = correctnessArtifactPath(
        "et_public_lut_party_" + std::to_string(party) + ".bin");
    savePublicLUT(path, generated);
    PublicLUTData table = loadPublicLUT(path);

    constexpr int entries = 1 << kBin;
    for (uint64_t input : {uint64_t(0), uint64_t(4),
                           uint64_t(entries - 1)}) {
        PublicLutKeyPack key = dfss::publicLutOffline(party, table);
        GroupElement output = dfss::publicLut(
            party, split_share(input, kBin, input + 23), table, key);
        log.check_scalar("public LUT ET mode default suffix input " +
                             std::to_string(input),
                         output, reduce_to_bits(generator(input), kBout));
        freePublicLutKeyPack(key);
    }

    for (uint64_t input : {uint64_t(1), uint64_t(7)}) {
        dfss::LutEvalKeyPack key = dfss::lutEvalOffline(party, table);
        GroupElement output = dfss::lutEval(
            party, split_share(input, kBin, input + 25), table, key);
        log.check_scalar("math LUT eval input " + std::to_string(input),
                         output, reduce_to_bits(generator(input), kBout));
        freePublicLutKeyPack(key);
    }

    for (uint64_t input : {uint64_t(2), uint64_t(9)}) {
        dfss::PublicLutOptions options;
        options.suffix_bits = 2;
        PublicLutKeyPack key = dfss::publicLutOffline(party, table, options);
        std::vector<GroupElement> shifted(entries);
        for (int i = 0; i < entries; i++) {
            shifted[i] = GroupElement(0, kBout);
        }
        GroupElement output = dfss::publicLut(
            party, split_share(input, kBin, input + 29), table, key,
            shifted.data());
        log.check_scalar("public LUT ET mode explicit suffix input " +
                             std::to_string(input),
                         output, reduce_to_bits(generator(input), kBout));
        freePublicLutKeyPack(key);
    }

    const char* external_path = std::getenv("DFSS_PUBLIC_LUT_PATH");
    if (external_path != nullptr && external_path[0] != '\0') {
        PublicLUTData external_table = loadPublicLUT(external_path);
        const uint64_t external_entries = uint64_t(1) << external_table.Bin;
        std::vector<uint64_t> external_inputs = {
            0,
            external_entries / 4,
            external_entries / 2,
            external_entries - 1,
        };
        if (external_table.Bin > 1) {
            external_inputs.push_back(
                (uint64_t(1) << (external_table.Bin - 1)) - 1);
            external_inputs.push_back(uint64_t(1) << (external_table.Bin - 1));
        }
        for (uint64_t input : external_inputs) {
            PublicLutKeyPack key =
                dfss::publicLutOffline(party, external_table);
            GroupElement output = dfss::publicLut(
                party, split_share(input, external_table.Bin, input + 53),
                external_table, key);
            log.check_scalar("public LUT ET mode external input " +
                                 std::to_string(input),
                             output,
                             external_table.values[static_cast<size_t>(input)]
                                 .value);
            freePublicLutKeyPack(key);
        }
    }
}

void check_public_lut_full_mode(ResultLog& log) {
    const auto generator = [](uint64_t i) {
        return 7 * i + 11 + (i & 3);
    };
    PublicLUTData generated = generatePublicLUT(kBin, kBout, generator);
    const std::string path = correctnessArtifactPath(
        "correlated_dpf_public_lut_party_" + std::to_string(party) + ".bin");
    savePublicLUT(path, generated);
    PublicLUTData table = loadPublicLUT(path);

    constexpr int entries = 1 << kBin;
    for (uint64_t input : {uint64_t(0), uint64_t(6),
                           uint64_t(entries - 1)}) {
        dfss::PublicLutOptions options;
        options.early_termination = false;
        PublicLutKeyPack key = dfss::publicLutOffline(party, table, options);
        GroupElement output = dfss::publicLut(
            party, split_share(input, kBin, input + 37), table, key);
        log.check_scalar("public LUT full mode input " +
                             std::to_string(input),
                         output, reduce_to_bits(generator(input), kBout));
        freePublicLutKeyPack(key);
    }

    dfss::PublicLutOptions options;
    options.early_termination = false;
    PublicLutKeyPack shifted_key = dfss::publicLutOffline(party, table, options);
    std::vector<GroupElement> shifted(entries);
    for (int i = 0; i < entries; i++) {
        shifted[i] = GroupElement(0, kBout);
    }
    constexpr uint64_t shifted_input = 9;
    GroupElement shifted_output = dfss::publicLut(
        party, split_share(shifted_input, kBin, shifted_input + 41),
        table, shifted_key, shifted.data());
    log.check_scalar("public LUT full mode shifted buffer",
                     shifted_output,
                     reduce_to_bits(generator(shifted_input), kBout));
    freePublicLutKeyPack(shifted_key);
}

namespace {

uint64_t expected_piecewise_poly_fixed(
    uint64_t input, const PublicPiecewisePolyData& poly) {
    int segment = -1;
    for (int m = 0; m + 1 < static_cast<int>(poly.breakpoints.size()); m++) {
        if (poly.breakpoints[m] <= input && input < poly.breakpoints[m + 1]) {
            segment = m;
            break;
        }
    }
    if (segment < 0) {
        throw std::runtime_error("test input outside public polynomial domain");
    }

    const int64_t x = signed_from_twos(input, poly.Bin);
    __int128 total = 0;
    __int128 x_power = 1;
    for (int i = 0; i <= poly.degree; i++) {
        const GroupElement coeff =
            poly.coefficients[segment * (poly.degree + 1) + i];
        const int64_t signed_coeff = signed_from_twos(coeff.value, poly.Bout);
        const int shift = (poly.degree - i) * poly.scale;
        total += (static_cast<__int128>(signed_coeff) << shift) * x_power;
        x_power *= x;
    }
    const int64_t scaled =
        floor_div_pow2_i128(total, poly.degree * poly.scale);
    return twos_from_signed(scaled, poly.Bout);
}

std::vector<uint64_t> sample_piecewise_poly_inputs(
    const PublicPiecewisePolyData& poly) {
    std::vector<uint64_t> inputs;
    for (int m = 0; m + 1 < static_cast<int>(poly.breakpoints.size()); m++) {
        const uint64_t left = poly.breakpoints[m];
        const uint64_t right = poly.breakpoints[m + 1];
        if (left >= right) {
            continue;
        }
        const uint64_t mid = left + (right - left - 1) / 2;
        const uint64_t last = right - 1;
        inputs.push_back(left);
        inputs.push_back(mid);
        inputs.push_back(last);
    }
    return inputs;
}

std::vector<uint64_t> load_accuracy_inputs(const std::string& path) {
    std::ifstream in(path);
    if (!in) {
        throw std::runtime_error("failed to open accuracy input CSV: " + path);
    }
    std::vector<uint64_t> inputs;
    std::string line;
    bool first = true;
    while (std::getline(in, line)) {
        if (line.empty()) {
            continue;
        }
        if (first) {
            first = false;
            if (line.find("encoded_x") == 0) {
                continue;
            }
        }
        std::stringstream ss(line);
        std::string field;
        if (!std::getline(ss, field, ',')) {
            continue;
        }
        inputs.push_back(static_cast<uint64_t>(std::stoull(field)));
    }
    return inputs;
}

void check_mic_poly_eval_data(ResultLog& log,
                              const PublicPiecewisePolyData& poly,
                              const std::vector<uint64_t>& inputs,
                              const std::string& label) {
    for (uint64_t input : inputs) {
        MICPolyEvalKeyPack key = dfss::micPolyEvalOffline(party, poly);
        GroupElement output = dfss::micPolyEval(
            party, split_share(input, poly.Bin, input + 43), poly, key);
        log.check_scalar(label + " input " + std::to_string(input),
                         output, expected_piecewise_poly_fixed(input, poly));
        freeMICPolyEvalKeyPack(key);
    }
}

void check_mic_poly_eval_accuracy_csv(ResultLog& log,
                                      const PublicPiecewisePolyData& poly,
                                      const std::string& inputs_path,
                                      const std::string& output_path) {
    const std::vector<uint64_t> inputs = load_accuracy_inputs(inputs_path);
    std::ofstream out;
    if (party == SERVER) {
        out.open(output_path);
        if (!out) {
            throw std::runtime_error("failed to open accuracy output CSV: " +
                                     output_path);
        }
        out << "encoded_x,secure_y_encoded,material_y_encoded\n";
    }

    for (uint64_t input : inputs) {
        MICPolyEvalKeyPack key = dfss::micPolyEvalOffline(party, poly);
        GroupElement output = dfss::micPolyEval(
            party, split_share(input, poly.Bin, input + 43), poly, key);
        const uint64_t expected = expected_piecewise_poly_fixed(input, poly);
        GroupElement reconstructed = output;
        reconstruct(&reconstructed);
        if (party == SERVER) {
            out << input << ',' << reconstructed.value << ',' << expected
                << '\n';
        }
        log.check_scalar("MIC PolyEval accuracy external input " +
                             std::to_string(input),
                         output, expected);
        freeMICPolyEvalKeyPack(key);
    }
}

}  // namespace

void check_mic_poly_eval(ResultLog& log) {
    constexpr int poly_bin = 6;
    constexpr int poly_bout = 16;
    constexpr int poly_scale = 4;
    constexpr int degree = 2;
    const std::vector<uint64_t> breakpoints = {0, 32, 64};
    const auto coeff = [](int segment, int power) -> uint64_t {
        const int64_t segment0[] = {16, 4, 8};
        const int64_t segment1[] = {-16, 8, -4};
        return twos_from_signed(
            segment == 0 ? segment0[power] : segment1[power], poly_bout);
    };
    PublicPiecewisePolyData generated = generatePublicPiecewisePolynomial(
        poly_bin, poly_bout, poly_scale, degree, breakpoints, coeff);
    const std::string path = correctnessArtifactPath(
        "mic_poly_eval_party_" + std::to_string(party) + ".bin");
    savePublicPiecewisePolynomial(path, generated);
    PublicPiecewisePolyData poly = loadPublicPiecewisePolynomial(path);

    const std::vector<uint64_t> inputs = {0, 8, 24, 36, 60};
    check_mic_poly_eval_data(log, poly, inputs, "MIC PolyEval fixed");

    const auto constant_coeff = [](int segment, int) -> uint64_t {
        const int64_t values[] = {16, -8};
        return twos_from_signed(values[segment], poly_bout);
    };
    PublicPiecewisePolyData constant_poly = generatePublicPiecewisePolynomial(
        poly_bin, poly_bout, poly_scale, 0, breakpoints, constant_coeff);
    const std::vector<uint64_t> constant_inputs = {0, 31, 32, 63};
    check_mic_poly_eval_data(log, constant_poly, constant_inputs,
                             "MIC PolyEval piecewise constant");

    const char* external_path = std::getenv("DFSS_PUBLIC_POLY_PATH");
    const char* accuracy_inputs_path =
        std::getenv("DFSS_ACCURACY_INPUTS_PATH");
    const char* accuracy_output_csv =
        std::getenv("DFSS_ACCURACY_OUTPUT_CSV");
    const bool has_accuracy_inputs =
        accuracy_inputs_path != nullptr && accuracy_inputs_path[0] != '\0';
    const bool has_accuracy_output =
        accuracy_output_csv != nullptr && accuracy_output_csv[0] != '\0';
    if (has_accuracy_inputs != has_accuracy_output) {
        throw std::runtime_error(
            "DFSS_ACCURACY_INPUTS_PATH and DFSS_ACCURACY_OUTPUT_CSV "
            "must be set together");
    }
    if ((has_accuracy_inputs || has_accuracy_output) &&
        (external_path == nullptr || external_path[0] == '\0')) {
        throw std::runtime_error(
            "DFSS_PUBLIC_POLY_PATH is required for accuracy CSV mode");
    }
    if (external_path != nullptr && external_path[0] != '\0') {
        PublicPiecewisePolyData external_poly =
            loadPublicPiecewisePolynomial(external_path);
        if (has_accuracy_inputs) {
            check_mic_poly_eval_accuracy_csv(
                log, external_poly, accuracy_inputs_path, accuracy_output_csv);
        } else {
            check_mic_poly_eval_data(
                log, external_poly, sample_piecewise_poly_inputs(external_poly),
                "MIC PolyEval external PublicPiecewisePolyData");
        }
    }
}
