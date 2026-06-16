#include "math/polyeval.h"

#include <algorithm>
#include <stdexcept>
#include <unordered_map>
#include <vector>

#include "mpc/secure_ops.h"
#include "mpc/api.h"
#include "buildingblock/mic.h"
#include "buildingblock/ring_extension.h"
#include "buildingblock/truncation.h"
#include "fss/internal/ggm.h"
#include "fss/internal/payload_conversion.h"

namespace {

GroupElement signExtendPublicValue(GroupElement value, int output_bits) {
    assert(output_bits >= value.bitsize);
    uint64_t extended_value = value.value;
    if (value.bitsize < 64 &&
        value.value > ((uint64_t(1) << (value.bitsize - 1)) - 1)) {
        extended_value |= ((uint64_t(1) << (output_bits - value.bitsize)) - 1)
                          << value.bitsize;
    }
    return GroupElement(extended_value, output_bits);
}

uint64_t binomialCoefficient(int n, int k) {
    if (k < 0 || k > n) {
        return 0;
    }
    if (k > n - k) {
        k = n - k;
    }
    __uint128_t result = 1;
    for (int i = 1; i <= k; i++) {
        result = (result * static_cast<uint64_t>(n - k + i)) /
                 static_cast<uint64_t>(i);
    }
    return static_cast<uint64_t>(result);
}

GroupElement publicPower(uint64_t base, int exponent, int bits) {
    GroupElement result(1, bits);
    GroupElement cur(base, bits);
    int e = exponent;
    while (e > 0) {
        if (e & 1) {
            result = result * cur;
        }
        e >>= 1;
        if (e > 0) {
            cur = cur * cur;
        }
    }
    return result;
}

BooleanElement blockLsb(const osuCrypto::block& input) {
    return _mm_cvtsi128_si64x(input) & 1;
}

GroupElement prescalePublicCoefficient(GroupElement coefficient,
                                       int coefficient_bits, int wide_bits,
                                       int scale_shift) {
    coefficient.bitsize = coefficient_bits;
    GroupElement extended = signExtendPublicValue(coefficient, wide_bits);
    __uint128_t shifted =
        static_cast<__uint128_t>(extended.value) << scale_shift;
    return GroupElement(static_cast<uint64_t>(shifted), wide_bits);
}

void beaverMultOnlineOneRound(int party_id, const GroupElement* input0,
                              const GroupElement* input1,
                              const GroupElement* a,
                              const GroupElement* b,
                              const GroupElement* c,
                              GroupElement* output, int size) {
    if (size <= 0) {
        return;
    }
    const int bitsize = input0[0].bitsize;
    std::vector<GroupElement> opened(2 * size, GroupElement(0, bitsize));
    for (int i = 0; i < size; i++) {
        if (input0[i].bitsize != bitsize || input1[i].bitsize != bitsize ||
            a[i].bitsize != bitsize || b[i].bitsize != bitsize ||
            c[i].bitsize != bitsize) {
            throw std::invalid_argument(
                "one-round Beaver multiplication requires one ring size");
        }
        opened[i] = input0[i] - a[i];
        opened[size + i] = input1[i] - b[i];
    }
    reconstruct(2 * size, opened.data(), bitsize);
    for (int i = 0; i < size; i++) {
        const GroupElement& alpha = opened[i];
        const GroupElement& beta = opened[size + i];
        output[i] = c[i] + b[i] * alpha + a[i] * beta +
                    alpha * beta * static_cast<uint64_t>(party_id - SERVER);
    }
}

void validateMicPolyEvalShape(const PublicPiecewisePolyData& poly,
                              const MICPolyEvalKeyPack& key) {
    if (poly.Bin != key.Bin || poly.Bout != key.Bout ||
        poly.scale != key.scale || poly.degree != key.degree ||
        static_cast<int>(poly.breakpoints.size()) != key.segment_count + 1) {
        throw std::invalid_argument("MIC PolyEval public data does not match key");
    }
}

uint64_t prefixStateKey(int level, uint64_t prefix) {
    return (static_cast<uint64_t>(level) << 32) | prefix;
}

GroupElement evalPrefixPayload(int party_id, const DPFKeyPack& key,
                               const GroupElement& root_payload_cw,
                               int prefix_level, osuCrypto::block node,
                               BooleanElement control_bit) {
    const osuCrypto::block label = dfss::internal::setBlockLsb(
        node, static_cast<osuCrypto::u8>(control_bit));
    const uint64_t converted_value =
        dfss::internal::convertPayload_iDPF(key.Bout, label);
    GroupElement converted(converted_value, key.Bout);
    const GroupElement& cw =
        prefix_level == 0 ? root_payload_cw : key.g[prefix_level - 1];
    GroupElement local_output =
        converted + cw * static_cast<uint64_t>(control_bit);
    return party_id == SERVER ? local_output : -local_output;
}

struct PrefixEvalState {
    osuCrypto::block node = osuCrypto::ZeroBlock;
    BooleanElement control_bit = 0;
    GroupElement prefix_sum;
    int sign_count = 0;
    BooleanElement previous_direction = 0;
};

std::unordered_map<uint64_t, GroupElement> evalPrefixBoundaries(
    int party_id, const DPFKeyPack& key, const GroupElement& root_payload_cw,
    GroupElement payload_share, const std::vector<uint64_t>& endpoints) {
    if (key.Bin >= 32) {
        throw std::invalid_argument("MIC prefix evaluation supports Bin < 32");
    }
    const int n = key.Bin;
    const uint64_t domain = uint64_t(1) << n;
    std::vector<uint64_t> sorted = endpoints;
    std::sort(sorted.begin(), sorted.end());
    sorted.erase(std::unique(sorted.begin(), sorted.end()), sorted.end());

    std::unordered_map<uint64_t, PrefixEvalState> memo;
    PrefixEvalState root;
    root.node = key.k[0];
    root.control_bit = static_cast<BooleanElement>(party_id - 2);
    root.prefix_sum = GroupElement(0, key.Bout);
    memo[prefixStateKey(0, 0)] = root;

    std::unordered_map<uint64_t, GroupElement> result;
    osuCrypto::AES aes;
    const static osuCrypto::block pt[2] = {osuCrypto::ZeroBlock,
                                           osuCrypto::OneBlock};
    osuCrypto::block ct[2];

    for (uint64_t endpoint : sorted) {
        if (endpoint == 0) {
            result[endpoint] = GroupElement(0, key.Bout);
            continue;
        }
        if (endpoint == domain) {
            result[endpoint] = payload_share;
            continue;
        }
        if (endpoint > domain) {
            throw std::invalid_argument("MIC endpoint outside domain");
        }

        const uint64_t phi = endpoint - 1;
        int cached_level = 0;
        uint64_t cached_prefix = 0;
        for (int level = n; level >= 0; level--) {
            const uint64_t prefix =
                level == 0 ? 0 : (phi >> (n - level));
            if (memo.find(prefixStateKey(level, prefix)) != memo.end()) {
                cached_level = level;
                cached_prefix = prefix;
                break;
            }
        }

        PrefixEvalState state =
            memo[prefixStateKey(cached_level, cached_prefix)];
        for (int level = cached_level; level < n; level++) {
            const BooleanElement direction =
                static_cast<BooleanElement>((phi >> (n - 1 - level)) & 1);
            if (direction != state.previous_direction) {
                GroupElement prefix_output = evalPrefixPayload(
                    party_id, key, root_payload_cw, level, state.node,
                    state.control_bit);
                state.prefix_sum =
                    (state.sign_count % 2 == 0)
                        ? state.prefix_sum + prefix_output
                        : state.prefix_sum - prefix_output;
                state.sign_count++;
            }

            aes.setKey(state.node);
            aes.ecbEncTwoBlocks(pt, ct);
            const osuCrypto::block level_cw = key.k[level + 1];
            const BooleanElement level_tau = key.v[2 * level + direction];
            if (state.control_bit == static_cast<BooleanElement>(1)) {
                state.node = ct[direction] ^ level_cw;
                state.control_bit = blockLsb(ct[direction]) ^ level_tau;
            } else {
                state.node = ct[direction];
                state.control_bit = blockLsb(ct[direction]);
            }
            state.previous_direction = direction;

            const uint64_t next_prefix =
                level + 1 == 0 ? 0 : (phi >> (n - (level + 1)));
            memo[prefixStateKey(level + 1, next_prefix)] = state;
        }

        if ((phi & 1) == 0) {
            GroupElement leaf_output = evalPrefixPayload(
                party_id, key, root_payload_cw, n, state.node,
                state.control_bit);
            state.prefix_sum =
                (state.sign_count % 2 == 0)
                    ? state.prefix_sum + leaf_output
                    : state.prefix_sum - leaf_output;
        }
        result[endpoint] = state.prefix_sum;
    }
    return result;
}

void micWithDeltaValue(int party_id, uint64_t delta_value,
                       const PublicInterval* intervals, int interval_count,
                       GroupElement* output, const MICKeyPack& key) {
    if (key.Bin <= 0 || key.Bin >= 32) {
        throw std::invalid_argument("mic requires 0 < Bin < 32");
    }
    const uint64_t domain = uint64_t(1) << key.Bin;
    delta_value %= domain;

    std::vector<uint64_t> shifted_left(interval_count, 0);
    std::vector<uint64_t> shifted_right(interval_count, 0);
    std::vector<uint64_t> lengths(interval_count, 0);
    std::vector<uint64_t> endpoints;

    for (int i = 0; i < interval_count; i++) {
        if (intervals[i].left > intervals[i].right ||
            intervals[i].right > domain) {
            throw std::invalid_argument(
                "mic interval must satisfy 0 <= left <= right <= 2^Bin");
        }
        const uint64_t length = intervals[i].right - intervals[i].left;
        lengths[i] = length;
        if (length == 0 || length == domain) {
            continue;
        }
        shifted_left[i] = (intervals[i].left + domain - delta_value) % domain;
        shifted_right[i] =
            (intervals[i].right % domain + domain - delta_value) % domain;
        endpoints.push_back(shifted_left[i]);
        endpoints.push_back(shifted_right[i]);
    }

    std::unordered_map<uint64_t, GroupElement> prefix_values =
        evalPrefixBoundaries(party_id, key.iDPFKey, key.root_payload_cw,
                             key.payload_share, endpoints);

    for (int i = 0; i < interval_count; i++) {
        if (lengths[i] == 0) {
            output[i] = GroupElement(0, key.Bout);
        } else if (lengths[i] == domain) {
            output[i] = key.payload_share;
        } else if (shifted_left[i] < shifted_right[i]) {
            output[i] =
                prefix_values[shifted_right[i]] - prefix_values[shifted_left[i]];
        } else {
            output[i] = key.payload_share - prefix_values[shifted_left[i]] +
                        prefix_values[shifted_right[i]];
        }
    }
}

}  // namespace

namespace dfss {

MICPolyEvalKeyPack micPolyEvalOffline(
    int party_id, const PublicPiecewisePolyData& poly) {
    if (poly.Bin <= 0 || poly.Bin >= 31 || poly.Bout <= 0 ||
        poly.scale < 0 || poly.degree < 0) {
        throw std::invalid_argument("micPolyEvalOffline invalid parameters");
    }
    const int segment_count = static_cast<int>(poly.breakpoints.size()) - 1;
    if (segment_count <= 0) {
        throw std::invalid_argument("micPolyEvalOffline requires segments");
    }
    const int wide_bits = poly.Bout + poly.degree * poly.scale;
    if (wide_bits < poly.Bin || wide_bits <= 0 || wide_bits > 63) {
        throw std::invalid_argument(
            "micPolyEvalOffline requires Bin <= Bout + degree*scale <= 63");
    }

    MICPolyEvalKeyPack key;
    key.Bin = poly.Bin;
    key.Bout = poly.Bout;
    key.wide_bits = wide_bits;
    key.scale = poly.scale;
    key.degree = poly.degree;
    key.segment_count = segment_count;

    GroupElement one(static_cast<uint64_t>(party_id - SERVER), wide_bits);
    key.MICKey = micOffline(party_id, poly.Bin, wide_bits, one);
    if (poly.degree > 0 && wide_bits != poly.Bin) {
        key.ExtKey = signedRingExtendOffline(party_id, poly.Bin, wide_bits);
    }
    if (poly.degree * poly.scale > 0) {
        key.TruncKey = signedTruncateOffline(
            party_id, wide_bits, poly.degree * poly.scale);
    }

    key.r_powers = makeKeyArray<GroupElement>(poly.degree + 1);
    key.r_powers[0] = one;
    auto rng = secure_prng();
    if (poly.degree >= 1) {
        key.r_powers[1] = random_ge_from_prng(rng, wide_bits);
    }
    // Offline shares of r^j let online evaluation recover all powers from one
    // opened delta, without Horner-style serial multiplications.
    if (poly.degree >= 2) {
        const int power_mult_count = poly.degree - 1;
        std::vector<GroupElement> power_a(power_mult_count,
                                          GroupElement(0, wide_bits));
        std::vector<GroupElement> power_b(power_mult_count,
                                          GroupElement(0, wide_bits));
        std::vector<GroupElement> power_c(power_mult_count,
                                          GroupElement(0, wide_bits));
        beaver_mult_offline(party_id, power_a.data(), power_b.data(),
                            power_c.data(), peer, power_mult_count);
        for (int j = 2; j <= poly.degree; j++) {
            const int idx = j - 2;
            key.r_powers[j] = beaver_mult_online(
                party_id, key.r_powers[j - 1], key.r_powers[1],
                power_a[idx], power_b[idx], power_c[idx], peer);
        }
    }

    if (poly.degree > 0) {
        key.MulAList = makeKeyArray<GroupElement>(poly.degree);
        key.MulBList = makeKeyArray<GroupElement>(poly.degree);
        key.MulCList = makeKeyArray<GroupElement>(poly.degree);
        for (int i = 0; i < poly.degree; i++) {
            key.MulAList[i] = GroupElement(0, wide_bits);
            key.MulBList[i] = GroupElement(0, wide_bits);
            key.MulCList[i] = GroupElement(0, wide_bits);
        }
        beaver_mult_offline(party_id, key.MulAList.data(), key.MulBList.data(),
                            key.MulCList.data(), peer, poly.degree);
    }
    return key;
}

GroupElement micPolyEval(int party_id, GroupElement input,
                         const PublicPiecewisePolyData& poly,
                         const MICPolyEvalKeyPack& key) {
    validateMicPolyEvalShape(poly, key);

    std::vector<PublicInterval> intervals(key.segment_count);
    const uint64_t domain = uint64_t(1) << poly.Bin;
    for (int m = 0; m < key.segment_count; m++) {
        intervals[m] = {poly.breakpoints[m], poly.breakpoints[m + 1]};
        if (intervals[m].left >= intervals[m].right ||
            intervals[m].right > domain) {
            throw std::invalid_argument("MIC PolyEval invalid breakpoint");
        }
    }

    std::vector<GroupElement> segment_indicators(key.segment_count);
    if (key.degree == 0) {
        mic(party_id, input, intervals.data(), key.segment_count,
            segment_indicators.data(), key.MICKey);
        GroupElement selected_constant(0, key.wide_bits);
        for (int m = 0; m < key.segment_count; m++) {
            const GroupElement raw_coeff =
                poly.coefficients[static_cast<size_t>(m)];
            const GroupElement coeff = prescalePublicCoefficient(
                raw_coeff, poly.Bout, key.wide_bits, 0);
            selected_constant =
                selected_constant + coeff * segment_indicators[m];
        }
        return GroupElement(selected_constant.value, key.Bout);
    }

    GroupElement x = input;
    if (key.wide_bits == input.bitsize) {
        mic(party_id, input, intervals.data(), key.segment_count,
            segment_indicators.data(), key.MICKey);
    } else {
        const int open_bits = input.bitsize + 1;
        GroupElement lifted_input(input.value, open_bits);
        GroupElement opened_deltas[3] = {
            GroupElement((input - key.MICKey.rho_share).value, open_bits),
            GroupElement(
                (lifted_input - key.ExtKey.CarryKey.MICKey.rho_share).value,
                open_bits),
            GroupElement((input - key.ExtKey.SignKey.MICKey.rho_share).value,
                         open_bits),
        };
        // MIC selection and signed extension need independent public offsets;
        // opening them together keeps this stage to one online round.
        reconstruct(3, opened_deltas, open_bits);

        micWithDeltaValue(party_id, opened_deltas[0].value, intervals.data(),
                          key.segment_count, segment_indicators.data(),
                          key.MICKey);

        const uint64_t input_domain = uint64_t(1) << input.bitsize;
        const uint64_t signed_threshold = uint64_t(1)
                                          << (input.bitsize - 1);
        const PublicInterval carry_interval[1] = {{0, input_domain}};
        const PublicInterval sign_interval[1] = {{0, signed_threshold}};
        GroupElement is_below_lift_modulus(0, key.wide_bits);
        GroupElement is_nonnegative(0, key.wide_bits);
        micWithDeltaValue(party_id, opened_deltas[1].value, carry_interval, 1,
                          &is_below_lift_modulus,
                          key.ExtKey.CarryKey.MICKey);
        micWithDeltaValue(party_id, opened_deltas[2].value, sign_interval, 1,
                          &is_nonnegative, key.ExtKey.SignKey.MICKey);

        GroupElement one(static_cast<uint64_t>(party_id - SERVER),
                         key.wide_bits);
        GroupElement carry = one - is_below_lift_modulus;
        GroupElement unsigned_extended =
            GroupElement(input.value, key.wide_bits) - carry * input_domain;
        GroupElement sign = one - is_nonnegative;
        x = unsigned_extended - sign * input_domain;
    }

    GroupElement delta_share = x;
    if (key.degree >= 1) {
        delta_share = x + key.r_powers[1];
    }
    reconstruct(&delta_share);
    const uint64_t delta = delta_share.value;

    std::vector<GroupElement> selected_coefficients(
        key.degree + 1, GroupElement(0, key.wide_bits));
    for (int m = 0; m < key.segment_count; m++) {
        for (int i = 0; i <= key.degree; i++) {
            const GroupElement raw_coeff =
                poly.coefficients[static_cast<size_t>(m * (key.degree + 1) + i)];
            const GroupElement coeff = prescalePublicCoefficient(
                raw_coeff, poly.Bout, key.wide_bits,
                (key.degree - i) * key.scale);
            selected_coefficients[i] =
                selected_coefficients[i] + coeff * segment_indicators[m];
        }
    }

    std::vector<GroupElement> powers(
        key.degree + 1, GroupElement(0, key.wide_bits));
    powers[0] = GroupElement(static_cast<uint64_t>(party_id - SERVER),
                             key.wide_bits);
    for (int i = 1; i <= key.degree; i++) {
        GroupElement power_share(0, key.wide_bits);
        for (int j = 0; j <= i; j++) {
            const uint64_t binom = binomialCoefficient(i, j);
            const GroupElement delta_power =
                publicPower(delta, i - j, key.wide_bits);
            GroupElement term =
                key.r_powers[j] * binom * delta_power.value;
            if (j % 2 == 1) {
                term = -term;
            }
            power_share = power_share + term;
        }
        powers[i] = power_share;
    }

    GroupElement result = selected_coefficients[0];
    if (key.degree > 0) {
        std::vector<GroupElement> mul_outputs(key.degree);
        std::vector<GroupElement> mul_lhs(key.degree);
        std::vector<GroupElement> mul_rhs(key.degree);
        for (int i = 1; i <= key.degree; i++) {
            mul_lhs[i - 1] = selected_coefficients[i];
            mul_rhs[i - 1] = powers[i];
            mul_outputs[i - 1] = GroupElement(0, key.wide_bits);
        }
        beaverMultOnlineOneRound(
            party_id, mul_lhs.data(), mul_rhs.data(), key.MulAList.data(),
            key.MulBList.data(), key.MulCList.data(), mul_outputs.data(),
            key.degree);
        for (const GroupElement& output : mul_outputs) {
            result = result + output;
        }
    }

    const int truncation = key.degree * key.scale;
    if (truncation == 0) {
        return GroupElement(result.value, key.Bout);
    }
    return signedTruncate(party_id, result, truncation, key.TruncKey);
}

}  // namespace dfss
