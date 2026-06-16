#include "legacy/spline_approx.h"

#include <cassert>
#include <cstdlib>
#include <iostream>
#include <vector>

#include "mpc/secure_ops.h"
#include "mpc/api.h"
#include "legacy/basic_ops.h"
#include "legacy/comparison.h"
#include "legacy/utils.h"

namespace {

GroupElement zeroExtendPublicValue(GroupElement value, int output_bits) {
    assert(output_bits >= value.bitsize);
    return GroupElement(value.value, output_bits);
}

u8 wrapOfSharedValue(int party_id, GroupElement share) {
    const uint64_t mask =
        share.bitsize == 64 ? ~uint64_t(0)
                            : ((uint64_t(1) << share.bitsize) - 1);
    GroupElement mill_input =
        party_id == SERVER ? share
                           : GroupElement(mask - share.value, share.bitsize);
    u8 wrap = 0;
    peer->mill(&wrap, &mill_input, 1);
    return wrap;
}

GroupElement zeroExtendSharedValue(int party_id, GroupElement share,
                                   int output_bits) {
    assert(output_bits >= share.bitsize);
    if (output_bits == share.bitsize) {
        return share;
    }

    u8 wrap = wrapOfSharedValue(party_id, share);
    GroupElement arithmetic_wrap = B2A(party_id, wrap, output_bits, peer);

    GroupElement extended_share(share.value, output_bits);
    return extended_share -
           arithmetic_wrap * (uint64_t(1) << share.bitsize);
}

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

::LegacyComparisonKeyPack signExtendOffline(int party_id, int input_bits,
                                      int output_bits) {
    GroupElement sign_threshold(
        (uint64_t)(party_id - 2) * (uint64_t(1) << (input_bits - 1)),
        input_bits);
    GroupElement one((uint64_t)(party_id - 2), output_bits);
    return dfss::legacy::legacyComparisonOffline(party_id, input_bits, output_bits,
                                           sign_threshold, one);
}

GroupElement signExtendWithKey(int party_id, GroupElement input,
                               int output_bits,
                               const ::LegacyComparisonKeyPack& key) {
    GroupElement is_nonnegative = dfss::legacy::legacyComparison(party_id, input,
                                                           key);
    GroupElement unsigned_input = zeroExtendSharedValue(party_id, input,
                                                        output_bits);
    GroupElement one((uint64_t)(party_id - 2), output_bits);
    GroupElement sign = one - is_nonnegative;
    return unsigned_input - sign * (uint64_t(1) << input.bitsize);
}

}  // namespace

namespace dfss::legacy {

SplinePolyApproxKeyPack splinePolyApproxOffline(
    int party_id, int Bin, int Bout, const GroupElement* public_coefficients,
    int degree, int seg_num, int fixed_scale) {
    SplinePolyApproxKeyPack output;
    output.Bin = Bin;
    output.Bout = Bout;
    output.degNum = degree;
    output.segNum = seg_num;
    output.fixed_scale = fixed_scale;
    output.EvalSignKeyList = NULL;
    output.EvalExtendKeyList = NULL;
    output.EvalScaleTRKeyList = NULL;
    output.EvalAList = NULL;
    output.EvalBList = NULL;
    output.EvalCList = NULL;
    int truncation_bits = Bin - log2floor(seg_num);

    switch (degree) {
        case 2: {
            output.coefficientList = makeKeyArray<GroupElement>(3 * seg_num);
            GroupElement* coefficient_list = output.coefficientList.data();
            auto rng = secure_prng();
            GroupElement random_mask = random_ge_from_prng(rng, Bout);

            if (fixed_scale > 0) {
                const int product_bits = Bout + fixed_scale;
                for (int i = 0; i < seg_num; i++) {
                    GroupElement public_a =
                        signExtendPublicValue(public_coefficients[i],
                                              product_bits);
                    GroupElement public_b = signExtendPublicValue(
                        public_coefficients[seg_num + i], product_bits);
                    GroupElement public_c = signExtendPublicValue(
                        public_coefficients[2 * seg_num + i], product_bits);
                    coefficient_list[i] =
                        public_a * (uint64_t)(party_id - 2);
                    coefficient_list[seg_num + i] =
                        public_b * (uint64_t)(party_id - 2);
                    coefficient_list[2 * seg_num + i] =
                        public_c * (uint64_t)(party_id - 2);
                }

                output.EvalScaleTRKeyList =
                    makeKeyArray<LegacyTRKeyPack>(degree + 1);
                for (int i = 0; i < degree + 1; i++) {
                    output.EvalScaleTRKeyList[i] =
                        truncateOffline(party_id, product_bits, fixed_scale);
                }
                output.EvalExtendKeyList =
                    makeKeyArray<::LegacyComparisonKeyPack>(2);
                output.EvalExtendKeyList[0] =
                    legacyRingExtendOffline(party_id, Bin, product_bits);
                output.EvalExtendKeyList[1] =
                    legacyRingExtendOffline(party_id, Bout, product_bits);
                output.EvalAList = makeKeyArray<GroupElement>(degree + 1);
                output.EvalBList = makeKeyArray<GroupElement>(degree + 1);
                output.EvalCList = makeKeyArray<GroupElement>(degree + 1);
                for (int i = 0; i < degree + 1; i++) {
                    output.EvalAList[i].bitsize = product_bits;
                    output.EvalBList[i].bitsize = product_bits;
                    output.EvalCList[i].bitsize = product_bits;
                }
                beaver_mult_offline(party_id, output.EvalAList,
                                    output.EvalBList, output.EvalCList, peer,
                                    degree + 1);
            } else {
                if (Bout > Bin) {
                    output.EvalExtendKeyList =
                        makeKeyArray<::LegacyComparisonKeyPack>(1);
                    output.EvalExtendKeyList[0] =
                        legacyRingExtendOffline(party_id, Bin, Bout);
                }
                for (int i = 0; i < seg_num; i++) {
                    coefficient_list[i] =
                        zeroExtendPublicValue(public_coefficients[i], Bout) *
                        (uint64_t)(party_id - 2);
                }

                std::vector<GroupElement> tmp_a(1 + seg_num);
                std::vector<GroupElement> tmp_b(1 + seg_num);
                std::vector<GroupElement> tmp_c(1 + seg_num);
                std::vector<GroupElement> mul_a(1 + seg_num);
                std::vector<GroupElement> mul_b(1 + seg_num);
                std::vector<GroupElement> mul_res(1 + seg_num);
                for (int j = 0; j < 1 + seg_num; j++) {
                    tmp_a[j].bitsize = Bout;
                    tmp_b[j].bitsize = Bout;
                    tmp_c[j].bitsize = Bout;
                    mul_a[j] = j < seg_num ? coefficient_list[j] : random_mask;
                    mul_b[j] = random_mask;
                    mul_res[j].bitsize = Bout;
                }
                beaver_mult_offline(party_id, tmp_a.data(), tmp_b.data(),
                                    tmp_c.data(), peer, 1 + seg_num);
                beaver_mult_online(party_id, mul_a.data(), mul_b.data(),
                                   tmp_a.data(), tmp_b.data(), tmp_c.data(),
                                   mul_res.data(), 1 + seg_num, peer);

                for (int i = 0; i < seg_num; i++) {
                    GroupElement public_a =
                        zeroExtendPublicValue(public_coefficients[i], Bout);
                    GroupElement public_b = zeroExtendPublicValue(
                        public_coefficients[seg_num + i], Bout);
                    GroupElement public_c = zeroExtendPublicValue(
                        public_coefficients[2 * seg_num + i], Bout);
                    coefficient_list[seg_num + i] =
                        public_b * (uint64_t)(party_id - 2) - mul_res[i] * 2;
                    coefficient_list[2 * seg_num + i] =
                        public_c * (uint64_t)(party_id - 2) +
                        public_a * mul_res[seg_num] - public_b * random_mask;
                }
            }

            output.random_mask = random_mask;
            output.TRKey = truncateOffline(party_id, Bin, truncation_bits);
            output.PriLUTKeyList =
                makeKeyArray<LegacyPrivateLutKey>(degree + 1);
            for (int i = 0; i < degree + 1; i++) {
                output.PriLUTKeyList[i] = privateLutOffline(
                    party_id, log2ceil(seg_num),
                    coefficient_list[i * seg_num].bitsize,
                    &(coefficient_list[i * seg_num]));
            }
            break;
        }
        default:
            std::cout << "[ERROR] Unsupported approx degree!" << std::endl;
            std::exit(-1);
    }
    return output;
}

GroupElement splinePolyApprox(int party_id, GroupElement input,
                              const SplinePolyApproxKeyPack& key) {
    int degree = key.degNum;
    int seg_num = key.segNum;
    const GroupElement* coefficient_list = key.coefficientList;
    GroupElement random_mask = key.random_mask;
    const LegacyTRKeyPack& tr_key = key.TRKey;
    const LegacyPrivateLutKey* private_lut_keys = key.PriLUTKeyList;
    GroupElement output(0, coefficient_list[0].bitsize);

    switch (degree) {
        case 2: {
            GroupElement truncated_input = truncate(
                party_id, input, input.bitsize - log2floor(seg_num), tr_key);
            GroupElement lut_output[degree + 1];
            for (int i = 0; i < degree + 1; i++) {
                lut_output[i] =
                    privateLut(party_id, truncated_input, private_lut_keys[i]);
            }

            if (key.fixed_scale > 0) {
                const int product_bits = key.Bout + key.fixed_scale;
                GroupElement extended_input = legacyRingExtend(
                    party_id, input, product_bits, key.EvalExtendKeyList[0]);

                GroupElement raw_x_squared = beaver_mult_online(
                    party_id, extended_input, extended_input,
                    key.EvalAList[0], key.EvalBList[0], key.EvalCList[0],
                    peer);
                GroupElement x_squared = truncate(
                    party_id, raw_x_squared, key.fixed_scale,
                    key.EvalScaleTRKeyList[0]);
                GroupElement x_squared_extended = legacyRingExtend(
                    party_id, x_squared, product_bits,
                    key.EvalExtendKeyList[1]);

                GroupElement raw_ax_squared = beaver_mult_online(
                    party_id, lut_output[0], x_squared_extended,
                    key.EvalAList[1], key.EvalBList[1], key.EvalCList[1],
                    peer);
                GroupElement ax_squared = truncate(
                    party_id, raw_ax_squared, key.fixed_scale,
                    key.EvalScaleTRKeyList[1]);

                GroupElement raw_bx = beaver_mult_online(
                    party_id, lut_output[1], extended_input, key.EvalAList[2],
                    key.EvalBList[2], key.EvalCList[2], peer);
                GroupElement bx = truncate(party_id, raw_bx, key.fixed_scale,
                                           key.EvalScaleTRKeyList[2]);
                output = ax_squared + bx +
                         GroupElement(lut_output[2].value, key.Bout);
            } else {
                GroupElement extended_input =
                    key.EvalExtendKeyList == NULL
                        ? input
                        : legacyRingExtend(party_id, input, random_mask.bitsize,
                                     key.EvalExtendKeyList[0]);
                GroupElement real_input = extended_input + random_mask;
                reconstruct(&real_input);
                output = lut_output[0] * real_input * real_input +
                         lut_output[1] * real_input + lut_output[2];
            }
            break;
        }
        default:
            std::cout << "[ERROR] Unsupported approx degree!" << std::endl;
            std::exit(-1);
    }
    return output;
}

SplinePolyApproxKeyPack splinePolyApproxOfflineLegacyNoOnlineBeaver(
    int party_id, int Bin, int Bout, const GroupElement* public_coefficients,
    int degree, int seg_num, int fixed_scale) {
    if (fixed_scale == 0) {
        return splinePolyApproxOffline(party_id, Bin, Bout,
                                       public_coefficients, degree, seg_num,
                                       fixed_scale);
    }
    if (degree != 2) {
        std::cout << "[ERROR] Unsupported approx degree!" << std::endl;
        std::exit(-1);
    }

    SplinePolyApproxKeyPack output;
    output.Bin = Bin;
    output.Bout = Bout;
    output.degNum = degree;
    output.segNum = seg_num;
    output.fixed_scale = fixed_scale;
    output.EvalSignKeyList = NULL;
    output.EvalExtendKeyList = NULL;
    output.EvalScaleTRKeyList = NULL;
    output.EvalAList = NULL;
    output.EvalBList = NULL;
    output.EvalCList = NULL;

    output.coefficientList = makeKeyArray<GroupElement>(3 * seg_num);
    GroupElement* coefficient_list = output.coefficientList.data();
    auto rng = secure_prng();
    GroupElement random_mask = random_ge_from_prng(rng, Bin);

    const int product_bits = Bout + fixed_scale;
    GroupElement r_extended =
        zeroExtendSharedValue(party_id, random_mask, product_bits);
    GroupElement rr_a(0, product_bits), rr_b(0, product_bits);
    GroupElement rr_c(0, product_bits);
    beaver_mult_offline(party_id, &rr_a, &rr_b, &rr_c, peer, 1);
    GroupElement rr_raw =
        beaver_mult_online(party_id, r_extended, r_extended, rr_a, rr_b,
                           rr_c, peer);
    LegacyTRKeyPack rr_tr_key =
        truncateOffline(party_id, product_bits, fixed_scale);
    GroupElement r_squared =
        truncate(party_id, rr_raw, fixed_scale, rr_tr_key);
    GroupElement r_squared_extended =
        zeroExtendSharedValue(party_id, r_squared, product_bits);

    for (int i = 0; i < seg_num; i++) {
        GroupElement public_a(public_coefficients[i].value, Bout);
        GroupElement public_b(public_coefficients[seg_num + i].value, Bout);
        GroupElement public_c(public_coefficients[2 * seg_num + i].value,
                              Bout);
        GroupElement public_a_extended =
            signExtendPublicValue(public_a, product_bits);
        GroupElement public_b_extended =
            signExtendPublicValue(public_b, product_bits);

        LegacyTRKeyPack ar_tr_key =
            truncateOffline(party_id, product_bits, fixed_scale);
        LegacyTRKeyPack br_tr_key =
            truncateOffline(party_id, product_bits, fixed_scale);
        LegacyTRKeyPack ar2_tr_key =
            truncateOffline(party_id, product_bits, fixed_scale);
        GroupElement ar = truncate(
            party_id, r_extended * public_a_extended, fixed_scale, ar_tr_key);
        GroupElement br = truncate(
            party_id, r_extended * public_b_extended, fixed_scale, br_tr_key);
        GroupElement ar2 = truncate(
            party_id, r_squared_extended * public_a_extended, fixed_scale,
            ar2_tr_key);

        coefficient_list[i] = public_a * (uint64_t)(party_id - 2);
        coefficient_list[seg_num + i] =
            public_b * (uint64_t)(party_id - 2) - ar * 2;
        coefficient_list[2 * seg_num + i] =
            public_c * (uint64_t)(party_id - 2) + ar2 - br;
    }

    output.EvalSignKeyList = makeKeyArray<::LegacyComparisonKeyPack>(degree);
    output.EvalScaleTRKeyList = makeKeyArray<LegacyTRKeyPack>(degree);
    for (int i = 0; i < degree; i++) {
        output.EvalSignKeyList[i] =
            signExtendOffline(party_id, Bout, product_bits);
        output.EvalScaleTRKeyList[i] =
            truncateOffline(party_id, product_bits, fixed_scale);
    }

    output.random_mask = random_mask;
    const int truncation_bits = Bin - log2floor(seg_num);
    output.TRKey = truncateOffline(party_id, Bin, truncation_bits);
    output.PriLUTKeyList = makeKeyArray<LegacyPrivateLutKey>(degree + 1);
    for (int i = 0; i < degree + 1; i++) {
        output.PriLUTKeyList[i] = privateLutOffline(
            party_id, log2ceil(seg_num), Bout,
            &(coefficient_list[i * seg_num]));
    }
    return output;
}

GroupElement splinePolyApproxLegacyNoOnlineBeaver(
    int party_id, GroupElement input, const SplinePolyApproxKeyPack& key) {
    if (key.fixed_scale == 0) {
        return splinePolyApprox(party_id, input, key);
    }
    if (key.degNum != 2) {
        std::cout << "[ERROR] Unsupported approx degree!" << std::endl;
        std::exit(-1);
    }

    const int product_bits = key.Bout + key.fixed_scale;
    GroupElement truncated_input = truncate(
        party_id, input, input.bitsize - log2floor(key.segNum), key.TRKey);
    GroupElement lut_output[3];
    for (int i = 0; i < 3; i++) {
        lut_output[i] =
            privateLut(party_id, truncated_input, key.PriLUTKeyList[i]);
    }

    GroupElement extended_input =
        zeroExtendSharedValue(party_id, input, key.random_mask.bitsize);
    GroupElement real_input = extended_input + key.random_mask;
    reconstruct(&real_input);
    GroupElement real_input_base(real_input.value, key.Bout);
    GroupElement real_input_squared =
        scale_mult(real_input_base, real_input_base, key.fixed_scale);
    GroupElement real_input_extended =
        zeroExtendPublicValue(real_input_base, product_bits);
    GroupElement real_input_squared_extended =
        zeroExtendPublicValue(real_input_squared, product_bits);

    GroupElement coefficient_a = signExtendWithKey(
        party_id, lut_output[0], product_bits, key.EvalSignKeyList[0]);
    GroupElement coefficient_b = signExtendWithKey(
        party_id, lut_output[1], product_bits, key.EvalSignKeyList[1]);

    GroupElement az = truncate(
        party_id, coefficient_a * real_input_squared_extended,
        key.fixed_scale, key.EvalScaleTRKeyList[0]);
    GroupElement bz = truncate(
        party_id, coefficient_b * real_input_extended, key.fixed_scale,
        key.EvalScaleTRKeyList[1]);
    return az + bz + lut_output[2];
}

}  // namespace dfss::legacy
