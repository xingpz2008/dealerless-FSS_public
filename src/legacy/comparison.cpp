#include "legacy/comparison.h"

#include <array>
#include <cassert>
#include <vector>

#include "legacy/dcf.h"
#include "mpc/secure_ops.h"
#include "mpc/api.h"

namespace {

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

GroupElement overflowOnAddition(int party_id, GroupElement lhs,
                                GroupElement rhs, int output_bits) {
    assert(lhs.bitsize == rhs.bitsize);
    GroupElement sum = lhs + rhs;
    u8 wrap_bits[] = {
        wrapOfSharedValue(party_id, sum),
        wrapOfSharedValue(party_id, lhs),
        wrapOfSharedValue(party_id, rhs),
    };
    GroupElement arithmetic_wraps[] = {
        GroupElement(0, output_bits),
        GroupElement(0, output_bits),
        GroupElement(0, output_bits),
    };
    B2A(party_id, wrap_bits, arithmetic_wraps, 3, output_bits, peer);

    const __uint128_t local_sum =
        static_cast<__uint128_t>(lhs.value) +
        static_cast<__uint128_t>(rhs.value);
    const uint64_t local_carry = local_sum >> lhs.bitsize;
    return arithmetic_wraps[0] - arithmetic_wraps[1] - arithmetic_wraps[2] +
           GroupElement(local_carry, output_bits);
}

}  // namespace

namespace dfss::legacy {

::LegacyComparisonKeyPack legacyComparisonOffline(int party_id, int Bin, int Bout,
                                      GroupElement c,
                                      const GroupElement& payload,
                                      bool public_payload) {
    (void)public_payload;
    assert((Bin == c.bitsize) && (Bout == payload.bitsize));
    ::LegacyComparisonKeyPack key;
    key.Bin = c.bitsize;
    key.Bout = Bout;
    auto rng = secure_prng();
    GroupElement r = random_ge_from_prng(rng, c.bitsize);
    key.mask = r;

    GroupElement r_plus_c = r + c;
    GroupElement g = overflowOnAddition(party_id, r, c, Bout);
    GroupElement a(-1, Bout);
    GroupElement b(-1, Bout);
    GroupElement mult_c(-1, Bout);
    beaver_mult_offline(party_id, &a, &b, &mult_c, peer, 1);
    key.correction =
        beaver_mult_online(party_id, payload, g, a, b, mult_c, peer);

    key.DCFKeyList[0] = keyGenNewDCF(party_id, Bin, Bout, r, -payload);
    key.DCFKeyList[1] = keyGenNewDCF(party_id, Bin, Bout, r_plus_c, payload);
    return key;
}

::LegacyComparisonKeyPack legacyComparisonOffline(int party_id, int Bin, int Bout,
                                      GroupElement c,
                                      const GroupElement* payload,
                                      bool public_payload) {
    return legacyComparisonOffline(party_id, Bin, Bout, c, *payload, public_payload);
}

void legacyComparison(int party_id, GroupElement* res, GroupElement idx,
                const ::LegacyComparisonKeyPack& key) {
    *res = legacyComparison(party_id, idx, key);
}

GroupElement legacyComparison(int party_id, GroupElement idx,
                        const ::LegacyComparisonKeyPack& key) {
    GroupElement real_idx = idx + key.mask;
    reconstruct(&real_idx);
    std::array<GroupElement, 2> y;
    GroupElement eval_idx[2] = {real_idx, real_idx};
    for (int i = 0; i < 2; i++) {
        y[i].bitsize = key.Bout;
    }

    evalNewDCF(party_id, y.data(), eval_idx, key.DCFKeyList.data(), 2,
               key.Bin);
    return y[0] + y[1] + key.correction;
}

void legacyComparison(int party_id, GroupElement* res, const GroupElement* idx,
                const ::LegacyComparisonKeyPack* key_list, int size,
                int max_bitsize) {
    std::vector<GroupElement> real_idx(size);
    std::vector<GroupElement> eval_idx(2 * size);
    std::vector<GroupElement> y(2 * size);
    std::vector<newDCFKeyPack> unified_key_list(2 * size);
    for (int i = 0; i < size; i++) {
        real_idx[i] = idx[i] + key_list[i].mask;
        y[2 * i].bitsize = key_list[i].Bout;
        y[2 * i + 1].bitsize = key_list[i].Bout;
        unified_key_list[2 * i] = key_list[i].DCFKeyList[0];
        unified_key_list[2 * i + 1] = key_list[i].DCFKeyList[1];
    }
    reconstruct(size, real_idx.data(), max_bitsize);
    for (int i = 0; i < size; i++) {
        eval_idx[2 * i] = real_idx[i];
        eval_idx[2 * i + 1] = real_idx[i];
    }

    evalNewDCF(party_id, y.data(), eval_idx.data(), unified_key_list.data(),
               2 * size, max_bitsize);

    for (int i = 0; i < size; i++) {
        res[i] = y[2 * i] + y[2 * i + 1] + key_list[i].correction;
    }
}

::LegacyComparisonKeyPack legacyRingExtendOffline(int party_id, int input_bits,
                                      int output_bits) {
    assert(output_bits >= input_bits);
    GroupElement threshold(
        (uint64_t)(party_id - 2) * (uint64_t(1) << input_bits),
        input_bits + 1);
    GroupElement one((uint64_t)(party_id - 2), output_bits);
    return legacyComparisonOffline(party_id, input_bits + 1, output_bits, threshold,
                             one, true);
}

GroupElement legacyRingExtend(int party_id, GroupElement input, int output_bits,
                        const ::LegacyComparisonKeyPack& key) {
    assert(output_bits >= input.bitsize);
    if (output_bits == input.bitsize) {
        return input;
    }

    GroupElement lifted_input(input.value, input.bitsize + 1);
    GroupElement is_below_threshold = legacyComparison(party_id, lifted_input, key);

    GroupElement one((uint64_t)(party_id - 2), output_bits);
    GroupElement carry = one - is_below_threshold;
    return GroupElement(input.value, output_bits) -
           carry * (uint64_t(1) << input.bitsize);
}

}  // namespace dfss::legacy
