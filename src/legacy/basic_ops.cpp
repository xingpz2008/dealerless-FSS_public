#include "legacy/basic_ops.h"

#include <cassert>
#include <vector>

#include "legacy/dpf.h"
#include "legacy/comparison.h"
#include "mpc/secure_ops.h"

namespace dfss::legacy {

LegacyModularKeyPack modularOffline(int party_id, GroupElement modulus,
                                    int Bout) {
    LegacyModularKeyPack output;
    GroupElement one((uint64_t)(party_id - SERVER), Bout);
    GroupElement shared_modulus = modulus * (uint64_t)(party_id - SERVER);
    output.ComparisonKey = legacyComparisonOffline(
        party_id, modulus.bitsize, Bout, shared_modulus, one);
    output.Bin = modulus.bitsize;
    output.Bout = Bout;
    return output;
}

GroupElement modular(int party_id, GroupElement input, int modulus,
                     const LegacyModularKeyPack& key) {
    GroupElement comparison_res =
        legacyComparison(party_id, input, key.ComparisonKey);
    return input - (GroupElement(uint64_t(party_id - SERVER), input.bitsize) -
                    comparison_res) *
                       modulus;
}

LegacyTRKeyPack truncateOffline(int party_id, int l, int s) {
    LegacyTRKeyPack output;
    output.Bin = s;
    output.Bout = l - s;
    output.s = s;
    GroupElement threshold(
        (uint64_t)(party_id - SERVER) * (uint64_t(1) << s), s + 1);
    GroupElement one((uint64_t)(party_id - SERVER), output.Bout);
    output.ComparisonKey =
        legacyComparisonOffline(party_id, output.Bin + 1, output.Bout,
                                threshold, one);
    return output;
}

GroupElement truncate(int party_id, GroupElement input, int s,
                      const LegacyTRKeyPack& key) {
    assert(s == key.s);
    if (s == 0) {
        return input;
    }
    auto segmented = segment(input, s);
    segmented.second.bitsize = s + 1;
    GroupElement comparison_res =
        legacyComparison(party_id, segmented.second, key.ComparisonKey);
    GroupElement one((uint64_t)(party_id - SERVER), input.bitsize - s);
    GroupElement carry = one - comparison_res;
    return segmented.first + carry;
}

LegacyDigDecKeyPack digdecOffline(int party_id, int Bin, int new_bit_size) {
    LegacyDigDecKeyPack output;
    const int seg_num =
        Bin / new_bit_size + ((Bin % new_bit_size == 0) ? 0 : 1);
    output.Bin = Bin;
    output.NewBitSize = new_bit_size;
    output.SegNum = seg_num;
    output.ComparisonKeyList =
        makeKeyArray<LegacyComparisonKeyPack>(seg_num - 1);
    output.DPFKeyList = makeKeyArray<DPFKeyPack>(seg_num - 1);

    GroupElement max_digit_share(
        (uint64_t)(party_id - SERVER) * ((1ULL << new_bit_size) - 1),
        new_bit_size);
    GroupElement one((uint64_t)(party_id - SERVER), new_bit_size);
    GroupElement comparison_threshold(
        (uint64_t)(party_id - SERVER) * (uint64_t(1) << new_bit_size),
        new_bit_size + 1);
    for (int i = 0; i < seg_num - 1; i++) {
        output.DPFKeyList[i] = keyGenDPF(
            party_id, new_bit_size, new_bit_size, max_digit_share, one, true);
        output.ComparisonKeyList[i] = legacyComparisonOffline(
            party_id, new_bit_size + 1, new_bit_size, comparison_threshold,
            one);
    }

    output.AList = makeKeyArray<GroupElement>(seg_num - 1);
    output.BList = makeKeyArray<GroupElement>(seg_num - 1);
    output.CList = makeKeyArray<GroupElement>(seg_num - 1);
    for (int i = 0; i < seg_num - 1; i++) {
        output.AList[i].bitsize = new_bit_size;
        output.BList[i].bitsize = new_bit_size;
        output.CList[i].bitsize = new_bit_size;
    }
    beaver_mult_offline(party_id, output.AList, output.BList, output.CList,
                        peer, seg_num - 1);
    return output;
}

void digdec(int party_id, GroupElement input, GroupElement* output,
            int new_bit_size, const LegacyDigDecKeyPack& key) {
    assert(new_bit_size == key.NewBitSize);
    const int seg_num = key.SegNum;
    std::vector<GroupElement> parsed_input(seg_num);
    std::vector<GroupElement> w(seg_num);
    std::vector<GroupElement> e(seg_num);
    std::vector<GroupElement> u(seg_num - 1);
    std::vector<GroupElement> v(seg_num - 1);

    for (int i = 0; i < seg_num; i++) {
        parsed_input[i] = input >> (new_bit_size * i);
        parsed_input[i].value &= ((uint64_t(1) << new_bit_size) - 1);
        parsed_input[i].bitsize = new_bit_size;
        w[i].bitsize = new_bit_size;
        e[i].bitsize = new_bit_size;
    }

    std::vector<GroupElement> equality_input(seg_num - 1);
    for (int i = 0; i < seg_num - 1; i++) {
        equality_input[i] = parsed_input[i];
    }
    evalDPF(party_id, e.data(), equality_input.data(), key.DPFKeyList,
            seg_num - 1, new_bit_size);

    for (int i = 0; i < seg_num; i++) {
        parsed_input[i].bitsize = new_bit_size + 1;
    }
    legacyComparison(party_id, w.data(), parsed_input.data(),
                     key.ComparisonKeyList, seg_num - 1, new_bit_size + 1);
    for (int i = 0; i < seg_num - 1; i++) {
        w[i] = GroupElement((uint64_t)(party_id - SERVER), new_bit_size) -
               w[i];
    }
    for (int i = 0; i < seg_num; i++) {
        parsed_input[i].bitsize = new_bit_size;
    }

    u[0] = GroupElement(0, new_bit_size);
    output[0] = parsed_input[0];
    for (int i = 0; i < seg_num - 1; i++) {
        u[i].bitsize = new_bit_size;
        v[i].bitsize = new_bit_size;
        v[i] = beaver_mult_online(party_id, u[i], e[i], key.AList[i],
                                  key.BList[i], key.CList[i], peer);
        output[i + 1] = parsed_input[i + 1] + v[i] + w[i];
        if (i + 1 < seg_num - 1) {
            u[i + 1] = v[i] + w[i];
        }
    }
}

LegacyPrivateLutKey privateLutOffline(int party_id, int idx_bitlen,
                                      int lut_bitlen,
                                      const GroupElement* private_list) {
    LegacyPrivateLutKey output;
    const int entries = 1 << idx_bitlen;
    output.entryNum = entries;
    output.lut_bitlen = lut_bitlen;

    auto rng = secure_prng();
    GroupElement random_mask = random_ge_from_prng(rng, idx_bitlen);
    output.DPFKeyList = makeKeyArray<DPFKeyPack>(entries);
    for (int i = 0; i < entries; i++) {
        GroupElement target =
            random_mask +
            GroupElement(i * static_cast<uint64_t>(party_id - SERVER),
                         idx_bitlen);
        output.DPFKeyList[i] = keyGenDPF(
            party_id, idx_bitlen, lut_bitlen, target, private_list[i], false);
    }
    output.random_mask = random_mask;
    return output;
}

GroupElement privateLut(int party_id, GroupElement idx,
                        const LegacyPrivateLutKey& key) {
    GroupElement real_input = idx + key.random_mask;
    reconstruct(&real_input);

    GroupElement output(0, key.lut_bitlen);
    for (int i = 0; i < key.entryNum; i++) {
        output = output +
                 evalDPF(party_id, real_input, key.DPFKeyList[i], false);
    }
    return output;
}

}  // namespace dfss::legacy
