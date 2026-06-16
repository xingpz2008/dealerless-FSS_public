#include "buildingblock/digit_decomposition.h"

#include <cassert>
#include <vector>

#include "mpc/secure_ops.h"
#include "buildingblock/comparison.h"
#include "fss/fss_wrapper.h"

namespace dfss {

DigDecKeyPack digdecOffline(int party_id, int Bin, int new_bit_size) {
    DigDecKeyPack output;
    int seg_num = Bin / new_bit_size + ((Bin % new_bit_size == 0) ? 0 : 1);
    output.Bin = Bin;
    output.NewBitSize = new_bit_size;
    output.SegNum = seg_num;
    output.ComparisonKeyList = makeKeyArray<ComparisonKeyPack>(seg_num - 1);
    output.DPFKeyList = makeKeyArray<DPFKeyPack>(seg_num - 1);

    GroupElement two_power_s_minus_one(
        (uint64_t)(party_id - 2) * ((1ULL << new_bit_size) - 1),
        new_bit_size);
    GroupElement one((uint64_t)(party_id - 2), new_bit_size);
    GroupElement two_power_s(
        (uint64_t)(party_id - 2) * (1ULL << new_bit_size),
        new_bit_size + 1);
    GroupElement one_for_comparison((uint64_t)(party_id - 2), new_bit_size);
    for (int i = 0; i < seg_num - 1; i++) {
        output.DPFKeyList[i] = wrapper::keyGenDPF(
            party_id, two_power_s_minus_one, one);
        output.ComparisonKeyList[i] = comparisonOffline(
            party_id, new_bit_size + 1, new_bit_size, two_power_s,
            one_for_comparison);
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
            int new_bit_size, const DigDecKeyPack& key) {
    assert(new_bit_size == key.NewBitSize);
    int seg_num = key.SegNum;
    std::vector<GroupElement> parsed_input(seg_num);
    std::vector<GroupElement> w(seg_num);
    std::vector<GroupElement> e(seg_num);
    std::vector<GroupElement> u(seg_num - 1);
    std::vector<GroupElement> v(seg_num - 1);

    const DPFKeyPack* dpf_key_list = key.DPFKeyList;
    const GroupElement* a_list = key.AList;
    const GroupElement* b_list = key.BList;
    const GroupElement* c_list = key.CList;

    for (int i = 0; i < seg_num; i++) {
        parsed_input[i] = input >> (new_bit_size * i);
        parsed_input[i].value =
            parsed_input[i].value & ((uint64_t(1) << new_bit_size) - 1);
        parsed_input[i].bitsize = new_bit_size;
        w[i].bitsize = new_bit_size;
        e[i].bitsize = new_bit_size;
    }

    std::vector<GroupElement> equality_input(seg_num - 1);
    for (int i = 0; i < seg_num - 1; i++) {
        equality_input[i] = parsed_input[i];
    }
    for (int i = 0; i < seg_num - 1; i++) {
        e[i] = wrapper::evalDPF(party_id, equality_input[i], dpf_key_list[i]);
    }

    for (int i = 0; i < seg_num; i++) {
        parsed_input[i].bitsize = new_bit_size + 1;
    }
    comparison(party_id, w.data(), parsed_input.data(), key.ComparisonKeyList,
               seg_num - 1, new_bit_size + 1);
    for (int i = 0; i < seg_num - 1; i++) {
        w[i] = GroupElement((uint64_t)(party_id - 2), new_bit_size) - w[i];
    }

    for (int i = 0; i < seg_num; i++) {
        parsed_input[i].bitsize = new_bit_size;
    }

    // Propagate carries between digits with one arithmetic multiplication per
    // lower digit.
    u[0] = GroupElement(0, new_bit_size);
    output[0] = parsed_input[0];
    for (int i = 0; i < seg_num - 1; i++) {
        u[i].bitsize = new_bit_size;
        v[i].bitsize = new_bit_size;
        v[i] = beaver_mult_online(party_id, u[i], e[i], a_list[i], b_list[i],
                                  c_list[i], peer);
        output[i + 1] = parsed_input[i + 1] + v[i] + w[i];
        if (i + 1 < seg_num - 1) {
            u[i + 1] = v[i] + w[i];
        }
    }
}

}  // namespace dfss
