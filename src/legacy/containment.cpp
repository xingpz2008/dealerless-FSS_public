#include "legacy/containment.h"

#include <cassert>
#include <vector>

#include "mpc/secure_ops.h"
#include "legacy/comparison.h"

namespace dfss::legacy {

ContainmentKeyPack containmentOffline(int party_id, int Bout,
                                      const GroupElement* knots_list,
                                      int knots_size) {
    ContainmentKeyPack output;
    output.Bin = knots_list[0].bitsize;
    output.Bout = Bout;
    const int mult_count = knots_size - 1;
    if (mult_count > 0) {
        output.AList = makeKeyArray<GroupElement>(mult_count);
        output.BList = makeKeyArray<GroupElement>(mult_count);
        output.CList = makeKeyArray<GroupElement>(mult_count);
    }
    output.ComparisonKeyList = makeKeyArray<LegacyComparisonKeyPack>(knots_size);
    output.CtnNum = knots_size;
    for (int i = 0; i < mult_count; i++) {
        output.AList[i].bitsize = output.Bout;
        output.BList[i].bitsize = output.Bout;
        output.CList[i].bitsize = output.Bout;
    }
    if (mult_count > 0) {
        beaver_mult_offline(party_id, output.AList, output.BList,
                            output.CList, peer, mult_count);
    }
    GroupElement one((uint64_t)(party_id - 2), output.Bout);
    for (int i = 0; i < knots_size; i++) {
        output.ComparisonKeyList[i] =
            legacyComparisonOffline(party_id, output.Bin, output.Bout,
                                    knots_list[i], one);
    }
    return output;
}

ContainmentKeyPack containmentOfflinePublic(int party_id, int Bout,
                                            const GroupElement* knots_list,
                                            int knots_size) {
    std::vector<GroupElement> shared_knots(knots_size);
    for (int i = 0; i < knots_size; i++) {
        shared_knots[i] = knots_list[i] * (uint64_t)(party_id - 2);
    }
    return containmentOffline(party_id, Bout, shared_knots.data(), knots_size);
}

void containment(int party_id, GroupElement input, GroupElement* output,
                 int knots_size, const ContainmentKeyPack& key) {
    assert(knots_size == key.CtnNum);
    assert(knots_size > 0);
    std::vector<GroupElement> input_array(knots_size);
    std::vector<GroupElement> comparison_output(knots_size);

    for (int i = 0; i < knots_size + 1; i++) {
        output[i] = GroupElement(0, key.Bout);
    }
    for (int i = 0; i < knots_size; i++) {
        input_array[i] = input;
        comparison_output[i].bitsize = key.Bout;
    }

    legacyComparison(party_id, comparison_output.data(), input_array.data(),
                     key.ComparisonKeyList, knots_size, input.bitsize);

    output[0] = comparison_output[0];
    const int mult_count = knots_size - 1;
    std::vector<GroupElement> mult_lhs(mult_count);
    std::vector<GroupElement> mult_rhs(mult_count);
    for (int i = 0; i < mult_count; i++) {
        mult_lhs[i] = comparison_output[i + 1];
        mult_rhs[i] =
            comparison_output[i] * -1 + (uint64_t)(party_id - 2);
    }
    if (mult_count > 0) {
        beaver_mult_online(party_id, mult_lhs.data(), mult_rhs.data(),
                           key.AList, key.BList, key.CList, &(output[1]),
                           mult_count, peer);
    }
    output[knots_size] =
        GroupElement((uint64_t)(party_id - 2), key.Bout) -
        comparison_output[knots_size - 1];
}

}  // namespace dfss::legacy
