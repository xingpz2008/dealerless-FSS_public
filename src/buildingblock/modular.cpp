#include "buildingblock/modular.h"

#include "buildingblock/comparison.h"

namespace dfss {

ModularKeyPack modularOffline(int party_id, GroupElement modulus, int Bout) {
    ModularKeyPack output;
    GroupElement one((uint64_t)(party_id - 2), Bout);
    GroupElement shared_modulus = modulus * (uint64_t)(party_id - 2);
    output.ComparisonKey = comparisonOffline(
        party_id, modulus.bitsize, Bout, shared_modulus, one);
    output.Bin = modulus.bitsize;
    output.Bout = Bout;
    return output;
}

GroupElement modular(int party_id, GroupElement input, int modulus,
                     const ModularKeyPack& key) {
    GroupElement comparison_res = comparison(party_id, input, key.ComparisonKey);
    return input - (GroupElement(uint64_t(party_id - 2), input.bitsize) -
                    comparison_res) *
                       modulus;
}

}  // namespace dfss
