#pragma once

#include <vector>

#include "commons/types.h"
#include "commons/group_element.h"
#include "commons/keypack.h"

// Correlated-GGM helpers for correlated DPF variants will be moved here from
// legacy DPF code during the staged refactor.
namespace dfss::internal {

struct CorrelatedTreeMaterial {
    int Bin = 0;
    int Bout = 0;
    KeyArray<osuCrypto::block> scw;
    KeyArray<BooleanElement> tau;
    osuCrypto::block leaf_xor = osuCrypto::ZeroBlock;
    GroupElement converted_sum;
    uint64_t control_bit_sum = 0;
};

CorrelatedTreeMaterial generateCorrelatedTree(
    int party_id, int Bin, int Bout, const BooleanElement* bits,
    const char* caller, bool computeArithmeticSums);

osuCrypto::block evalCorrelatedDPFLeaf(const BooleanElement* opened_bits,
                                       const DPFKeyPack& key,
                                       BooleanElement* controlBitOut = nullptr);

osuCrypto::block evalCorrelatedDPFLeaf(
    const BooleanElement* opened_bits, const BooleanDPFKeyPack& key,
    BooleanElement* controlBitOut = nullptr);

}  // namespace dfss::internal
