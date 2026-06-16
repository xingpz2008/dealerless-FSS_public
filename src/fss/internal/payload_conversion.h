#pragma once

#include <cstdint>
#include <vector>

#include <cryptoTools/Common/Defines.h>

#include "commons/group_element.h"

// FSS payload-conversion helpers, including arithmetic conversion, XOR/block
// conversion, and second-LSB selection, will be moved here.
namespace dfss::internal {

osuCrypto::u8 dpfPayloadChoiceBit(int party_id, uint64_t controlBitSum,
                                  int bitIndex);

void convertBlockToWords(int bitsize, int groupSize,
                         const osuCrypto::block& seed, uint64_t* output);
void convertBlockToWordAndSeed(int bitsize, const osuCrypto::block& seed,
                               uint64_t* output, osuCrypto::block* outputSeed);
uint64_t convertPayload_iDPF(int bitsize, const osuCrypto::block& label);

GroupElement convertBlockToGroup(int bitsize, const osuCrypto::block& seed);
GroupElement convertRawBlockToGroup(int bitsize,
                                    const osuCrypto::block& seed);
std::vector<GroupElement> convertBlockToGroupVector(
    int bitsize, int vectorSize, const osuCrypto::block& seed);
void addConvertedBlockVectorToSums(int bitsize, int vectorSize,
                                   const osuCrypto::block& seed,
                                   std::vector<uint64_t>& scratch,
                                   std::vector<GroupElement>& sums);

}  // namespace dfss::internal
