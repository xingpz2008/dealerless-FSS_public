#pragma once

#include "commons/keypack.h"
#include "commons/types.h"

namespace dfss {

ComparisonKeyPack comparisonOffline(int party_id, int Bin, int Bout,
                                    GroupElement payload);
ComparisonKeyPack comparisonOffline(int party_id, int Bin, int Bout,
                                    GroupElement threshold_share,
                                    GroupElement payload);

ComparisonBitKeyPack comparisonBitOffline(int party_id, int Bin);
ComparisonBitKeyPack comparisonBitOffline(int party_id, int Bin,
                                          GroupElement threshold_share);

GroupElement comparison(int party_id, GroupElement input, uint64_t threshold,
                        const ComparisonKeyPack& key);
GroupElement comparison(int party_id, GroupElement input,
                        const ComparisonKeyPack& key);
void comparison(int party_id, GroupElement* output, GroupElement input,
                uint64_t threshold, const ComparisonKeyPack& key);
void comparison(int party_id, GroupElement* output, GroupElement input,
                const ComparisonKeyPack& key);
void comparison(int party_id, GroupElement* output, const GroupElement* input,
                const ComparisonKeyPack* key_list, int size,
                int max_bitsize);

BooleanElement comparisonBit(int party_id, GroupElement input,
                             uint64_t threshold,
                             const ComparisonBitKeyPack& key);
BooleanElement comparisonBit(int party_id, GroupElement input,
                             const ComparisonBitKeyPack& key);

ComparisonKeyPack ringExtendOffline(int party_id, int input_bits,
                                    int output_bits);

GroupElement ringExtend(int party_id, GroupElement input, int output_bits,
                        const ComparisonKeyPack& key);

}  // namespace dfss
