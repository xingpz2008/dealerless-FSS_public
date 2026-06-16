#pragma once

#include "commons/group_element.h"
#include "commons/keypack.h"
#include "commons/types.h"

namespace dfss {

EqualityKey equalityOffline(int party_id, GroupElement point,
                            GroupElement payload, bool masked = true);
EqualityKey equalityOffline(int party_id, int Bin,
                            const BooleanElement* point_bits,
                            GroupElement payload, bool masked = true);

EqualityKey equalityBitOffline(int party_id, GroupElement point,
                               bool masked = true);
EqualityKey equalityBitOffline(int party_id, int Bin,
                               const BooleanElement* point_bits,
                               bool masked = true);

EqualityBlockKey equalityBlockOffline(int party_id, GroupElement point,
                                      block payload, bool masked = true);
EqualityBlockKey equalityBlockOffline(int party_id, int Bin,
                                      const BooleanElement* point_bits,
                                      block payload, bool masked = true);

GroupElement equality(int party_id, GroupElement input,
                      const EqualityKey& key, bool masked = true);
GroupElement equality(int party_id, const BooleanElement* input_bits,
                      const EqualityKey& key, bool masked = true);
void equality(int party_id, GroupElement* output, GroupElement input,
              const EqualityKey& key, bool masked = true);
void equality(int party_id, GroupElement* output,
              const BooleanElement* input_bits, const EqualityKey& key,
              bool masked = true);

BooleanElement equalityBit(int party_id, GroupElement input,
                           const EqualityKey& key, bool masked = true);
BooleanElement equalityBit(int party_id, const BooleanElement* input_bits,
                           const EqualityKey& key, bool masked = true);

block equalityBlock(int party_id, GroupElement input,
                    const EqualityBlockKey& key, bool masked = true);
block equalityBlock(int party_id, const BooleanElement* input_bits,
                    const EqualityBlockKey& key, bool masked = true);
void equalityBlock(int party_id, block* output, GroupElement input,
                   const EqualityBlockKey& key, bool masked = true);
void equalityBlock(int party_id, block* output,
                   const BooleanElement* input_bits,
                   const EqualityBlockKey& key, bool masked = true);

}  // namespace dfss
