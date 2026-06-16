#pragma once

#include "commons/types.h"
#include "legacy/keypack.h"

namespace dfss::legacy {

::LegacyComparisonKeyPack legacyComparisonOffline(int party_id, int Bin, int Bout,
                                      GroupElement c,
                                      const GroupElement& payload,
                                      bool public_payload = true);

::LegacyComparisonKeyPack legacyComparisonOffline(int party_id, int Bin, int Bout,
                                      GroupElement c,
                                      const GroupElement* payload,
                                      bool public_payload);

void legacyComparison(int party_id, GroupElement* res, GroupElement idx,
                const ::LegacyComparisonKeyPack& key);

GroupElement legacyComparison(int party_id, GroupElement idx,
                        const ::LegacyComparisonKeyPack& key);

void legacyComparison(int party_id, GroupElement* res, const GroupElement* idx,
                const ::LegacyComparisonKeyPack* key_list, int size,
                int max_bitsize);

::LegacyComparisonKeyPack legacyRingExtendOffline(int party_id, int input_bits,
                                      int output_bits);

GroupElement legacyRingExtend(int party_id, GroupElement input, int output_bits,
                        const ::LegacyComparisonKeyPack& key);

}  // namespace dfss::legacy
