#pragma once

#include "commons/types.h"
#include "legacy/keypack.h"

namespace dfss::legacy {

LegacyModularKeyPack modularOffline(int party_id, GroupElement modulus,
                                    int Bout);

GroupElement modular(int party_id, GroupElement input, int modulus,
                     const LegacyModularKeyPack& key);

LegacyTRKeyPack truncateOffline(int party_id, int l, int s);

GroupElement truncate(int party_id, GroupElement input, int s,
                      const LegacyTRKeyPack& key);

LegacyDigDecKeyPack digdecOffline(int party_id, int Bin, int new_bit_size);

void digdec(int party_id, GroupElement input, GroupElement* output,
            int new_bit_size, const LegacyDigDecKeyPack& key);

LegacyPrivateLutKey privateLutOffline(int party_id, int idx_bitlen,
                                      int lut_bitlen,
                                      const GroupElement* private_list);

GroupElement privateLut(int party_id, GroupElement idx,
                        const LegacyPrivateLutKey& key);

}  // namespace dfss::legacy
