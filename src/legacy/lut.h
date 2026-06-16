#pragma once

#include "legacy/keypack.h"
#include "commons/types.h"

namespace dfss::legacy {

LegacyPublicLutKeyPack publicLutOffline(int party_id, int idx_bitlen,
                                        int lut_bitlen);

GroupElement publicLut(int party_id, GroupElement input,
                       const GroupElement* table,
                       GroupElement* shifted_full_domain_res, int table_size,
                       int output_bitlen,
                       const LegacyPublicLutKeyPack& key);

}  // namespace dfss::legacy
