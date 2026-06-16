#pragma once

#include "commons/types.h"
#include "commons/keypack.h"
#include "commons/public_data.h"

namespace dfss {

struct PublicLutOptions {
    bool early_termination = true;
    int suffix_bits = -1;
    int lambda_bits = 128;
};

PublicLutKeyPack publicLutOffline(int party_id, const PublicLUTData& table,
                                  PublicLutOptions options = {});

PublicLutKeyPack publicLutOffline(int party_id, int idx_bitlen,
                                  int output_bitlen,
                                  PublicLutOptions options = {});

GroupElement publicLut(int party_id, GroupElement input,
                       const PublicLUTData& table,
                       const PublicLutKeyPack& key,
                       GroupElement* shifted_full_domain_res = nullptr);

PrivateLutKey privateLutOffline(int party_id, int idx_bitlen, int lut_bitlen,
                                const GroupElement* private_list);

GroupElement privateLut(int party_id, GroupElement idx,
                        const PrivateLutKey& key);

}  // namespace dfss
