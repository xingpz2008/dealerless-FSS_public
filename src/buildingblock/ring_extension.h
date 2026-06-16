#pragma once

#include "commons/types.h"
#include "commons/keypack.h"

namespace dfss {

SignedRingExtensionKeyPack signedRingExtendOffline(int party_id,
                                                   int input_bits,
                                                   int output_bits);

GroupElement signedRingExtend(int party_id, GroupElement input,
                                 int output_bits,
                                 const SignedRingExtensionKeyPack& key);

}  // namespace dfss
