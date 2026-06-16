#pragma once

#include "buildingblock/lut.h"
#include "commons/types.h"
#include "commons/keypack.h"
#include "commons/public_data.h"

namespace dfss {

using LutEvalKeyPack = PublicLutKeyPack;

LutEvalKeyPack lutEvalOffline(int party_id, const PublicLUTData& table,
                              int suffix_bits = -1,
                              int lambda_bits = 128);

GroupElement lutEval(int party_id, GroupElement input,
                     const PublicLUTData& table,
                     const LutEvalKeyPack& key);

}  // namespace dfss
