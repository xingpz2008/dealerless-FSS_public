#pragma once

#include "commons/types.h"
#include "commons/keypack.h"
#include "commons/public_data.h"

namespace dfss {

MICPolyEvalKeyPack micPolyEvalOffline(
    int party_id, const PublicPiecewisePolyData& poly);

GroupElement micPolyEval(int party_id, GroupElement input,
                         const PublicPiecewisePolyData& poly,
                         const MICPolyEvalKeyPack& key);

}  // namespace dfss
