#pragma once

#include "commons/types.h"
#include "legacy/keypack.h"

namespace dfss::legacy {

SplinePolyApproxKeyPack splinePolyApproxOffline(
    int party_id, int Bin, int Bout, const GroupElement* public_coefficients,
    int degree, int seg_num, int fixed_scale = 0);

GroupElement splinePolyApprox(int party_id, GroupElement input,
                              const SplinePolyApproxKeyPack& key);

SplinePolyApproxKeyPack splinePolyApproxOfflineLegacyNoOnlineBeaver(
    int party_id, int Bin, int Bout, const GroupElement* public_coefficients,
    int degree, int seg_num, int fixed_scale = 0);

GroupElement splinePolyApproxLegacyNoOnlineBeaver(
    int party_id, GroupElement input, const SplinePolyApproxKeyPack& key);

}  // namespace dfss::legacy
