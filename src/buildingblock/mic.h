#pragma once

#include "commons/types.h"
#include "commons/keypack.h"

namespace dfss {

MICKeyPack micOffline(int party_id, int Bin, int Bout, GroupElement payload);

void mic(int party_id, GroupElement input, const PublicInterval* intervals,
         int interval_count, GroupElement* output, const MICKeyPack& key);

MICBooleanKeyPack micBooleanOffline(int party_id, int Bin);

void micBoolean(int party_id, GroupElement input,
                const PublicInterval* intervals, int interval_count,
                BooleanElement* output, const MICBooleanKeyPack& key);

}  // namespace dfss
