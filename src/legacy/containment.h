#pragma once

#include "commons/types.h"
#include "legacy/keypack.h"

namespace dfss::legacy {

ContainmentKeyPack containmentOffline(int party_id, int Bout,
                                      const GroupElement* knots_list,
                                      int knots_size);

ContainmentKeyPack containmentOfflinePublic(int party_id, int Bout,
                                            const GroupElement* knots_list,
                                            int knots_size);

void containment(int party_id, GroupElement input, GroupElement* output,
                 int knots_size, const ContainmentKeyPack& key);

}  // namespace dfss::legacy
