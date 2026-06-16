#pragma once

#include "commons/types.h"
#include "commons/keypack.h"

namespace dfss {

ModularKeyPack modularOffline(int party_id, GroupElement modulus, int Bout);

GroupElement modular(int party_id, GroupElement input, int modulus,
                     const ModularKeyPack& key);

}  // namespace dfss
