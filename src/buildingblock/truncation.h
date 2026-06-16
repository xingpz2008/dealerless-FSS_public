#pragma once

#include "commons/types.h"
#include "commons/keypack.h"

namespace dfss {

TRKeyPack truncateOffline(int party_id, int l, int s);

GroupElement truncate(int party_id, GroupElement input, int s,
                      const TRKeyPack& key);

SignedTruncateKeyPack signedTruncateOffline(int party_id, int l, int s);

GroupElement signedTruncate(int party_id, GroupElement input, int s,
                               const SignedTruncateKeyPack& key);

}  // namespace dfss
