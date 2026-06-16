#pragma once

#include "commons/types.h"
#include "commons/keypack.h"

namespace dfss {

DigDecKeyPack digdecOffline(int party_id, int Bin, int new_bit_size);

void digdec(int party_id, GroupElement input, GroupElement* output,
            int new_bit_size, const DigDecKeyPack& key);

}  // namespace dfss
