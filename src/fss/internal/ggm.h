#pragma once

#include <cryptoTools/Common/Defines.h>
#include <cstddef>

// Ordinary GGM helpers for FSS constructions will be moved here from
// legacy DPF code during the staged refactor.
namespace dfss::internal {

osuCrypto::block setBlockLsb(osuCrypto::block input, osuCrypto::u8 bit);
osuCrypto::block clearBlockLsb(const osuCrypto::block& input);
osuCrypto::block ccrHash(const osuCrypto::block& input);

void expandDpfPrgLevel(const osuCrypto::block* levelNodes,
                       osuCrypto::block* nextLevelNodes,
                       std::size_t expandNum,
                       osuCrypto::block& leftChildren,
                       osuCrypto::block& rightChildren);

void expandPdfGgmLevel(const osuCrypto::block* levelNodes,
                       osuCrypto::block* nextLevelNodes,
                       std::size_t expandNum,
                       osuCrypto::block& leftSeedXor,
                       osuCrypto::block& rightSeedXor,
                       osuCrypto::u8& leftControlXor,
                       osuCrypto::u8& rightControlXor);

}  // namespace dfss::internal
