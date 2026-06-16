#include "fss/internal/ggm.h"

#include <vector>

#include <cryptoTools/Crypto/AES.h>
#ifdef _OPENMP
#include <omp.h>
#endif

namespace dfss::internal {

namespace {

constexpr std::size_t kParallelPrgExpansionThreshold = 4096;
const osuCrypto::block kLsbMask = osuCrypto::OneBlock;
const osuCrypto::block kNotLsbMask =
    osuCrypto::toBlock(static_cast<osuCrypto::u64>(~0),
                       static_cast<osuCrypto::u64>(~1));

osuCrypto::u8 blockLsb(const osuCrypto::block& input) {
    return _mm_cvtsi128_si64x(input) & 1;
}

}  // namespace

osuCrypto::block setBlockLsb(osuCrypto::block input, osuCrypto::u8 bit) {
    if (blockLsb(input) != (bit & 1)) {
        input = input ^ kLsbMask;
    }
    return input;
}

osuCrypto::block clearBlockLsb(const osuCrypto::block& input) {
    return input & kNotLsbMask;
}

osuCrypto::block ccrHash(const osuCrypto::block& input) {
    return osuCrypto::mAesFixedKey.ecbEncBlock(input) ^ input;
}

void expandDpfPrgLevel(const osuCrypto::block* levelNodes,
                       osuCrypto::block* nextLevelNodes,
                       std::size_t expandNum,
                       osuCrypto::block& leftChildren,
                       osuCrypto::block& rightChildren) {
    const static osuCrypto::block pt[2] = {osuCrypto::ZeroBlock,
                                           osuCrypto::OneBlock};
    leftChildren = osuCrypto::ZeroBlock;
    rightChildren = osuCrypto::ZeroBlock;

#ifdef _OPENMP
    const int threadCount = omp_get_max_threads();
    if (expandNum >= kParallelPrgExpansionThreshold && threadCount > 1) {
        std::vector<osuCrypto::block> leftPartials(threadCount,
                                                   osuCrypto::ZeroBlock);
        std::vector<osuCrypto::block> rightPartials(threadCount,
                                                    osuCrypto::ZeroBlock);

#pragma omp parallel
        {
            const int tid = omp_get_thread_num();
            osuCrypto::AES aes;
            osuCrypto::block ct[2];
            osuCrypto::block localLeft = osuCrypto::ZeroBlock;
            osuCrypto::block localRight = osuCrypto::ZeroBlock;

#pragma omp for
            for (long long jj = 0;
                 jj < static_cast<long long>(expandNum); jj++) {
                const std::size_t j = static_cast<std::size_t>(jj);
                aes.setKey(levelNodes[j]);
                aes.ecbEncTwoBlocks(pt, ct);
                localLeft = localLeft ^ ct[0];
                localRight = localRight ^ ct[1];
                nextLevelNodes[2 * j] = ct[0];
                nextLevelNodes[2 * j + 1] = ct[1];
            }

            leftPartials[tid] = localLeft;
            rightPartials[tid] = localRight;
        }

        for (int tid = 0; tid < threadCount; tid++) {
            leftChildren = leftChildren ^ leftPartials[tid];
            rightChildren = rightChildren ^ rightPartials[tid];
        }
        return;
    }
#endif

    osuCrypto::AES aes;
    osuCrypto::block ct[2];
    for (std::size_t j = 0; j < expandNum; j++) {
        aes.setKey(levelNodes[j]);
        aes.ecbEncTwoBlocks(pt, ct);
        leftChildren = leftChildren ^ ct[0];
        rightChildren = rightChildren ^ ct[1];
        nextLevelNodes[2 * j] = ct[0];
        nextLevelNodes[2 * j + 1] = ct[1];
    }
}

void expandPdfGgmLevel(const osuCrypto::block* levelNodes,
                       osuCrypto::block* nextLevelNodes,
                       std::size_t expandNum,
                       osuCrypto::block& leftSeedXor,
                       osuCrypto::block& rightSeedXor,
                       osuCrypto::u8& leftControlXor,
                       osuCrypto::u8& rightControlXor) {
    const static osuCrypto::block pt[2] = {osuCrypto::ZeroBlock,
                                           osuCrypto::OneBlock};
    leftSeedXor = osuCrypto::ZeroBlock;
    rightSeedXor = osuCrypto::ZeroBlock;
    leftControlXor = 0;
    rightControlXor = 0;

    osuCrypto::AES aes;
    osuCrypto::block ct[2];
    for (std::size_t j = 0; j < expandNum; j++) {
        aes.setKey(clearBlockLsb(levelNodes[j]));
        aes.ecbEncTwoBlocks(pt, ct);
        nextLevelNodes[2 * j] = ct[0];
        nextLevelNodes[2 * j + 1] = ct[1];
        leftSeedXor = leftSeedXor ^ clearBlockLsb(ct[0]);
        rightSeedXor = rightSeedXor ^ clearBlockLsb(ct[1]);
        leftControlXor ^= blockLsb(ct[0]);
        rightControlXor ^= blockLsb(ct[1]);
    }
}

}  // namespace dfss::internal
