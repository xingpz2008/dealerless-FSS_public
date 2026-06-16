#include "fss/internal/payload_conversion.h"

#include <cstring>
#include <stdexcept>
#include <vector>

#include <cryptoTools/Crypto/AES.h>

#include "mpc/comms.h"
#include "fss/internal/ggm.h"

namespace dfss::internal {

namespace {

int byteSize(int bitsize) {
    return (bitsize % 8) == 0 ? bitsize / 8 : (bitsize / 8) + 1;
}

uint64_t loadLittleEndianWord(const uint8_t* bytes, int byte_count) {
    if (byte_count <= 0 || byte_count > 8) {
        throw std::invalid_argument("invalid word byte count");
    }
    uint64_t value = 0;
    std::memcpy(&value, bytes, static_cast<std::size_t>(byte_count));
    return value;
}

}  // namespace

osuCrypto::u8 dpfPayloadChoiceBit(int party_id, uint64_t controlBitSum,
                                  int bitIndex) {
    const uint64_t localSignedSum =
        (party_id == SERVER) ? controlBitSum : (uint64_t(0) - controlBitSum);
    return static_cast<osuCrypto::u8>((localSignedSum >> bitIndex) & 1);
}

void convertBlockToWords(int bitsize, int groupSize,
                         const osuCrypto::block& seed, uint64_t* output) {
    const int bys = byteSize(bitsize);
    const int totalBys = bys * groupSize;
    if (totalBys <= 16) {
        const uint8_t* bptr = reinterpret_cast<const uint8_t*>(&seed);
        for (int i = 0; i < groupSize; i++) {
            output[i] = loadLittleEndianWord(bptr + i * bys, bys);
        }
        return;
    }

    const int numblocks =
        (totalBys % 16 == 0) ? totalBys / 16 : (totalBys / 16) + 1;
    osuCrypto::AES aes(seed);
    std::vector<osuCrypto::block> pt(numblocks);
    std::vector<osuCrypto::block> ct(numblocks);
    for (int i = 0; i < numblocks; i++) {
        pt[i] = osuCrypto::toBlock(0, i);
    }
    aes.ecbEncBlocks(pt.data(), numblocks, ct.data());
    uint8_t* bptr = reinterpret_cast<uint8_t*>(ct.data());
    for (int i = 0; i < groupSize; i++) {
        output[i] = loadLittleEndianWord(bptr + i * bys, bys);
    }
}

void convertBlockToWordAndSeed(int bitsize, const osuCrypto::block& seed,
                               uint64_t* output,
                               osuCrypto::block* outputSeed) {
    const int bys = byteSize(bitsize);
    const int numblocks = (bys % 16 == 0) ? bys / 16 : (bys / 16) + 1;
    osuCrypto::AES aes(seed);
    if (numblocks == 1) {
        osuCrypto::block pt[1] = {osuCrypto::toBlock(0, 0)};
        osuCrypto::block ct[1];
        aes.ecbEncBlocks(pt, 1, ct);
        uint8_t* bptr = reinterpret_cast<uint8_t*>(ct);
        *output = loadLittleEndianWord(bptr, bys);
        *outputSeed = ct[0];
        return;
    }

    std::vector<osuCrypto::block> pt(numblocks);
    std::vector<osuCrypto::block> ct(numblocks);
    for (int i = 0; i < numblocks; i++) {
        pt[i] = osuCrypto::toBlock(0, i);
    }
    aes.ecbEncBlocks(pt.data(), numblocks, ct.data());
    uint8_t* bptr = reinterpret_cast<uint8_t*>(ct.data());
    *output = loadLittleEndianWord(bptr, bys);
    *outputSeed = ct[0];
}

uint64_t convertPayload_iDPF(int bitsize, const osuCrypto::block& label) {
    uint64_t converted = 0;
    const osuCrypto::block payload_seed =
        ccrHash(label ^ osuCrypto::toBlock(0, 2));
    convertBlockToWords(bitsize, 1, payload_seed, &converted);
    return converted;
}

GroupElement convertBlockToGroup(int bitsize, const osuCrypto::block& seed) {
    uint64_t converted = 0;
    const osuCrypto::block seed_only = clearBlockLsb(seed);
    convertBlockToWords(bitsize, 1, seed_only, &converted);
    return GroupElement(converted, bitsize);
}

GroupElement convertRawBlockToGroup(int bitsize,
                                    const osuCrypto::block& seed) {
    uint64_t converted = 0;
    convertBlockToWords(bitsize, 1, seed, &converted);
    return GroupElement(converted, bitsize);
}

std::vector<GroupElement> convertBlockToGroupVector(
    int bitsize, int vectorSize, const osuCrypto::block& seed) {
    std::vector<uint64_t> converted(vectorSize, 0);
    convertBlockToWords(bitsize, vectorSize, seed, converted.data());
    std::vector<GroupElement> output(vectorSize);
    for (int i = 0; i < vectorSize; i++) {
        output[i] = GroupElement(converted[i], bitsize);
    }
    return output;
}

void addConvertedBlockVectorToSums(int bitsize, int vectorSize,
                                   const osuCrypto::block& seed,
                                   std::vector<uint64_t>& scratch,
                                   std::vector<GroupElement>& sums) {
    if (static_cast<int>(scratch.size()) < vectorSize ||
        static_cast<int>(sums.size()) < vectorSize) {
        throw std::invalid_argument("converted-vector scratch is too small");
    }
    convertBlockToWords(bitsize, vectorSize, seed, scratch.data());
    for (int i = 0; i < vectorSize; i++) {
        sums[i] = sums[i] + GroupElement(scratch[i], bitsize);
    }
}

}  // namespace dfss::internal
