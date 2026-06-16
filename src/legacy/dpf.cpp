/*
 * Description: Refer to README.md
 * Author: Pengzhi Xing
 * Email: p.xing@std.uestc.edu.cn
 * Last Modified: 2024-12-02
 * License: Apache-2.0 License
 * Copyright (c) 2024 Pengzhi Xing
 */
#include "legacy/dpf.h"

#include <cassert>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#ifdef _OPENMP
#include <omp.h>
#endif

using namespace osuCrypto;

namespace {

constexpr size_t kParallelPrgExpansionThreshold = 4096;
constexpr int kMaxFullTreeBits = 24;

int byteSize(const int bitsize) {
    return (bitsize % 8) == 0 ? bitsize / 8 : (bitsize / 8) + 1;
}

void ensureSupportedFullTreeBits(const int bits, const char* caller) {
    if (bits < 0 || bits > kMaxFullTreeBits) {
        throw std::invalid_argument(
            std::string(caller) + " requires 0 <= bit length <= " +
            std::to_string(kMaxFullTreeBits) +
            " in the current full-tree implementation");
    }
}

void expandDpfPrgLevel(const block* levelNodes, block* nextLevelNodes,
                       const size_t expandNum, block& leftChildren,
                       block& rightChildren) {
    const static block pt[2] = {ZeroBlock, OneBlock};
    leftChildren = ZeroBlock;
    rightChildren = ZeroBlock;

#ifdef _OPENMP
    const int threadCount = omp_get_max_threads();
    if (expandNum >= kParallelPrgExpansionThreshold && threadCount > 1) {
        std::vector<block> leftPartials(threadCount, ZeroBlock);
        std::vector<block> rightPartials(threadCount, ZeroBlock);

#pragma omp parallel
        {
            const int tid = omp_get_thread_num();
            AES aes;
            block ct[2];
            block localLeft = ZeroBlock;
            block localRight = ZeroBlock;

#pragma omp for
            for (long long jj = 0;
                 jj < static_cast<long long>(expandNum); jj++) {
                const size_t j = static_cast<size_t>(jj);
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

    AES aes;
    block ct[2];
    for (size_t j = 0; j < expandNum; j++) {
        aes.setKey(levelNodes[j]);
        aes.ecbEncTwoBlocks(pt, ct);
        leftChildren = leftChildren ^ ct[0];
        rightChildren = rightChildren ^ ct[1];
        nextLevelNodes[2 * j] = ct[0];
        nextLevelNodes[2 * j + 1] = ct[1];
    }
}

void convertBlockToWords(const int bitsize, const int groupSize,
                         const block& input, uint64_t* out) {
    const int bys = byteSize(bitsize);
    const int totalBys = bys * groupSize;
    if (totalBys <= 16) {
        const uint8_t* bptr = reinterpret_cast<const uint8_t*>(&input);
        for (int i = 0; i < groupSize; i++) {
            out[i] = *reinterpret_cast<const uint64_t*>(bptr + i * bys);
        }
        return;
    }

    const int blocksNeeded =
        (totalBys % 16 == 0) ? totalBys / 16 : (totalBys / 16) + 1;
    AES aes(input);
    std::vector<block> plaintext(blocksNeeded);
    std::vector<block> ciphertext(blocksNeeded);
    for (int i = 0; i < blocksNeeded; i++) {
        plaintext[i] = osuCrypto::toBlock(0, i);
    }
    aes.ecbEncBlocks(plaintext.data(), blocksNeeded, ciphertext.data());
    uint8_t* bptr = reinterpret_cast<uint8_t*>(ciphertext.data());
    for (int i = 0; i < groupSize; i++) {
        out[i] = *reinterpret_cast<uint64_t*>(bptr + i * bys);
    }
}

void convertBlockToWordAndSeed(const int bitsize, const block& input,
                               uint64_t* out, block* out_s) {
    const int bys = byteSize(bitsize);
    const int blocksNeeded = (bys % 16 == 0) ? bys / 16 : (bys / 16) + 1;
    AES aes(input);
    if (blocksNeeded == 1) {
        block plaintext[1] = {osuCrypto::toBlock(0, 0)};
        block ciphertext[1];
        aes.ecbEncBlocks(plaintext, 1, ciphertext);
        uint8_t* bptr = reinterpret_cast<uint8_t*>(ciphertext);
        *out = *reinterpret_cast<uint64_t*>(bptr);
        *out_s = ciphertext[0];
        return;
    }

    std::vector<block> plaintext(blocksNeeded);
    std::vector<block> ciphertext(blocksNeeded);
    for (int i = 0; i < blocksNeeded; i++) {
        plaintext[i] = osuCrypto::toBlock(0, i);
    }
    aes.ecbEncBlocks(plaintext.data(), blocksNeeded, ciphertext.data());
    uint8_t* bptr = reinterpret_cast<uint8_t*>(ciphertext.data());
    *out = *reinterpret_cast<uint64_t*>(bptr);
    *out_s = ciphertext[0];
}

}  // namespace

void two_pc_convert(const int bitsize, const int groupSize, const block& b,
                    uint64_t* out) {
    convertBlockToWords(bitsize, groupSize, b, out);
}

void two_pc_convert(const int bitsize, const block& b, uint64_t* out) {
    convertBlockToWords(bitsize, 1, b, out);
}

void two_pc_convert(int bitsize, const block& b, uint64_t* out,
                    block* out_s) {
    convertBlockToWordAndSeed(bitsize, b, out, out_s);
}

DPFKeyPack keyGenDPF(int party_id, int Bin, int Bout,
                     GroupElement idx, GroupElement payload, bool masked) {
    ensureSupportedFullTreeBits(Bin, "keyGenDPF");

    auto rng = secure_prng();
    auto s = rng.get<std::array<block, 1>>();
    const size_t leafCapacity = size_t(1) << Bin;
    const size_t halfCapacity = (leafCapacity > 1) ? (leafCapacity / 2) : 1;
    auto largeLevelNodes = std::make_unique<block[]>(leafCapacity);
    auto smallLevelNodes = std::make_unique<block[]>(halfCapacity);
    auto largeControlBits = std::make_unique<u8[]>(leafCapacity);
    auto smallControlBits = std::make_unique<u8[]>(halfCapacity);
    block* levelNodes =
        (Bin % 2 == 0) ? largeLevelNodes.get() : smallLevelNodes.get();
    block* nextLevelNodes =
        (Bin % 2 == 0) ? smallLevelNodes.get() : largeLevelNodes.get();
    u8* levelControlBits =
        (Bin % 2 == 0) ? largeControlBits.get() : smallControlBits.get();
    u8* nextLevelControlBits =
        (Bin % 2 == 0) ? smallControlBits.get() : largeControlBits.get();

    levelNodes[0] = s[0];
    levelControlBits[0] = static_cast<u8>(party_id - SERVER);

    auto tau = makeKeyArray<u8>(Bin * 2);
    auto scw = makeKeyArray<block>(Bin + 1);
    scw[0] = s[0];

    auto mask = std::make_shared<GroupElement>(0, Bin);
    if (masked) {
        mask->value = rng.get<uint64_t>();
        mod(*mask);
        idx = idx + *mask;
    }

    std::vector<u8> real_idx(Bin);
    u8 carry = 0;
    for (int i = 0; i < Bin; i++) {
        real_idx[Bin - i - 1] = idx[Bin - i - 1] ^ carry;
        carry = check_bit_overflow(party_id, idx[Bin - i - 1], carry, peer);
    }

    for (int i = 0; i < Bin; i++) {
        block leftChildren = ZeroBlock;
        block rightChildren = ZeroBlock;
        const size_t expandNum = size_t(1) << i;
        expandDpfPrgLevel(levelNodes, nextLevelNodes, expandNum,
                          leftChildren, rightChildren);

        const uint8_t mux_input =
            real_idx[i] ^ static_cast<u8>(party_id - SERVER);
        block sigma = multiplexer2(party_id, mux_input, leftChildren,
                                   rightChildren, peer);
        u8 tau_0 = lsb(leftChildren) ^ real_idx[i] ^
                   static_cast<u8>(party_id - SERVER);
        u8 tau_1 = lsb(rightChildren) ^ real_idx[i];

        reconstruct(&sigma);
        reconstruct(&tau_0);
        reconstruct(&tau_1);

        tau[i * 2] = tau_0;
        tau[i * 2 + 1] = tau_1;
        scw[i + 1] = sigma;

        for (size_t j = 0; j < expandNum; j++) {
            nextLevelControlBits[2 * j] = lsb(nextLevelNodes[2 * j]);
            nextLevelControlBits[2 * j + 1] =
                lsb(nextLevelNodes[2 * j + 1]);
            if (levelControlBits[j] == static_cast<u8>(1)) {
                nextLevelNodes[2 * j] =
                    nextLevelNodes[2 * j] ^ scw[i + 1];
                nextLevelNodes[2 * j + 1] =
                    nextLevelNodes[2 * j + 1] ^ scw[i + 1];
                nextLevelControlBits[2 * j] ^= tau_0;
                nextLevelControlBits[2 * j + 1] ^= tau_1;
            }
        }
        std::swap(levelNodes, nextLevelNodes);
        std::swap(levelControlBits, nextLevelControlBits);
    }

    uint64_t controlBitSum = 0;
    uint64_t lastLevelSum = 0;
    for (size_t i = 0; i < leafCapacity; i++) {
        uint64_t converted = 0;
        two_pc_convert(Bout, 1, levelNodes[i], &converted);
        lastLevelSum += converted;
        controlBitSum += static_cast<uint64_t>(levelControlBits[i]);
    }

    // NDSS legacy DPF uses cmp2bit on the two low bits of the control-bit sum
    // to select the arithmetic payload correction word.
    u8 cmp_tau_0 = static_cast<u8>(controlBitSum & 1);
    u8 cmp_tau_1 = static_cast<u8>((controlBitSum >> 1) & 1);
    u8 t = cmp_2bit_opt(party_id, cmp_tau_1, cmp_tau_0, peer);

    GroupElement sign(((party_id - SERVER) == 1) ? 1 : -1, Bout);
    GroupElement W_CW_0 = payload + lastLevelSum * sign;
    GroupElement W_CW_1 = -payload + lastLevelSum * (-sign);
    auto W_CW = makeKeyArray<GroupElement>(1);
    W_CW[0] = multiplexer2(party_id, t, W_CW_0, W_CW_1, peer);
    reconstruct(W_CW.data());

    DPFKeyPack key;
    key.Bin = Bin;
    key.Bout = Bout;
    key.groupSize = 1;
    key.k = scw;
    key.g = W_CW;
    key.v = tau;
    key.random_mask = mask;
    return key;
}

void evalDPF(int party, GroupElement* res, GroupElement idx,
             const DPFKeyPack& key, bool masked) {
    *res = evalDPF(party, idx, key, masked);
}

GroupElement evalDPF(int party, GroupElement idx, const DPFKeyPack& key,
                     bool masked) {
    const int Bin = key.Bin;
    const int Bout = key.Bout;
    const block* scw = key.k;
    const GroupElement* wcw = key.g;
    const u8* tau = key.v;
    if (masked) {
        idx = idx + *key.random_mask;
        reconstruct(1, &idx, idx.bitsize);
    }

    block levelNode = scw[0];
    u8 controlBit = static_cast<u8>(party - SERVER);
    const static block pt[2] = {ZeroBlock, OneBlock};
    AES aes;
    block ct[2];

    for (int i = 0; i < Bin; i++) {
        aes.setKey(levelNode);
        aes.ecbEncTwoBlocks(pt, ct);
        const int branch = static_cast<int>(idx[i]);
        const block levelCW = scw[i + 1];
        const u8 level_tau = tau[2 * i + branch];
        if (controlBit == static_cast<u8>(1)) {
            levelNode = ct[branch] ^ levelCW;
            controlBit = lsb(ct[branch]) ^ level_tau;
        } else {
            levelNode = ct[branch];
            controlBit = lsb(ct[branch]);
        }
    }

    const int sign = (party - SERVER) ? -1 : 1;
    uint64_t converted = 0;
    two_pc_convert(Bout, levelNode, &converted);
    return (wcw[0] * static_cast<uint64_t>(controlBit) + converted) * sign;
}

void evalDPF(int party, GroupElement* res, GroupElement* idx,
             const DPFKeyPack* keyList, int size, int max_bitsize) {
    std::vector<int> Bin(size);
    std::vector<int> Bout(size);
    std::vector<const block*> scw(size);
    std::vector<const GroupElement*> wcw(size);
    std::vector<const u8*> tau(size);
    std::vector<GroupElement> mask(size);
    std::vector<block> levelNodes(size);
    std::vector<u8> controlBit(size);
    std::vector<u8> levelTau(size);
    std::vector<AES> aesInstances(size);
    std::vector<block> ct(2 * size);
    std::vector<block> levelCW(size);
    const static block pt[2] = {ZeroBlock, OneBlock};

    for (int i = 0; i < size; i++) {
        Bin[i] = idx[i].bitsize;
        scw[i] = keyList[i].k;
        wcw[i] = keyList[i].g;
        tau[i] = keyList[i].v;
        mask[i] = *keyList[i].random_mask;
        levelNodes[i] = scw[i][0];
        controlBit[i] = static_cast<u8>(party - SERVER);
        levelTau[i] = controlBit[i];
        idx[i] = idx[i] + mask[i];
        Bout[i] = keyList[i].Bout;
    }
    reconstruct(size, idx, max_bitsize);

    for (int i = 0; i < max_bitsize; i++) {
#pragma omp parallel for
        for (int j = 0; j < size; j++) {
            aesInstances[j].setKey(levelNodes[j]);
            aesInstances[j].ecbEncTwoBlocks(pt, ct.data() + 2 * j);
            levelCW[j] = scw[j][i + 1];
            const int branch = static_cast<int>(idx[j][i]);
            levelTau[j] = tau[j][2 * i + branch];
            if (controlBit[j] == static_cast<u8>(1)) {
                levelNodes[j] = ct[2 * j + branch] ^ levelCW[j];
                controlBit[j] = lsb(ct[2 * j + branch]) ^ levelTau[j];
            } else {
                levelNodes[j] = ct[2 * j + branch];
                controlBit[j] = lsb(ct[2 * j + branch]);
            }
        }
    }

    const int sign = (party - SERVER) ? -1 : 1;
    std::vector<uint64_t> converted(size);
    for (int i = 0; i < size; i++) {
        two_pc_convert(Bout[i], levelNodes[i], &converted[i]);
        res[i] = (wcw[i][0] * static_cast<uint64_t>(controlBit[i]) +
                  converted[i]) * sign;
    }
}

void evalAll(int party, GroupElement* res, const DPFKeyPack& key, int length) {
    ensureSupportedFullTreeBits(length, "evalAll");
    assert(length == key.Bin);
    const size_t leafNum = size_t(1) << length;
    const size_t halfNum = (leafNum > 1) ? (leafNum / 2) : 1;
    auto largeNodes = std::make_unique<block[]>(leafNum);
    auto smallNodes = std::make_unique<block[]>(halfNum);
    auto largeControlBits = std::make_unique<u8[]>(leafNum);
    auto smallControlBits = std::make_unique<u8[]>(halfNum);
    block* levelNodes = (length % 2 == 0) ? largeNodes.get() : smallNodes.get();
    block* nextNodes = (length % 2 == 0) ? smallNodes.get() : largeNodes.get();
    u8* controlBits =
        (length % 2 == 0) ? largeControlBits.get() : smallControlBits.get();
    u8* nextControlBits =
        (length % 2 == 0) ? smallControlBits.get() : largeControlBits.get();
    levelNodes[0] = key.k[0];
    controlBits[0] = static_cast<u8>(party - SERVER);

    const static block pt[2] = {ZeroBlock, OneBlock};
    for (int level = 0; level < length; level++) {
        const size_t levelSize = size_t(1) << level;
#pragma omp parallel for if(levelSize >= 1024)
        for (long long node_ll = 0;
             node_ll < static_cast<long long>(levelSize); node_ll++) {
            const size_t node = static_cast<size_t>(node_ll);
            AES aes;
            block ct[2];
            aes.setKey(levelNodes[node]);
            aes.ecbEncTwoBlocks(pt, ct);
            for (int branch = 0; branch < 2; branch++) {
                const size_t child = 2 * node + static_cast<size_t>(branch);
                nextNodes[child] = ct[branch];
                nextControlBits[child] = lsb(ct[branch]);
                if (controlBits[node] == static_cast<u8>(1)) {
                    nextNodes[child] = nextNodes[child] ^ key.k[level + 1];
                    nextControlBits[child] ^=
                        key.v[2 * level + branch];
                }
            }
        }
        std::swap(levelNodes, nextNodes);
        std::swap(controlBits, nextControlBits);
    }

    const int sign = (party - SERVER) ? -1 : 1;
#pragma omp parallel for if(leafNum >= 1024)
    for (long long i_ll = 0; i_ll < static_cast<long long>(leafNum); i_ll++) {
        const size_t i = static_cast<size_t>(i_ll);
        uint64_t converted = 0;
        two_pc_convert(key.Bout, levelNodes[i], &converted);
        res[i] = (key.g[0] * static_cast<uint64_t>(controlBits[i]) +
                  converted) * sign;
    }
}
