/*
 * Description: Refer to README.md
 * Author: Pengzhi Xing
 * Email: p.xing@std.uestc.edu.cn
 * Last Modified: 2024-12-02
 * License: Apache-2.0 License
 * Copyright (c) 2024 Pengzhi Xing
 * Usage:
 * Example:
 *
 * Change Log:
 * 2024-12-02 - Initial version of the authentication module
 */
#include "2pc_idpf.h"

#include <memory>
#include <stdexcept>
#include <string>

using namespace osuCrypto;

inline int bytesize(const int bitsize) {
    return (bitsize % 8) == 0 ? bitsize / 8 : (bitsize / 8)  + 1;
}

namespace {

constexpr size_t kParallelPrgExpansionThreshold = 4096;
constexpr int kMaxFullTreeBits = 24;

void ensureSupportedFullTreeBits(const int bits, const char* caller) {
    if (bits < 0 || bits > kMaxFullTreeBits) {
        throw std::invalid_argument(
            std::string(caller) + " requires 0 <= bit length <= " +
            std::to_string(kMaxFullTreeBits) +
            " in the current full-tree implementation");
    }
}

void expandDpfPrgLevel(const block* levelNodes, block* nextLevelNodes,
                       size_t expandNum, block& leftChildren,
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
            for (long long jj = 0; jj < static_cast<long long>(expandNum); jj++) {
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

}

void two_pc_convert(const int bitsize, const int groupSize, const block &b, uint64_t *out)
{
    static const block notThreeBlock = osuCrypto::toBlock((u64)~0, (u64)~3);
    const int bys = bytesize(bitsize);
    const int totalBys = bys * groupSize;
    if (bys * groupSize <= 16) {
            const uint8_t *bptr = reinterpret_cast<const uint8_t *>(&b);
        for(int i = 0; i < groupSize; i++) {
            out[i] = *(uint64_t *)(bptr + i * bys);
        }
    }
    else {
        int numblocks = totalBys % 16 == 0 ? totalBys / 16 : (totalBys / 16) + 1;
        AES aes(b);
        std::vector<block> pt(numblocks);
        std::vector<block> ct(numblocks);
        for(int i = 0; i < numblocks; i++) {
            pt[i] = osuCrypto::toBlock(0, i);
        }
        aes.ecbEncBlocks(pt.data(), numblocks, ct.data());
        uint8_t *bptr = reinterpret_cast<uint8_t *>(ct.data());
        for(int i = 0; i < groupSize; i++) {
            out[i] = *(uint64_t *)(bptr + i * bys);
        }
    }
}

void two_pc_convert(const int bitsize, const block &b, uint64_t *out)
{
    const int bys = bytesize(bitsize);
    const int totalBys = bys;
    if (bys <= 16) {
        const uint8_t *bptr = reinterpret_cast<const uint8_t *>(&b);
        *out = *(uint64_t *)(bptr);
    }
    else {
        int numblocks = totalBys % 16 == 0 ? totalBys / 16 : (totalBys / 16) + 1;
        AES aes(b);
        std::vector<block> pt(numblocks);
        std::vector<block> ct(numblocks);
        for(int i = 0; i < numblocks; i++) {
            pt[i] = osuCrypto::toBlock(0, i);
        }
        aes.ecbEncBlocks(pt.data(), numblocks, ct.data());
        uint8_t *bptr = reinterpret_cast<uint8_t *>(ct.data());
        *out = *(uint64_t *)(bptr);
    }
}

void two_pc_convert(int bitsize, const block& b, uint64_t *out, block* out_s){
    // Implementation of iDPF convert in Lightweight Techniques for Private Heavy Hitter
    const int bys = bytesize(bitsize);
    const int totalBys = bys;

    int numblocks = totalBys % 16 == 0 ? totalBys / 16 : (totalBys / 16) + 1;
    const block _b = b;
    AES aes(_b);
    if (numblocks == 1) {
        block pt[1] = {osuCrypto::toBlock(0, 0)};
        block ct[1];
        aes.ecbEncBlocks(pt, 1, ct);
        uint8_t *bptr = reinterpret_cast<uint8_t *>(ct);
        *out = *reinterpret_cast<uint64_t *>(bptr);
        *out_s = ct[0];
        return;
    }

    std::vector<block> pt(numblocks);
    std::vector<block> ct(numblocks);
    for(int i = 0; i < numblocks; i++) {
        pt[i] = osuCrypto::toBlock(0, i);
    }
    aes.ecbEncBlocks(pt.data(), numblocks, ct.data());
    uint8_t *bptr = (uint8_t *)ct.data();
    *out = *(uint64_t *)(bptr);
    *out_s = ct[0];
}


DPFKeyPack keyGenDPF(int party_id, int Bin, int Bout,
                     GroupElement idx, GroupElement payload, bool masked)
{
    ensureSupportedFullTreeBits(Bin, "keyGenDPF");
    // Here payload should be the same bit length with b out
    // Here we initialize the first block as the root node
    auto rng = secure_prng();
    auto s = rng.get<std::array<block, 1>>();
    // One full leaf-level buffer plus one half-level buffer is enough: choose
    // the initial orientation so the final level lands in the full buffer.
    const size_t leafCapacity = size_t(1) << Bin;
    const size_t halfCapacity = (leafCapacity > 1) ? (leafCapacity / 2) : 1;
    auto largeLevelNodes = std::make_unique<block[]>(leafCapacity);
    auto smallLevelNodes = std::make_unique<block[]>(halfCapacity);
    auto largeControlBits = std::make_unique<u8[]>(leafCapacity);
    auto smallControlBits = std::make_unique<u8[]>(halfCapacity);
    block* levelNodes = (Bin % 2 == 0) ? largeLevelNodes.get() : smallLevelNodes.get();
    block* nextLevelNodes = (Bin % 2 == 0) ? smallLevelNodes.get() : largeLevelNodes.get();
    u8* levelControlBits = (Bin % 2 == 0) ? largeControlBits.get() : smallControlBits.get();
    u8* nextLevelControlBits = (Bin % 2 == 0) ? smallControlBits.get() : largeControlBits.get();

    levelNodes[0] = s[0];
    levelControlBits[0] = (u8)(party_id-2);

    // Variants in this area indicates generation results -> DPFKeyPack
    auto tau = makeKeyArray<u8>(Bin * 2);
    auto scw = makeKeyArray<block>(Bin + 1);
    scw[0] = s[0];
    block sigma;

    // Create mask
    auto mask = std::make_shared<GroupElement>(0, Bin);
    if (masked){
        auto mask_s = rng.get<uint64_t>();
        mask->value = mask_s;
        idx = idx + *mask;
    }

    std::vector<u8> real_idx(Bin);
    u8 level_and_res = 0;
    for (int i = 0; i < Bin; i++) {
        real_idx[Bin - i - 1] = idx[Bin - i - 1] ^ level_and_res;
        level_and_res = check_bit_overflow(party_id, idx[Bin - i - 1], level_and_res, peer);
    }

    for (int i = 0; i < Bin; i++){
        block leftChildren = ZeroBlock;
        block rightChildren = ZeroBlock;

        // First step: expand all the nodes in the previous level
        // We use 128 bit as the seed, instead of 128-1 in llama
        // The seeds number is 2^i
        const size_t expandNum = size_t(1) << i;
        expandDpfPrgLevel(levelNodes, nextLevelNodes, expandNum, leftChildren,
                          rightChildren);

        // Second step: Invoke F_MUX and retrieve reconstructed leftChildren or rightChildren
        // Selection Criterion:
        // P0 with s0l, t0l=lsb(s0l), s0r, t0r=lsb(s0r)
        // P1 with s1l, t1l=lsb(s1l), s1r, t1r=lsb(s1r)
        // if a[x] = 1, get s0, else get s1
        //TODO: Add and wrapper for single non-share input
        uint8_t mux_input = real_idx[i] ^ (party_id - 2);
        sigma = multiplexer2(party_id, mux_input, leftChildren, rightChildren, peer);
        // Set tau, note that lsb returns <u8>
        u8 tau_0 = lsb(leftChildren) ^ real_idx[i] ^ (u8)(party_id - 2);
        u8 tau_1 = lsb(rightChildren) ^ real_idx[i];

        // Reconstruct sigma, tau
        block recL = leftChildren;
        block recR = rightChildren;
        reconstruct(&recL);
        reconstruct(&recR);
        reconstruct(&sigma);
        reconstruct(&tau_0);
        reconstruct(&tau_1);

        // Now we parse CW
        tau[i * 2] = tau_0;
        tau[i * 2 + 1] = tau_1;
        scw[i + 1] = sigma;

        // Third step: update seeds
        // For every seed in the level, it should xor t * this_level.CW, where t is the control bit
        for (size_t j = 0; j < expandNum; j++){
            nextLevelControlBits[2 * j] = lsb(nextLevelNodes[2 * j]);
            nextLevelControlBits[2 * j + 1] = lsb(nextLevelNodes[2 * j + 1]);
            if (levelControlBits[j] == (u8)1) {
                // Here the sigma does not contain the info of CW control bit, i.e. simply add scw
                // cannot update control bit to hold on-path attribute
                nextLevelNodes[2 * j] = nextLevelNodes[2 * j] ^ scw[i + 1];
                nextLevelNodes[2 * j + 1] = nextLevelNodes[2 * j + 1] ^ scw[i + 1];
                nextLevelControlBits[2 * j] = nextLevelControlBits[2 * j] ^ tau_0;
                nextLevelControlBits[2 * j + 1] = nextLevelControlBits[2 * j + 1] ^ tau_1;
            }
        }
        std::swap(levelNodes, nextLevelNodes);
        std::swap(levelControlBits, nextLevelControlBits);
    }


    // Last step: Calculate CW_{n+1}
    // To begin with, we add all control bits together
    uint64_t controlBitSum = 0;
    // We also need to add all Converted elements
    uint64_t lastLevelSum = 0;
    for (size_t i = 0; i < leafCapacity; i++){
        uint64_t converted = 0;
        two_pc_convert(Bout, 1, levelNodes[i], &converted);
        lastLevelSum = lastLevelSum + converted;
        controlBitSum = controlBitSum + (uint64_t)levelControlBits[i];
    }
    // Get last 2 bits of bits sum to compare
    u8 cmp_tau_0 = (u8)(controlBitSum & 1);
    u8 cmp_tau_1 = (u8)((controlBitSum >> 1) & 1);
    // Calculate [t]
    // The first input is high order bit, latter is lower order bit.
    u8 t = cmp_2bit_opt(party_id, cmp_tau_1, cmp_tau_0, peer);

    GroupElement sign(((party_id-2) == 1) ? 1 : -1, Bout);
    // Sign = -1 for p0, 1 for p1
    GroupElement W_CW_0 = payload + lastLevelSum * sign;
    GroupElement W_CW_1 = -payload + lastLevelSum * (-sign);
    auto W_CW = makeKeyArray<GroupElement>(1);
    W_CW[0] = GroupElement(0, Bout);

    W_CW[0] = multiplexer2(party_id, t, W_CW_0, W_CW_1, peer);

    reconstruct(W_CW.data());

    // in DPF, swc is the seed for each level from root level, W_CW is to help convert output from Z_2 to Z_n
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



DPFKeyPack keyGeniDPF(int party_id, int Bin, int Bout,
                     GroupElement idx, const GroupElement* payload, bool call_from_DCF, bool masked)
{
    ensureSupportedFullTreeBits(Bin, "keyGeniDPF");
    // This is the 2pc generation of iDPF Key, proceed with multiple payload
    // Here we initialize the first block as the root node
    auto rng = secure_prng();
    auto s = rng.get<block>();
    // One full leaf-level buffer plus one half-level buffer is enough: choose
    // the initial orientation so the final level lands in the full buffer.
    const size_t leafCapacity = size_t(1) << Bin;
    const size_t halfCapacity = (leafCapacity > 1) ? (leafCapacity / 2) : 1;
    auto largeLevelNodes = std::make_unique<block[]>(leafCapacity);
    auto smallLevelNodes = std::make_unique<block[]>(halfCapacity);
    auto largeControlBits = std::make_unique<u8[]>(leafCapacity);
    auto smallControlBits = std::make_unique<u8[]>(halfCapacity);
    block* levelNodes = (Bin % 2 == 0) ? largeLevelNodes.get() : smallLevelNodes.get();
    block* nextLevelNodes = (Bin % 2 == 0) ? smallLevelNodes.get() : largeLevelNodes.get();
    u8* levelControlBits = (Bin % 2 == 0) ? largeControlBits.get() : smallControlBits.get();
    u8* nextLevelControlBits = (Bin % 2 == 0) ? smallControlBits.get() : largeControlBits.get();

    levelNodes[0] = s;
    levelControlBits[0] = (u8)(party_id-2);

    // Variants in this area indicates generation results -> DPFKeyPack
    auto tau = makeKeyArray<u8>(Bin * 2);
    auto scw = makeKeyArray<block>(Bin + 1);
    scw[0] = s;

    std::vector<GroupElement> W_CW_0(Bin);
    std::vector<GroupElement> W_CW_1(Bin);
    std::vector<u8> t(Bin);
    std::vector<u8> cmp_tau_0(Bin);
    std::vector<u8> cmp_tau_1(Bin);
    std::vector<uint64_t> levelSum(Bin, 0);

    // Variants for iDPF CW calculation
    auto W_CW = makeKeyArray<GroupElement>(Bin);
    for (int i = 0; i < Bin; i++){
        W_CW[i].bitsize = Bout;
    }

    // Preparing random mask
    auto mask = std::make_shared<GroupElement>(0, Bin);
    if (masked){
        auto mask_s = rng.get<uint64_t>();
        mask->value = mask_s;
        idx = idx + *mask;
    }

    // Step 0: prepare for the DigDec decomposition of x from msb to lsb
    // Particularly, we construct from lsb to msb, then reverse it.
    std::vector<u8> real_idx(Bin);
    u8 level_and_res = 0;
    if (call_from_DCF){
        for (int i = 0; i < Bin; i++){
            real_idx[i] = idx[i];
        }
    }else{
        for (int i = 0; i < Bin; i++) {
            real_idx[Bin - i - 1] = idx[Bin - i - 1] ^ level_and_res;
            level_and_res = check_bit_overflow(party_id, idx[Bin - i - 1], level_and_res, peer);
        }
    }


    for (int i = 0; i < Bin; i++){

        block leftChildren = ZeroBlock;
        block rightChildren = ZeroBlock;

        // First step: expand all the nodes in the previous level
        // We use 128 bit as the seed, instead of 128-1 in llama
        // The seeds number is 2^i
        const size_t expandNum = size_t(1) << i;
        expandDpfPrgLevel(levelNodes, nextLevelNodes, expandNum, leftChildren,
                          rightChildren);

        // Second step: Invoke F_MUX and retrieve reconstructed leftChildren or rightChildren
        // Selection Criterion:
        // P0 with s0l, t0l=lsb(s0l), s0r, t0r=lsb(s0r)
        // P1 with s1l, t1l=lsb(s1l), s1r, t1r=lsb(s1r)
        // if a[x] = 1, get s0, else get s1
        uint8_t mux_input = real_idx[i] ^ (party_id-2);
        block sigma;
        sigma = multiplexer2(party_id, mux_input, leftChildren, rightChildren, peer);

        // Set tau, note that lsb returns <u8>
        u8 tau_0 = lsb(leftChildren) ^ real_idx[i] ^ (u8)(party_id - 2);
        u8 tau_1 = lsb(rightChildren) ^ real_idx[i];

        // Reconstruct sigma, tau
        reconstruct(&sigma);
        reconstruct(&tau_0);
        reconstruct(&tau_1);

        // Now we parse CW
        tau[i * 2] = tau_0;
        tau[i * 2 + 1] = tau_1;
        scw[i + 1] = sigma;

        // Third step: update seeds
        // For every seed in the level, it should xor t * this_level.CW, where t is the control bit
        for (size_t j = 0; j < expandNum; j++){
            nextLevelControlBits[2 * j] = lsb(nextLevelNodes[2 * j]);
            nextLevelControlBits[2 * j + 1] = lsb(nextLevelNodes[2 * j + 1]);
            if (levelControlBits[j] == (u8)1) {
                nextLevelNodes[2 * j] = nextLevelNodes[2 * j] ^ scw[i + 1];
                nextLevelNodes[2 * j + 1] = nextLevelNodes[2 * j + 1] ^ scw[i + 1];
                nextLevelControlBits[2 * j] = nextLevelControlBits[2 * j] ^ tau_0;
                nextLevelControlBits[2 * j + 1] = nextLevelControlBits[2 * j + 1] ^ tau_1;
            }
        }

        std::swap(levelNodes, nextLevelNodes);
        std::swap(levelControlBits, nextLevelControlBits);

        // Forth Step: calculate layer-wise CW
        // To begin with, we add all control bits together
        uint64_t controlBitSum = 0;

        // We also need to add all Converted elements
        for (size_t j = 0; j < 2 * expandNum; j++){
            uint64_t converted = 0;
            two_pc_convert(Bout, levelNodes[j], &converted, &levelNodes[j]);
            levelSum[i] = levelSum[i] + converted;
            controlBitSum = controlBitSum + (uint64_t)levelControlBits[j];
        }
        // Get last 2 bits of bits sum to compare
        cmp_tau_0[i] = (u8)(controlBitSum & 1);
        cmp_tau_1[i] = (u8)((controlBitSum >> 1) & 1);
    }
    GroupElement sign(((party_id-2) == 1) ? 1 : -1, Bout);
    // Sign = -1 for p1, 1 for p0
    for (int i = 0; i < Bin; i++){
        W_CW_0[i] = payload[i] + levelSum[i] * sign;
        W_CW_1[i] = -payload[i] + levelSum[i] * -sign;
    }
    // Calculate [t]
    cmp_2bit_opt(party_id, cmp_tau_1.data(), cmp_tau_0.data(), t.data(), Bin, peer);
    multiplexer2(party_id, t.data(), W_CW_0.data(), W_CW_1.data(), W_CW, (int32_t)Bin, peer);
    reconstruct((int32_t)Bin, W_CW, Bout);

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

DPFKeyPack keyGeniDPF(int party_id, int Bin, int Bout,
                      u8* idx, const GroupElement* payload, bool call_from_DCF, bool masked)
{
    ensureSupportedFullTreeBits(Bin, "keyGeniDPF");
    // This is the 2pc generation of iDPF Key, proceed with multiple payload
    // Here we initialize the first block as the root node
    auto rng = secure_prng();
    auto s = rng.get<block>();
    // One full leaf-level buffer plus one half-level buffer is enough: choose
    // the initial orientation so the final level lands in the full buffer.
    const size_t leafCapacity = size_t(1) << Bin;
    const size_t halfCapacity = (leafCapacity > 1) ? (leafCapacity / 2) : 1;
    auto largeLevelNodes = std::make_unique<block[]>(leafCapacity);
    auto smallLevelNodes = std::make_unique<block[]>(halfCapacity);
    auto largeControlBits = std::make_unique<u8[]>(leafCapacity);
    auto smallControlBits = std::make_unique<u8[]>(halfCapacity);
    block* levelNodes = (Bin % 2 == 0) ? largeLevelNodes.get() : smallLevelNodes.get();
    block* nextLevelNodes = (Bin % 2 == 0) ? smallLevelNodes.get() : largeLevelNodes.get();
    u8* levelControlBits = (Bin % 2 == 0) ? largeControlBits.get() : smallControlBits.get();
    u8* nextLevelControlBits = (Bin % 2 == 0) ? smallControlBits.get() : largeControlBits.get();

    levelNodes[0] = s;
    levelControlBits[0] = (u8)(party_id-2);

    // Variants in this area indicates generation results -> DPFKeyPack
    auto tau = makeKeyArray<u8>(Bin * 2);
    auto scw = makeKeyArray<block>(Bin + 1);
    scw[0] = s;
    std::vector<GroupElement> W_CW_0(Bin);
    std::vector<GroupElement> W_CW_1(Bin);
    std::vector<u8> t(Bin);
    std::vector<u8> cmp_tau_0(Bin);
    std::vector<u8> cmp_tau_1(Bin);
    std::vector<uint64_t> levelSum(Bin, 0);

    // Variants for iDPF CW calculation
    auto W_CW = makeKeyArray<GroupElement>(Bin);

    for (int i = 0; i < Bin; i++){
        W_CW[i].bitsize = Bout;
    }

    // Preparing random mask
    auto mask = std::make_shared<GroupElement>(0, Bin);
    assert(masked == false);

    // Step 0: prepare for the DigDec decomposition of x from msb to lsb
    // Particularly, we construct from lsb to msb, then reverse it.
    std::vector<u8> real_idx(Bin);
    u8 level_and_res = 0;
    if (call_from_DCF){
        for (int i = 0; i < Bin; i++){
            real_idx[i] = idx[i];
        }
    }else{
        for (int i = 0; i < Bin; i++) {
            real_idx[Bin - i - 1] = idx[Bin - i - 1] ^ level_and_res;
            level_and_res = check_bit_overflow(party_id, idx[Bin - i - 1], level_and_res, peer);
        }
    }


    for (int i = 0; i < Bin; i++){

        block leftChildren = ZeroBlock;
        block rightChildren = ZeroBlock;

        // First step: expand all the nodes in the previous level
        // We use 128 bit as the seed, instead of 128-1 in llama
        // The seeds number is 2^i
        const size_t expandNum = size_t(1) << i;
        expandDpfPrgLevel(levelNodes, nextLevelNodes, expandNum, leftChildren,
                          rightChildren);

        // Second step: Invoke F_MUX and retrieve reconstructed leftChildren or rightChildren
        // Selection Criterion:
        // P0 with s0l, t0l=lsb(s0l), s0r, t0r=lsb(s0r)
        // P1 with s1l, t1l=lsb(s1l), s1r, t1r=lsb(s1r)
        // if a[x] = 1, get s0, else get s1
        uint8_t mux_input = real_idx[i] ^ (party_id-2);
        block sigma;
        sigma = multiplexer2(party_id, mux_input, leftChildren, rightChildren, peer);

        // Set tau, note that lsb returns <u8>
        u8 tau_0 = lsb(leftChildren) ^ real_idx[i] ^ (u8)(party_id - 2);
        u8 tau_1 = lsb(rightChildren) ^ real_idx[i];

        // Reconstruct sigma, tau
        reconstruct(&sigma);
        reconstruct(&tau_0);
        reconstruct(&tau_1);

        // Now we parse CW
        tau[i * 2] = tau_0;
        tau[i * 2 + 1] = tau_1;
        scw[i + 1] = sigma;

        // Third step: update seeds
        // For every seed in the level, it should xor t * this_level.CW, where t is the control bit
        for (size_t j = 0; j < expandNum; j++){
            nextLevelControlBits[2 * j] = lsb(nextLevelNodes[2 * j]);
            nextLevelControlBits[2 * j + 1] = lsb(nextLevelNodes[2 * j + 1]);
            if (levelControlBits[j] == (u8)1) {
                nextLevelNodes[2 * j] = nextLevelNodes[2 * j] ^ scw[i + 1];
                nextLevelNodes[2 * j + 1] = nextLevelNodes[2 * j + 1] ^ scw[i + 1];
                nextLevelControlBits[2 * j] = nextLevelControlBits[2 * j] ^ tau_0;
                nextLevelControlBits[2 * j + 1] = nextLevelControlBits[2 * j + 1] ^ tau_1;
            }
        }

        std::swap(levelNodes, nextLevelNodes);
        std::swap(levelControlBits, nextLevelControlBits);

        // Forth Step: calculate layer-wise CW
        // To begin with, we add all control bits together
        uint64_t controlBitSum = 0;
        // We also need to add all Converted elements
        for (size_t j = 0; j < 2 * expandNum; j++){
            uint64_t converted = 0;
            two_pc_convert(Bout, levelNodes[j], &converted, &levelNodes[j]);
            levelSum[i] = levelSum[i] + converted;
            controlBitSum = controlBitSum + (uint64_t)levelControlBits[j];
        }
        // Get last 2 bits of bits sum to compare
        cmp_tau_0[i] = (u8)(controlBitSum & 1);
        cmp_tau_1[i] = (u8)((controlBitSum >> 1) & 1);
    }
    // Calculate [t]
    cmp_2bit_opt(party_id, cmp_tau_1.data(), cmp_tau_0.data(), t.data(), Bin, peer);
    GroupElement sign(((party_id-2) == 1) ? 1 : -1, Bout);
    // Sign = -1 for p1, 1 for p0
    for (int i = 0; i < Bin; i++){
        W_CW_0[i] = payload[i] + levelSum[i] * sign;
        W_CW_1[i] = -payload[i] + levelSum[i] * -sign;
    }
    multiplexer2(party_id, t.data(), W_CW_0.data(), W_CW_1.data(), W_CW, (int32_t)Bin, peer);
    reconstruct((int32_t)Bin, W_CW, Bout);

    // W_CW is returned to the caller.
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

void evalDPF(int party, GroupElement *res, GroupElement idx, const DPFKeyPack &key, bool masked){
    *res = evalDPF(party, idx, key, masked);
}

GroupElement evalDPF(int party, GroupElement idx, const DPFKeyPack &key, bool masked){
    // Eval of 2pc-dpf
    // Initialize with the root node
    osuCrypto::AES AESInstance;

    // Parse DCF Key
    // in DPF, swc is the seed for each level from root level, W_CW is to help convert output from Z_2 to Z_n
    int Bin = key.Bin;
    int Bout = key.Bout;
    int groupSize = key.groupSize;
    const block* scw = key.k;
    const GroupElement* wcw = key.g;
    const u8* tau = key.v;
    GroupElement mask = *key.random_mask;
    if (masked){
        idx = idx + mask;
        reconstruct(1, &idx, idx.bitsize);
    }

    // Prepare root node
    block levelNodes = scw[0];
    u8 controlBit = (u8)(party - 2);
    u8 level_tau = controlBit;
    static const block notOneBlock = osuCrypto::toBlock(~0, ~1);
    static const block notThreeBlock = osuCrypto::toBlock(~0, ~3);
    const static block pt[2] = {ZeroBlock, OneBlock};
    block ct[2];

    // Start evaluation
    for (int i = 0; i < Bin; i++){
        AESInstance.setKey(levelNodes);
        AESInstance.ecbEncTwoBlocks(pt, ct);
        block levelCW = scw[i + 1];
        level_tau = tau[2 * i + (int)(idx[i])];
        if (controlBit == (u8)1){
            levelNodes = ct[(int)(idx[i])] ^  levelCW;
            controlBit = lsb(ct[(int)(idx[i])]) ^ level_tau;
        }else{
            levelNodes = ct[(int)(idx[i])];
            controlBit = lsb(ct[(int)(idx[i])]);
        }
    }

    // At the final stage, we make the convert from output in Z_2 to Z_n
    int sign = (party - 2) ? -1 : 1;
    uint64_t convert_res = 0;
    two_pc_convert(Bout, levelNodes, &convert_res);

    return (wcw[0] * (uint64_t) controlBit + convert_res) * sign;
}

void evaliDPF(int party, GroupElement *res, GroupElement idx, const DPFKeyPack &key, bool masked){
    const std::vector<GroupElement> output = evaliDPF(party, idx, key, masked);
    for (size_t i = 0; i < output.size(); ++i) {
        res[i] = output[i];
    }
}

std::vector<GroupElement> evaliDPF(int party, GroupElement idx, const DPFKeyPack &key, bool masked){
    // Eval of 2pc-dpf
    // Initialize with the root node
    // The difference between dpf and idpf are to expand CW at each level
    osuCrypto::AES AESInstance;

    // Parse DCF Key
    // in DPF, swc is the seed for each level from root level, W_CW is to help convert output from Z_2 to Z_n
    int Bin = key.Bin;
    int Bout = key.Bout;
    std::vector<GroupElement> res(Bin);
    const block* scw = key.k;
    const GroupElement* wcw = key.g;
    const u8* tau = key.v;
    GroupElement mask  = *key.random_mask;
    if (masked){
        idx = idx + mask;
        reconstruct(1, &idx, idx.bitsize);
    }

    // Prepare root node
    block levelNodes = scw[0];
    u8 controlBit = (u8)(party - 2);
    u8 level_tau = controlBit;
    static const block notOneBlock = osuCrypto::toBlock(~0, ~1);
    static const block notThreeBlock = osuCrypto::toBlock(~0, ~3);
    const static block pt[2] = {ZeroBlock, OneBlock};
    block ct[2];
    uint64_t convert_res = 0;

    // Start evaluation
    for (int i = 0; i < Bin; i++){
        AESInstance.setKey(levelNodes);
        AESInstance.ecbEncTwoBlocks(pt, ct);
        block levelCW = scw[i + 1];
        level_tau = tau[2 * i + (int)(idx[i])];
        if (controlBit == (u8)1){
            levelNodes = ct[(int)(idx[i])] ^  levelCW;
            controlBit = lsb(ct[(int)(idx[i])]) ^ level_tau;
        }else{
            levelNodes = ct[(int)(idx[i])];
            controlBit = lsb(ct[(int)(idx[i])]);
        }

        // At each stage, we make the convert from output in Z_2 to Z_n
        int sign = (party - 2) ? -1 : 1;
        // wrapper void two_pc_convert(const int bitsize, const block &b, uint64_t *out, block* out_s)
        two_pc_convert(Bout, levelNodes, &convert_res, &levelNodes);
        res[i] = (wcw[i] * (uint64_t) controlBit + convert_res) * sign;
    }
    return res;
}

void evalDPF(int party, GroupElement *res, GroupElement *idx, const DPFKeyPack *keyList, int size, int max_bitsize){
    std::vector<int> Bin(size);
    std::vector<int> Bout(size);
    std::vector<const block*> scw(size);
    std::vector<const GroupElement*> wcw(size);
    std::vector<const u8*> tau(size);
    std::vector<GroupElement> mask(size);
    std::vector<block> levelNodes(size);
    std::vector<u8> controlBit(size);
    std::vector<u8> level_tau(size);
    static const block notOneBlock = osuCrypto::toBlock(~0, ~1);
    static const block notThreeBlock = osuCrypto::toBlock(~0, ~3);
    const static block pt[2] = {ZeroBlock, OneBlock};
    // Maybe call ecbEncBlocks
    std::vector<osuCrypto::AES> AESInstances(size);
    std::vector<block> ct(2 * size);
    std::vector<block> levelCW(size);
    // Perform batched idx reconstruct
    for (int i = 0; i < size; i++){
        Bin[i] = idx[i].bitsize;
        scw[i] = keyList[i].k;
        wcw[i] = keyList[i].g;
        tau[i] = keyList[i].v;
        mask[i] = *(keyList[i].random_mask);
        levelNodes[i] = scw[i][0];
        controlBit[i] = (u8)(party - 2);
        level_tau[i] = controlBit[i];
        idx[i] = idx[i] + mask[i];
        Bout[i] = keyList[i].Bout;
    }
    reconstruct(size, idx, max_bitsize);

    for (int i = 0; i < max_bitsize; i++){
        // We perform evaluation layer-wise
#pragma omp parallel for
        for (int j = 0; j < size; j++){
            AESInstances[j].setKey(levelNodes[j]);
            AESInstances[j].ecbEncTwoBlocks(pt, ct.data() + 2 * j);
            levelCW[j] = scw[j][i + 1];
            level_tau[j] = tau[j][2 * i + (int)(idx[j][i])];
            if (controlBit[j] == (u8)1){
                levelNodes[j] = ct[2 * j + (int)(idx[j][i])] ^ levelCW[j];
                controlBit[j] = lsb(ct[2 * j + (int)(idx[j][i])]) ^ level_tau[j];
            }else {
                levelNodes[j] = ct[2 * j + (int) (idx[j][i])];
                controlBit[j] = lsb(ct[2 * j + (int) (idx[j][i])]);
            }
        }
    }


    int sign = (party - 2) ? -1 : 1;
    std::vector<uint64_t> convert_res(size);
    for (int i = 0; i < size; i++){
        two_pc_convert(Bout[i], levelNodes[i], &convert_res[i]);
        res[i] = (wcw[i][0] * (uint64_t) controlBit[i] + convert_res[i]) * sign;
    }

    return;
}

void evalAll(int party, GroupElement* res, const DPFKeyPack& key, int length){
    ensureSupportedFullTreeBits(length, "evalAll");
    assert(length == key.Bin);
    const size_t leaf_num = size_t(1) << length;
    const size_t half_num = (leaf_num > 1) ? (leaf_num / 2) : 1;
    auto large_nodes = std::make_unique<block[]>(leaf_num);
    auto small_nodes = std::make_unique<block[]>(half_num);
    auto large_control_bits = std::make_unique<u8[]>(leaf_num);
    auto small_control_bits = std::make_unique<u8[]>(half_num);
    block* level_nodes = (length % 2 == 0) ? large_nodes.get() : small_nodes.get();
    block* next_nodes = (length % 2 == 0) ? small_nodes.get() : large_nodes.get();
    u8* control_bits = (length % 2 == 0) ? large_control_bits.get() : small_control_bits.get();
    u8* next_control_bits = (length % 2 == 0) ? small_control_bits.get() : large_control_bits.get();
    level_nodes[0] = key.k[0];
    control_bits[0] = static_cast<u8>(party - 2);

    const static block pt[2] = {ZeroBlock, OneBlock};
    for (int level = 0; level < length; level++){
        const size_t level_size = size_t(1) << level;
        #pragma omp parallel for if(level_size >= 1024)
        for (long long node_ll = 0; node_ll < static_cast<long long>(level_size); node_ll++){
            const size_t node = static_cast<size_t>(node_ll);
            osuCrypto::AES aes;
            block ct[2];
            aes.setKey(level_nodes[node]);
            aes.ecbEncTwoBlocks(pt, ct);
            for (int branch = 0; branch < 2; branch++){
                const size_t child = 2 * node + static_cast<size_t>(branch);
                next_nodes[child] = ct[branch];
                next_control_bits[child] = lsb(ct[branch]);
                if (control_bits[node] == static_cast<u8>(1)){
                    next_nodes[child] = next_nodes[child] ^ key.k[level + 1];
                    next_control_bits[child] =
                        next_control_bits[child] ^ key.v[2 * level + branch];
                }
            }
        }
        std::swap(level_nodes, next_nodes);
        std::swap(control_bits, next_control_bits);
    }

    const int sign = (party - 2) ? -1 : 1;
    #pragma omp parallel for if(leaf_num >= 1024)
    for (long long i_ll = 0; i_ll < static_cast<long long>(leaf_num); i_ll++){
        const size_t i = static_cast<size_t>(i_ll);
        uint64_t converted = 0;
        two_pc_convert(key.Bout, level_nodes[i], &converted);
        res[i] = (key.g[0] * static_cast<uint64_t>(control_bits[i]) + converted) * sign;
    }

}
