/*
 * Description:
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

using namespace osuCrypto;

inline int bytesize(const int bitsize) {
    return (bitsize % 8) == 0 ? bitsize / 8 : (bitsize / 8)  + 1;
}

void two_pc_convert(const int bitsize, const int groupSize, const block &b, uint64_t *out)
{
    static const block notThreeBlock = osuCrypto::toBlock((u64)~0, (u64)~3);
    const int bys = bytesize(bitsize);
    const int totalBys = bys * groupSize;
    if (bys * groupSize <= 16) {
        uint8_t *bptr = (uint8_t *)&b;
        for(int i = 0; i < groupSize; i++) {
            out[i] = *(uint64_t *)(bptr + i * bys);
        }
    }
    else {
        int numblocks = totalBys % 16 == 0 ? totalBys / 16 : (totalBys / 16) + 1;
        AES aes(b);
        block pt[numblocks];
        block ct[numblocks];
        for(int i = 0; i < numblocks; i++) {
            pt[i] = osuCrypto::toBlock(0, i);
        }
        aes.ecbEncBlocks(pt, numblocks, ct);
        uint8_t *bptr = (uint8_t *)ct;
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
        uint8_t *bptr = (uint8_t *)&b;
        *out = *(uint64_t *)(bptr);
    }
    else {
        int numblocks = totalBys % 16 == 0 ? totalBys / 16 : (totalBys / 16) + 1;
        AES aes(b);
        block pt[numblocks];
        block ct[numblocks];
        for(int i = 0; i < numblocks; i++) {
            pt[i] = osuCrypto::toBlock(0, i);
        }
        aes.ecbEncBlocks(pt, numblocks, ct);
        uint8_t *bptr = (uint8_t *)ct;
        *out = *(uint64_t *)(bptr);
    }
}

void two_pc_convert(int bitsize, block *b, uint64_t *out, block* out_s){
    // Implementation of iDPF convert in Lightweight Techniques for Private Heavy Hitter
    const int bys = bytesize(bitsize);
    const int totalBys = bys;

    int numblocks = totalBys % 16 == 0 ? totalBys / 16 : (totalBys / 16) + 1;
    const block _b = *b;
    AES aes(_b);
    block pt[numblocks];
    block ct[numblocks];
    for(int i = 0; i < numblocks; i++) {
        pt[i] = osuCrypto::toBlock(0, i);
    }
    aes.ecbEncBlocks(pt, numblocks, ct);
    uint8_t *bptr = (uint8_t *)ct;
    *out = *(uint64_t *)(bptr);
    *out_s = *ct;
}


DPFKeyPack keyGenDPF(int party_id, int Bin, int Bout,
                     GroupElement idx, GroupElement payload, bool masked)
{
    // Here payload should be the same bit length with b out
    static const block notOneBlock = osuCrypto::toBlock(~0, ~1);
    static const block notThreeBlock = osuCrypto::toBlock(~0, ~3);
    const static block pt[2] = {ZeroBlock, OneBlock};

    // Here we initialize the first block as the root node
    prng.SetSeed(osuCrypto::toBlock(party_id, time(NULL)));
    auto s = prng.get<std::array<block, 1>>();
    // We maintain a list of seeds, which indicates the nodes on i-th level
    // We directly request the largest amount of storage, as 2^Bin,
    int lastLevelNodes = 1 << Bin;
    auto* levelNodes = new block[lastLevelNodes];
    auto* nextLevelNodes = new block[lastLevelNodes];
    auto* nextLevelControlBits = new u8[lastLevelNodes];
    u8* levelControlBits = new u8[lastLevelNodes];

    block ct[2];
    AES AESInstance;
    levelNodes[0] = s[0];
    levelControlBits[0] = (u8)(party_id-2);

    // Variants in this area indicates generation results -> DPFKeyPack
    u8* tau = new u8[Bin * 2];
    auto* scw = new block[Bin + 1];
    scw[0] = s[0];
    block sigma;

    // Create mask
    GroupElement* mask = new GroupElement(0, Bin);
    if (masked){
        auto mask_s = prng.get<int>();
        mask->value = mask_s;
        idx = idx + *mask;
    }

    u8* real_idx = new u8[Bin];
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
        int expandNum = (int)pow(2, i);
        for (int j = 0; j < expandNum; j++){
            // To expand, we first set AES enc keys, with 2^i AES instances
            AESInstance.setKey(levelNodes[j]);
            std::cout << levelNodes[j] << ", " << (int)levelControlBits[j]<< std::endl;

            // Then we call enc to get 2 blocks, as left and right child in the next level
            AESInstance.ecbEncTwoBlocks(pt, ct);

            // Add left (resp. right) nodes together
            leftChildren = leftChildren ^ ct[0];
            rightChildren = rightChildren ^ ct[1];

            // Store Expansion results
            nextLevelNodes[2 * j] = ct[0];
            nextLevelNodes[2 * j + 1] = ct[1];
        }

        // Second step: Invoke F_MUX and retrieve reconstructed leftChildren or rightChildren
        // Selection Criterion:
        // P0 with s0l, t0l=lsb(s0l), s0r, t0r=lsb(s0r)
        // P1 with s1l, t1l=lsb(s1l), s1r, t1r=lsb(s1r)
        // if a[x] = 1, get s0, else get s1
        //TODO: Add and wrapper for single non-share input
        uint8_t mux_input = real_idx[i] ^ (party_id - 2);
        multiplexer2(party_id, &mux_input, &leftChildren, &rightChildren, &sigma, (int32_t)1,
                     peer);
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
        for (int j = 0; j < expandNum; j++){
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
        for (int j = 0; j < expandNum; j++){
            // We now move updated seeds to levelNodes list
            levelNodes[2 * j] = nextLevelNodes[2 * j];
            levelNodes[2 * j + 1] = nextLevelNodes[2 * j + 1];
            // We also need to update level Control bits
            levelControlBits[2 * j] = nextLevelControlBits[2 * j];
            levelControlBits[2 * j + 1] = nextLevelControlBits[2 * j + 1];
        }
    }


    // Last step: Calculate CW_{n+1}
    // To begin with, we add all control bits together
    uint64_t controlBitSum = 0;
    // We also need to add all Converted elements
    uint64_t lastLevelElements[lastLevelNodes];
    uint64_t lastLevelSum = 0;
    for (int i = 0; i < lastLevelNodes; i++){
        two_pc_convert(Bout, 1, levelNodes[i], &lastLevelElements[i]);

        lastLevelSum = lastLevelSum + lastLevelElements[i];
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
    auto* W_CW = new GroupElement(0, Bout);

    multiplexer2(party_id, &t, &W_CW_0, &W_CW_1, W_CW, 1, peer);

    reconstruct(W_CW);

    //Free space
    delete[] levelNodes;
    delete[] nextLevelNodes;
    delete[] nextLevelControlBits;
    delete[] levelControlBits;
    delete[] real_idx;

    // in DPF, swc is the seed for each level from root level, W_CW is to help convert output from Z_2 to Z_n
    return {Bin, Bout, 1, scw, W_CW, tau, mask};
}



DPFKeyPack keyGeniDPF(int party_id, int Bin, int Bout,
                     GroupElement idx, GroupElement* payload, bool call_from_DCF, bool masked)
{
    // This is the 2pc generation of iDPF Key, proceed with multiple payload
    static const block notOneBlock = osuCrypto::toBlock(~0, ~1);
    static const block notThreeBlock = osuCrypto::toBlock(~0, ~3);
    const static block pt[2] = {ZeroBlock, OneBlock};

    // Here we initialize the first block as the root node
    prng.SetSeed(osuCrypto::toBlock(party_id, time(NULL)));
    auto s = prng.get<block>();
    // We maintain a list of seeds, which indicates the nodes on i-th level
    // We directly request the largest amount of storage, as 2^Bin,
    int lastLevelNodes = (int)pow(2, Bin);
    block* levelNodes = new block[lastLevelNodes];
    block* nextLevelNodes = new block[lastLevelNodes];
    u8* levelControlBits = new u8[lastLevelNodes];
    auto* nextLevelControlBits = new u8[lastLevelNodes];

    block ct[2];
    AES AESInstance;
    levelNodes[0] = s;
    levelControlBits[0] = (u8)(party_id-2);

    // Variants in this area indicates generation results -> DPFKeyPack
    u8* tau = new u8[Bin * 2];
    block* scw = new block[Bin + 1];
    scw[0] = s;

    GroupElement W_CW_0[Bin];
    GroupElement W_CW_1[Bin];
    u8 t[Bin];
    u8 cmp_tau_0[Bin], cmp_tau_1[Bin];
    uint64_t levelSum[Bin];
    for (int i = 0; i < Bin; i++){
        levelSum[i] = 0;
    }

    // Variants for iDPF CW calculation
    uint64_t levelElements[lastLevelNodes];
    GroupElement* W_CW = new GroupElement[Bin];
    for (int i = 0; i < Bin; i++){
        W_CW[i].bitsize = Bout;
    }

    // Preparing random mask
    GroupElement* mask = new GroupElement(0, Bin);
    if (masked){
        auto mask_s = prng.get<int>();
        mask->value = mask_s;
        idx = idx + *mask;
    }

    // Step 0: prepare for the DigDec decomposition of x from msb to lsb
    // Particularly, we construct from lsb to msb, then reverse it.
    u8* real_idx = new u8[Bin];
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
        int expandNum = (int)pow(2, i);
        for (int j = 0; j < expandNum; j++){
            // To expand, we first set AES enc keys, with 2^i AES instances
            AESInstance.setKey(levelNodes[j]);

            // Then we call enc to get 2 blocks, as left and right child in the next level
            AESInstance.ecbEncTwoBlocks(pt, ct);

            // Add left (resp. right) nodes together
            leftChildren = leftChildren ^ ct[0];
            rightChildren = rightChildren ^ ct[1];

            // Store Expansion results
            nextLevelNodes[2 * j] = ct[0];
            nextLevelNodes[2 * j + 1] = ct[1];
        }

        // Second step: Invoke F_MUX and retrieve reconstructed leftChildren or rightChildren
        // Selection Criterion:
        // P0 with s0l, t0l=lsb(s0l), s0r, t0r=lsb(s0r)
        // P1 with s1l, t1l=lsb(s1l), s1r, t1r=lsb(s1r)
        // if a[x] = 1, get s0, else get s1
        uint8_t mux_input = real_idx[i] ^ (party_id-2);
        block* sigma = new block;
        multiplexer2(party_id, &mux_input, &leftChildren, &rightChildren, sigma,
                     (int32_t)1, peer);

        // Set tau, note that lsb returns <u8>
        u8 tau_0 = lsb(leftChildren) ^ real_idx[i] ^ (u8)(party_id - 2);
        u8 tau_1 = lsb(rightChildren) ^ real_idx[i];

        // Reconstruct sigma, tau
        reconstruct(sigma);
        reconstruct(&tau_0);
        reconstruct(&tau_1);

        // Now we parse CW
        tau[i * 2] = tau_0;
        tau[i * 2 + 1] = tau_1;
        scw[i + 1] = *sigma;

        // Third step: update seeds
        // For every seed in the level, it should xor t * this_level.CW, where t is the control bit
        for (int j = 0; j < expandNum; j++){
            nextLevelControlBits[2 * j] = lsb(nextLevelNodes[2 * j]);
            nextLevelControlBits[2 * j + 1] = lsb(nextLevelNodes[2 * j + 1]);
            if (levelControlBits[j] == (u8)1) {
                nextLevelNodes[2 * j] = nextLevelNodes[2 * j] ^ scw[i + 1];
                nextLevelNodes[2 * j + 1] = nextLevelNodes[2 * j + 1] ^ scw[i + 1];
                nextLevelControlBits[2 * j] = nextLevelControlBits[2 * j] ^ tau_0;
                nextLevelControlBits[2 * j + 1] = nextLevelControlBits[2 * j + 1] ^ tau_1;
            }
        }

        for (int j = 0; j < expandNum; j++){
            // We now move updated seeds to levelNodes list
            levelNodes[2 * j] = nextLevelNodes[2 * j];
            levelNodes[2 * j + 1] = nextLevelNodes[2 * j + 1];
            // We also need to update level Control bits
            levelControlBits[2 * j] = nextLevelControlBits[2 * j];
            levelControlBits[2 * j + 1] = nextLevelControlBits[2 * j + 1];
        }

        // Forth Step: calculate layer-wise CW
        // To begin with, we add all control bits together
        uint64_t controlBitSum = 0;

        // We also need to add all Converted elements
        for (int j = 0; j < 2 * expandNum; j++){
            two_pc_convert(Bout, &levelNodes[j], &levelElements[j], &levelNodes[j]);
            levelSum[i] = levelSum[i] + levelElements[j];
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
    cmp_2bit_opt(party_id, cmp_tau_1, cmp_tau_0, t, Bin, peer);
    multiplexer2(party_id, t, W_CW_0, W_CW_1, W_CW, (int32_t)Bin, peer);
    reconstruct((int32_t)Bin, W_CW, Bout);

    //Free space
    delete[] levelNodes;
    delete[] nextLevelNodes;
    delete[] nextLevelControlBits;
    delete[] levelControlBits;

    return {Bin, Bout, 1, scw, W_CW, tau, mask};
}

DPFKeyPack keyGeniDPF(int party_id, int Bin, int Bout,
                      u8* idx, GroupElement* payload, bool call_from_DCF, bool masked)
{
    // This is the 2pc generation of iDPF Key, proceed with multiple payload
    static const block notOneBlock = osuCrypto::toBlock(~0, ~1);
    static const block notThreeBlock = osuCrypto::toBlock(~0, ~3);
    const static block pt[2] = {ZeroBlock, OneBlock};

    // Here we initialize the first block as the root node
    prng.SetSeed(osuCrypto::toBlock(party_id, time(NULL)));
    auto s = prng.get<block>();
    // We maintain a list of seeds, which indicates the nodes on i-th level
    // We directly request the largest amount of storage, as 2^Bin,
    int lastLevelNodes = (int)pow(2, Bin);
    block* levelNodes = new block[lastLevelNodes];
    block* nextLevelNodes = new block[lastLevelNodes];
    u8* levelControlBits = new u8[lastLevelNodes];
    auto* nextLevelControlBits = new u8[lastLevelNodes];

    block ct[2];
    AES AESInstance;
    levelNodes[0] = s;
    levelControlBits[0] = (u8)(party_id-2);

    // Variants in this area indicates generation results -> DPFKeyPack
    u8* tau = new u8[Bin * 2];
    block* scw = new block[Bin + 1];
    scw[0] = s;
    GroupElement W_CW_0[Bin];
    GroupElement W_CW_1[Bin];
    u8 t[Bin];
    u8 cmp_tau_0[Bin], cmp_tau_1[Bin];
    uint64_t levelSum[Bin];

    // Variants for iDPF CW calculation
    uint64_t levelElements[lastLevelNodes];
    GroupElement* W_CW = new GroupElement[Bin];

    for (int i = 0; i < Bin; i++){
        W_CW[i].bitsize = Bout;
        levelSum[i] = 0;
    }

    // Preparing random mask
    GroupElement* mask = new GroupElement(0, Bin);
    assert(masked == false);

    // Step 0: prepare for the DigDec decomposition of x from msb to lsb
    // Particularly, we construct from lsb to msb, then reverse it.
    u8* real_idx = new u8[Bin];
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
        int expandNum = (int)pow(2, i);
        for (int j = 0; j < expandNum; j++){
            // To expand, we first set AES enc keys, with 2^i AES instances
            AESInstance.setKey(levelNodes[j]);

            // Then we call enc to get 2 blocks, as left and right child in the next level
            AESInstance.ecbEncTwoBlocks(pt, ct);

            // Add left (resp. right) nodes together
            leftChildren = leftChildren ^ ct[0];
            rightChildren = rightChildren ^ ct[1];

            // Store Expansion results
            nextLevelNodes[2 * j] = ct[0];
            nextLevelNodes[2 * j + 1] = ct[1];
        }

        // Second step: Invoke F_MUX and retrieve reconstructed leftChildren or rightChildren
        // Selection Criterion:
        // P0 with s0l, t0l=lsb(s0l), s0r, t0r=lsb(s0r)
        // P1 with s1l, t1l=lsb(s1l), s1r, t1r=lsb(s1r)
        // if a[x] = 1, get s0, else get s1
        uint8_t mux_input = real_idx[i] ^ (party_id-2);
        block* sigma = new block;
        multiplexer2(party_id, &mux_input, &leftChildren, &rightChildren, sigma,
                     (int32_t)1, peer);

        // Set tau, note that lsb returns <u8>
        u8 tau_0 = lsb(leftChildren) ^ real_idx[i] ^ (u8)(party_id - 2);
        u8 tau_1 = lsb(rightChildren) ^ real_idx[i];

        // Reconstruct sigma, tau
        reconstruct(sigma);
        reconstruct(&tau_0);
        reconstruct(&tau_1);

        // Now we parse CW
        tau[i * 2] = tau_0;
        tau[i * 2 + 1] = tau_1;
        scw[i + 1] = *sigma;

        // Third step: update seeds
        // For every seed in the level, it should xor t * this_level.CW, where t is the control bit
        for (int j = 0; j < expandNum; j++){
            nextLevelControlBits[2 * j] = lsb(nextLevelNodes[2 * j]);
            nextLevelControlBits[2 * j + 1] = lsb(nextLevelNodes[2 * j + 1]);
            if (levelControlBits[j] == (u8)1) {
                nextLevelNodes[2 * j] = nextLevelNodes[2 * j] ^ scw[i + 1];
                nextLevelNodes[2 * j + 1] = nextLevelNodes[2 * j + 1] ^ scw[i + 1];
                nextLevelControlBits[2 * j] = nextLevelControlBits[2 * j] ^ tau_0;
                nextLevelControlBits[2 * j + 1] = nextLevelControlBits[2 * j + 1] ^ tau_1;
            }
        }

        for (int j = 0; j < expandNum; j++){
            // We now move updated seeds to levelNodes list
            levelNodes[2 * j] = nextLevelNodes[2 * j];
            levelNodes[2 * j + 1] = nextLevelNodes[2 * j + 1];
            // We also need to update level Control bits
            levelControlBits[2 * j] = nextLevelControlBits[2 * j];
            levelControlBits[2 * j + 1] = nextLevelControlBits[2 * j + 1];
        }

        // Forth Step: calculate layer-wise CW
        // To begin with, we add all control bits together
        uint64_t controlBitSum = 0;
        // We also need to add all Converted elements
        for (int j = 0; j < 2 * expandNum; j++){
            two_pc_convert(Bout, &levelNodes[j], &levelElements[j], &levelNodes[j]);
            levelSum[i] = levelSum[i] + levelElements[j];
            controlBitSum = controlBitSum + (uint64_t)levelControlBits[j];
        }
        // Get last 2 bits of bits sum to compare
        cmp_tau_0[i] = (u8)(controlBitSum & 1);
        cmp_tau_1[i] = (u8)((controlBitSum >> 1) & 1);
    }
    // Calculate [t]
    cmp_2bit_opt(party_id, cmp_tau_1, cmp_tau_0, t, Bin, peer);
    GroupElement sign(((party_id-2) == 1) ? 1 : -1, Bout);
    // Sign = -1 for p1, 1 for p0
    for (int i = 0; i < Bin; i++){
        W_CW_0[i] = payload[i] + levelSum[i] * sign;
        W_CW_1[i] = -payload[i] + levelSum[i] * -sign;
    }
    multiplexer2(party_id, t, W_CW_0, W_CW_1, W_CW, (int32_t)Bin, peer);
    reconstruct((int32_t)Bin, W_CW, Bout);

    //Free space, W_CW not free
    delete[] levelNodes;
    delete[] nextLevelNodes;
    delete[] nextLevelControlBits;
    delete[] levelControlBits;

    return {Bin, Bout, 1, scw, W_CW, tau, mask};
}

void evalDPF(int party, GroupElement *res, GroupElement idx, const DPFKeyPack &key, bool masked){
    // Eval of 2pc-dpf
    // Initialize with the root node
    osuCrypto::AES AESInstance;

    // Parse DCF Key
    // in DPF, swc is the seed for each level from root level, W_CW is to help convert output from Z_2 to Z_n
    int Bin = key.Bin;
    int Bout = key.Bout;
    int groupSize = key.groupSize;
    block* scw = key.k;
    GroupElement* wcw = key.g;
    u8* tau = key.v;
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
    uint64_t* convert_res = new uint64_t;
    two_pc_convert(Bout, levelNodes, convert_res);

    res[0] = (wcw[0] * (uint64_t) controlBit + *convert_res) * sign;

    delete convert_res;

    return;
}

void evaliDPF(int party, GroupElement *res, GroupElement idx, const DPFKeyPack &key, bool masked){
    // Eval of 2pc-dpf
    // Initialize with the root node
    // The difference between dpf and idpf are to expand CW at each level
    osuCrypto::AES AESInstance;

    // Parse DCF Key
    // in DPF, swc is the seed for each level from root level, W_CW is to help convert output from Z_2 to Z_n
    int Bin = key.Bin;
    int Bout = key.Bout;
    block* scw = key.k;
    GroupElement* wcw = key.g;
    u8* tau = key.v;
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
    uint64_t* convert_res = new uint64_t;

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
        two_pc_convert(Bout, &levelNodes, convert_res, &levelNodes);
        res[i] = (wcw[i] * (uint64_t) controlBit + *convert_res) * sign;
    }
    delete convert_res;
    return;
}

void evalDPF(int party, GroupElement *res, GroupElement *idx, DPFKeyPack *keyList, int size, int max_bitsize){
    int Bin[size];
    int Bout[size];
    block* scw[size];
    GroupElement* wcw[size];
    u8* tau[size];
    GroupElement mask[size];
    block levelNodes[size];
    u8 controlBit[size];
    u8 level_tau[size];
    static const block notOneBlock = osuCrypto::toBlock(~0, ~1);
    static const block notThreeBlock = osuCrypto::toBlock(~0, ~3);
    const static block pt[2] = {ZeroBlock, OneBlock};
    // Maybe call ecbEncBlocks
    osuCrypto::AES AESInstances[size];
    block ct[2 * size];
    block levelCW[size];
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
#pragma omp critical
            {
                AESInstances[j].setKey(levelNodes[j]);
                AESInstances[j].ecbEncTwoBlocks(pt, ct + 2 * j * sizeof(block));
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
    }


    int sign = (party - 2) ? -1 : 1;
    uint64_t convert_res[size];
    for (int i = 0; i < size; i++){
        two_pc_convert(Bout[i], levelNodes[i], &convert_res[i]);
        res[i] = (wcw[i][0] * (uint64_t) controlBit[i] + convert_res[i]) * sign;
    }

    return;
}

void evalAll(int party, GroupElement* res, DPFKeyPack key, int length){
    // This is the implementation of all domain evaluation for evalAll
    // The optimization is that we do not have to compute the same PRG twice
    GroupElement mask = *(key.random_mask);
    // We first allocate memory for PRG dict, that is 2^n+1 - 1
    int blockNum = (1 << (length + 1)) - 1;
    block* dict[blockNum];
    for (int i = 0; i < blockNum; i++){
        dict[i] = NULL;
    }
    int evalNum = 1 << length;

    // Parse from key
    GroupElement real_input(0, length);
    block* scw = key.k;
    GroupElement* wcw = key.g;
    u8* tau = key.v;
    block levelNodes;
    u8 controlBit;
    u8 level_tau;
    static const block notOneBlock = osuCrypto::toBlock(~0, ~1);
    static const block notThreeBlock = osuCrypto::toBlock(~0, ~3);
    const static block pt[2] = {ZeroBlock, OneBlock};
    block ct[2];
    osuCrypto::AES AESInstance;
    int Bin = key.Bin;
    int Bout = key.Bout;
    int dict_iterator;
    int sign = (party - 2) ? -1 : 1;
    uint64_t* convert_res = new uint64_t;

    for (int i = 0; i < evalNum; i++){
        levelNodes = scw[0];
        controlBit = (u8)(party - 2);
        level_tau = controlBit;
        // Considering the usage in our work, we do not need the real input to add mask
        real_input = i;
        dict_iterator = 0;
        for (int j = 0; j < Bin; j++){
            dict_iterator += (real_input[j] << j);
            if (dict[dict_iterator] == NULL){
                AESInstance.setKey(levelNodes);
                AESInstance.ecbEncTwoBlocks(pt, ct);
                dict[dict_iterator] = new block[2];
                dict[dict_iterator][0] = ct[0];
                dict[dict_iterator][1] = ct[1];
            }else{
                ct[0] = dict[dict_iterator][0];
                ct[1] = dict[dict_iterator][1];
            }
            block levelCW = scw[j + 1];
            level_tau = tau[2 * j + (int)(real_input[j])];
            if (controlBit == (u8)1){
                levelNodes = ct[(int)(real_input[j])] ^  levelCW;
                controlBit = lsb(ct[(int)(real_input[j])]) ^ level_tau;
            }else{
                levelNodes = ct[(int)(real_input[j])];
                controlBit = lsb(ct[(int)(real_input[j])]);
            }
        }
        two_pc_convert(Bout, levelNodes, convert_res);
        res[i] = (wcw[0] * (uint64_t) controlBit + *convert_res) * sign;
    }
    // Free all space
    for (int i = 0; i < blockNum; i++){
        delete[] dict[i];
    }
    delete convert_res;
}