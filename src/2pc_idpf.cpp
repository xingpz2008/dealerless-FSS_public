//
// Created by  邢鹏志 on 2023/1/31.
//
#include "2pc_idpf.h"

using namespace osuCrypto;

using namespace osuCrypto;
// uint64_t aes_evals_count = 0;

#define SERVER0 0
#define SERVER1 1
#define GROUP_LOOP(s)                  \
    int lp = (evalGroupIdxStart + groupSize) % groupSize;        \
    int ctr = 0;                       \
    while(ctr < evalGroupIdxLen)       \
    {                                  \
        s                              \
        lp = (lp + 1) % groupSize;     \
        ctr++;                         \
    }


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
    int lastLevelNodes = (int)pow(2, Bin);
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
        std::cout << "Idx (from lsb) = " << (int) idx[Bin - i - 1] << std::endl;
        std::cout << "Real idx " << Bin - i - 1 << "= " << (int)real_idx[Bin - i - 1];
        level_and_res = check_bit_overflow(party_id, idx[Bin - i - 1], level_and_res, peer);
        std::cout << ", level and res = " << (int)level_and_res << std::endl;
    }

    for (int i = 0; i < Bin; i++){
        std::cout << "Seed = " << s[0] << std::endl;
        std::cout << "Layer " << i << std::endl;
        block leftChildren = ZeroBlock;
        block rightChildren = ZeroBlock;

        // First step: expand all the nodes in the previous level
        // We use 128 bit as the seed, instead of 128-1 in llama
        // The seeds number is 2^i
        int expandNum = (int)pow(2, i);
        std::cout << "levelNodes=" << std::endl;
        for (int j = 0; j < expandNum; j++){
            // To expand, we first set AES enc keys, with 2^i AES instances
            AESInstance.setKey(levelNodes[j]);
            std::cout << levelNodes[j] << ", " << (int)levelControlBits[j]<< std::endl;

            // Then we call enc to get 2 blocks, as left and right child in the next level
            AESInstance.ecbEncTwoBlocks(pt, ct);

            // Test code region
            /*
            if (party_id == 2){
                ct[0] = osuCrypto::toBlock(1);
                ct[1] = osuCrypto::toBlock(2);
            }else{
                ct[0] = osuCrypto::toBlock((u64)0);
                ct[1] = osuCrypto::toBlock((u64)0);
            } */


            // Add left (resp. right) nodes together
            leftChildren = leftChildren ^ ct[0];
            rightChildren = rightChildren ^ ct[1];

            // Store Expansion results
            nextLevelNodes[2 * j] = ct[0];
            nextLevelNodes[2 * j + 1] = ct[1];
        }
        std::cout << "Expand res = " << std::endl;
        for (int j=0;j<expandNum;j++){
            std::cout << nextLevelNodes [2 * j] << ", " << (int)lsb(nextLevelNodes[2 * j]) << std::endl;
            std::cout << nextLevelNodes [2 * j + 1] << ", " << (int)lsb(nextLevelNodes[2 * j + 1]) << std::endl;
        }


        // Second step: Invoke F_MUX and retrieve reconstructed leftChildren or rightChildren
        // Selection Criterion:
        // P0 with s0l, t0l=lsb(s0l), s0r, t0r=lsb(s0r)
        // P1 with s1l, t1l=lsb(s1l), s1r, t1r=lsb(s1r)
        // if a[x] = 1, get s0, else get s1
        //std::cout << "level and res=" << (int)level_and_res << ", ";
        //uint8_t real_idx = idx[i] ^ level_and_res;
        //level_and_res = and_wrapper(party_id, real_idx, peer);
        //TODO: Add and wrapper for single non-share input
        uint8_t mux_input = real_idx[i] ^ (party_id - 2);
        // std::cout << "Pos 1 @ expand num =" << expandNum << " ,i =" << i << std::endl;
        multiplexer2(party_id, &mux_input, &leftChildren, &rightChildren, &sigma, (int32_t)1,
                     peer);
        // TODO: Realize multiplexer2
        // std::cout << "Pos 2" << std::endl;
        // Set tau, note that lsb returns <u8>
        u8 tau_0 = lsb(leftChildren) ^ real_idx[i] ^ (u8)(party_id - 2);
        u8 tau_1 = lsb(rightChildren) ^ real_idx[i];

        // Reconstruct sigma, tau
        //std::cout << "Sigma before construct = "<<sigma << std::endl;
        block recL = leftChildren;
        block recR = rightChildren;
        reconstruct(&recL);
        reconstruct(&recR);
        std::cout << "recL = "<<recL<<", recR = " << recR << std::endl;

        reconstruct(&sigma);
        //std::cout << "Sigma after construct = "<<sigma << std::endl;
        reconstruct(&tau_0);
        reconstruct(&tau_1);

        // Now we parse CW
        tau[i * 2] = tau_0;
        tau[i * 2 + 1] = tau_1;
        scw[i + 1] = sigma;

        // Third step: update seeds
        // For every seed in the level, it should xor t * this_level.CW, where t is the control bit
        // TODO: !!!!check correctness of level control bits!!!
        std::cout << "Real idx= " << (int)real_idx[i] << std::endl;
        std::cout << "left C = " << leftChildren << " right C = " << rightChildren << " sigma =" << sigma << std::endl;
        std::cout << "tau_0 = " << (int)tau_0 << " tau_1 = " << (int)tau_1 << std::endl;
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
            // levelControlBits[2 * j] = lsb(levelNodes[2 * j]);
            // levelControlBits[2 * j + 1] = lsb(levelNodes[2 * j + 1]);
        }
        for (int j = 0; j < expandNum; j++){
            // We now move updated seeds to levelNodes list
            levelNodes[2 * j] = nextLevelNodes[2 * j];
            levelNodes[2 * j + 1] = nextLevelNodes[2 * j + 1];
            // We also need to update level Control bits
            levelControlBits[2 * j] = nextLevelControlBits[2 * j];
            levelControlBits[2 * j + 1] = nextLevelControlBits[2 * j + 1];
        }
        std::cout << std::endl;
        std::cout << "Next levelNodes=" << std::endl;
        for (int j=0; j<expandNum;j++){
            std::cout << levelNodes[2*j] << ", "<< (int)levelControlBits[2*j]<< std::endl;
            std::cout << levelNodes[2*j+1] << ", "<< (int)levelControlBits[2*j+1]<< std::endl;
        }
    }


    // Last step: Calculate CW_{n+1}
    // To begin with, we add all control bits together
    uint64_t controlBitSum = 0;
    // We also need to add all Converted elements
    uint64_t lastLevelElements[lastLevelNodes];
    uint64_t lastLevelSum = 0;
    std::cout << "Last level expansion:" << std::endl;
    for (int i = 0; i < lastLevelNodes; i++){
        two_pc_convert(Bout, 1, levelNodes[i], &lastLevelElements[i]);

        // Test code region:
        /*
        switch (party_id) {
            case 2:{
                uint64_t list[4] = {10, 2, 4, 7};
                u8 bit_list[4] = {0, 1, 1, 0};
                levelControlBits[i] = bit_list[i];
                lastLevelElements[i] = list[i];
                break;
            }
            case 3:{
                uint64_t list[4] = {10, 2, 4, 13};
                u8 bit_list[4] = {0, 1, 1, 1};
                levelControlBits[i] = bit_list[i];
                lastLevelElements[i] = list[i];
                break;
            }
        } */

        lastLevelSum = lastLevelSum + lastLevelElements[i];
        controlBitSum = controlBitSum + (uint64_t)levelControlBits[i];
        std::cout << levelNodes[i] << ", " << (int)levelControlBits[i] << ", " << lastLevelElements[i];
        std::cout << ", CtrlBitSum = " << (int)controlBitSum << ", LevelSum = " << lastLevelSum << std::endl;
    }
    // Get last 2 bits of bits sum to compare
    u8 cmp_tau_0 = (u8)(controlBitSum & 1);
    u8 cmp_tau_1 = (u8)((controlBitSum >> 1) & 1);
    // Calculate [t]
    // TODO: ADD F_AND here
    // The first input is high order bit, latter is lower order bit.
    u8 t = cmp_2bit(party_id, cmp_tau_1, cmp_tau_0, peer);
    std::cout << "Cmp 2 bit res = " << (int)t << std::endl;

    GroupElement sign(((party_id-2) == 1) ? 1 : -1, Bout);
    // Sign = -1 for p1, 1 for p0
    GroupElement W_CW_0 = payload + lastLevelSum * sign;
    GroupElement W_CW_1 = -payload + lastLevelSum * (-sign);
    std::cout << "WCW: 0 = " << W_CW_0.value << ", 1 = " << W_CW_1.value << std::endl;
    auto* W_CW = new GroupElement(0, Bout);

    // TODO: Add mux2 here
    //multiplexer2(party_id, &t, &W_CW_0, &W_CW_1, W_CW, 1, peer);
    multiplexer2(party_id, &t, &W_CW_0, &W_CW_1, W_CW, 1, peer);
    std::cout << "WCW after MUX = " << W_CW->value << std::endl;

    // (party_id-1)==1?server:client

    reconstruct(W_CW);
    std::cout << "WCW = " << W_CW->value << std::endl;

    //Free space
    delete[] levelNodes;
    delete[] nextLevelNodes;
    delete[] nextLevelControlBits;
    delete[] levelControlBits;

    // in DPF, swc is the seed for each level from root level, W_CW is to help convert output from Z_2 to Z_n
    return {Bin, Bout, 1, scw, W_CW, tau, mask};
}



DPFKeyPack keyGeniDPF(int party_id, int Bin, int Bout,
                     GroupElement idx, GroupElement* payload, bool call_from_DCF, bool masked)
{
    // This is the 2pc generation of iDPF Key, proceed with multiple payload
    std::cout << "==========iDPF Gen==========" << std::endl;
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

    // Variants for iDPF CW calculation
    uint64_t levelElements[lastLevelNodes];
    GroupElement W_CW[Bin];
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
            std::cout << "Idx (from lsb) = " << (int) idx[Bin - i - 1] << std::endl;
            std::cout << "Real idx " << Bin - i - 1 << "= " << (int)real_idx[Bin - i - 1];
            level_and_res = check_bit_overflow(party_id, idx[Bin - i - 1], level_and_res, peer);
            std::cout << ", level and res = " << (int)level_and_res << std::endl;
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
        //u8 real_idx = idx[i] ^ level_and_res;
        //level_and_res = and_wrapper(party_id, real_idx, peer);
        uint8_t mux_input = real_idx[i] ^ (party_id-2);
        block* sigma = new block;
        multiplexer2(party_id, &mux_input, &leftChildren, &rightChildren, sigma,
                     (int32_t)1, peer);
        // TODO: Realize multiplexer2

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
        uint64_t levelSum = 0;
        // We also need to add all Converted elements
        for (int j = 0; j < 2 * expandNum; j++){
            two_pc_convert(Bout, &levelNodes[j], &levelElements[j], &levelNodes[j]);
            levelSum = levelSum + levelElements[j];
            controlBitSum = controlBitSum + (uint64_t)levelControlBits[j];
        }
        // Get last 2 bits of bits sum to compare
        u8 cmp_tau_0 = (u8)(controlBitSum & 1);
        u8 cmp_tau_1 = (u8)((controlBitSum >> 1) & 1);
        // Calculate [t]
        // TODO: ADD F_AND here, Correct?
        u8 t = cmp_2bit(party_id, cmp_tau_1, cmp_tau_0, peer);
        GroupElement sign(((party_id-2) == 1) ? 1 : -1, Bout);
        // Sign = -1 for p1, 1 for p0
        GroupElement W_CW_0 = payload[i] + levelSum * sign;
        GroupElement W_CW_1 = -payload[i] + levelSum * -sign;

        // TODO: Add mux2 here
        multiplexer2(party_id, &t, &W_CW_0, &W_CW_1, &W_CW[i], (int32_t)1, peer);
        reconstruct((int32_t)1, &W_CW[i], Bout);
    }

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
    std::cout << "==========iDPF Gen==========" << std::endl;
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

    // Variants for iDPF CW calculation
    uint64_t levelElements[lastLevelNodes];
    GroupElement W_CW[Bin];

    for (int i = 0; i < Bin; i++){
        W_CW[i].bitsize = Bout;
    }

    // Preparing random mask
    GroupElement* mask = new GroupElement(0, Bin);
    assert(masked == false);
    /*
    if (masked){
        auto mask_s = prng.get<int>();
        mask->value = mask_s;
        idx = idx + *mask;
    } */

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
            std::cout << "Idx (from lsb) = " << (int) idx[Bin - i - 1] << std::endl;
            std::cout << "Real idx " << Bin - i - 1 << "= " << (int)real_idx[Bin - i - 1];
            level_and_res = check_bit_overflow(party_id, idx[Bin - i - 1], level_and_res, peer);
            std::cout << ", level and res = " << (int)level_and_res << std::endl;
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
        //u8 real_idx = idx[i] ^ level_and_res;
        //level_and_res = and_wrapper(party_id, real_idx, peer);
        uint8_t mux_input = real_idx[i] ^ (party_id-2);
        block* sigma = new block;
        multiplexer2(party_id, &mux_input, &leftChildren, &rightChildren, sigma,
                     (int32_t)1, peer);
        // TODO: Realize multiplexer2

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
        uint64_t levelSum = 0;
        // We also need to add all Converted elements
        for (int j = 0; j < 2 * expandNum; j++){
            two_pc_convert(Bout, &levelNodes[j], &levelElements[j], &levelNodes[j]);
            levelSum = levelSum + levelElements[j];
            controlBitSum = controlBitSum + (uint64_t)levelControlBits[j];
        }
        // Get last 2 bits of bits sum to compare
        u8 cmp_tau_0 = (u8)(controlBitSum & 1);
        u8 cmp_tau_1 = (u8)((controlBitSum >> 1) & 1);
        // Calculate [t]
        // TODO: ADD F_AND here, Correct?
        u8 t = cmp_2bit(party_id, cmp_tau_1, cmp_tau_0, peer);
        GroupElement sign(((party_id-2) == 1) ? 1 : -1, Bout);
        // Sign = -1 for p1, 1 for p0
        GroupElement W_CW_0 = payload[i] + levelSum * sign;
        GroupElement W_CW_1 = -payload[i] + levelSum * -sign;

        // TODO: Add mux2 here
        std::cout <<"Payload Bit size = " << payload[i].bitsize << " W_CW_0 / 1 .bitsize = " << W_CW_0.bitsize << ", " << W_CW_1.bitsize << std::endl;
        multiplexer2(party_id, &t, &W_CW_0, &W_CW_1, &W_CW[i], (int32_t)1, peer);
        reconstruct((int32_t)1, &W_CW[i], Bout);
    }

    //Free space
    delete[] levelNodes;
    delete[] nextLevelNodes;
    delete[] nextLevelControlBits;
    delete[] levelControlBits;

    return {Bin, Bout, 1, scw, W_CW, tau, mask};
}

void evalDPF(int party, GroupElement *res, GroupElement idx, const DPFKeyPack &key, bool masked){
    // Eval of 2pc-dpf
    // Initialize with the root node
    std::cout << "==========Eval==========" << std::endl;
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
        std::cout << "Current level nodes : " << std::endl;
        std::cout << levelNodes << ", " << (int)controlBit << std::endl;
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
        std::cout << "Next level nodes : " << levelNodes << ", " << (int)controlBit << std::endl;
    }

    // At the final stage, we make the convert from output in Z_2 to Z_n
    int sign = (party - 2) ? -1 : 1;
    uint64_t* convert_res = new uint64_t;
    two_pc_convert(Bout, levelNodes, convert_res);

    // test code region
    /*
    switch (party) {
        case 2:{
            controlBit = (u8)0;
            *convert_res = 7;
            break;
        }
        case 3:{
            controlBit = (u8)1;
            *convert_res = 13;
            break;
        }
    }
     */
    std::cout << "Converted = " << *convert_res << std::endl;
    std::cout << "WCW = " << wcw[0].value << std::endl;
    res[0] = (wcw[0] * (uint64_t) controlBit + *convert_res) * sign;

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
    int groupSize = key.groupSize;
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
    return;
}