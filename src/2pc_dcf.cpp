//
// Created by  邢鹏志 on 2023/1/31.
//

#include "2pc_dcf.h"

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

DPFKeyPack keyGeniDCF(int party_id, int Bin, int Bout,
                      GroupElement idx, GroupElement* payload)
{
    // This is the 2pc generation of DCF Key, proceed with multiple payload
    // The diff between DCF and iDPF is that:
    // 1. the length of n change to n-1
    // 2. payload from beta2 to beta_n
    // 3. real beta have to be determined using mux
    static const block notOneBlock = osuCrypto::toBlock(~0, ~1);
    static const block notThreeBlock = osuCrypto::toBlock(~0, ~3);
    const static block pt[2] = {ZeroBlock, OneBlock};

    // Here we initialize the first block as the root node
    auto s = prng.get<block>();
    // We maintain a list of seeds, which indicates the nodes on i-th level
    // We directly request the largest amount of storage, as 2^Bin,
    int lastLevelNodes = (int)pow(2, Bin);
    block* levelNodes = new block[lastLevelNodes];
    block* nextLevelNodes = new block[lastLevelNodes];
    u8* levelControlBits = new u8[lastLevelNodes];

    block ct[2];
    AES AESInstance;
    levelNodes[0] = s;
    levelControlBits[0] = (u8)(party_id-2);
    u8 level_and_res = 0;
    GroupElement zero_payload = payload[0];
    zero_payload.value = 0;

    // Variants in this area indicates generation results -> DPFKeyPack
    u8* tau = new u8[Bin * 2];
    block* scw = new block[Bin + 1];
    scw[0] = s;

    // Variants for iDPF CW calculation
    uint64_t levelElements[lastLevelNodes];
    GroupElement W_CW[Bin];
    W_CW[0] = payload[0];

    for (int i = 0; i < Bin - 1; i++){

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
        // real idx is the share of index
        u8 real_idx = idx[i] ^ level_and_res;
        level_and_res = and_wrapper(party_id, real_idx, peer);
        uint8_t mux_input = real_idx ^ (party_id-2);
        block* sigma = new block;
        multiplexer2(party_id, &mux_input, &leftChildren, &rightChildren, sigma,
                     (int32_t)1, peer);
        // TODO: Realize multiplexer2

        // Set tau, note that lsb returns <u8>
        u8 tau_0 = lsb(leftChildren) ^ real_idx ^ (u8)(party_id - 2);
        u8 tau_1 = lsb(rightChildren) ^ real_idx;

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
            if (levelControlBits[j] == (u8)1) {
                nextLevelNodes[2 * j] = nextLevelNodes[2 * j] ^ scw[i];
                nextLevelNodes[2 * j + 1] = nextLevelNodes[2 * j + 1] ^ scw[i];
            }
            // We now move updated seeds to levelNodes list
            levelNodes[2 * j] = nextLevelNodes[2 * j];
            levelNodes[2 * j + 1] = nextLevelNodes[2 * j + 1];
            // We also need to update level Control bits
            levelControlBits[2 * j] = lsb(levelNodes[2 * j]);
            levelControlBits[2 * j + 1] = lsb(levelNodes[2 * j + 1]);
        }

        // Forth Step: calculate layer-wise CW
        // To begin with, we add all control bits together
        uint64_t controlBitSum = 0;
        GroupElement levelSum = GroupElement(0, Bout);
        // We also need to add all Converted elements
        for (int j = 0; j < 2 * expandNum; j++){
            two_pc_convert(Bout, levelNodes[j], &levelElements[j], &levelNodes[j]);
            levelSum = levelSum + levelElements[j];
            controlBitSum = controlBitSum + (uint64_t)levelControlBits[j];
        }
        // Get last 2 bits of bits sum to compare
        u8 cmp_tau_0 = (u8)(controlBitSum & 1);
        u8 cmp_tau_1 = (u8)((controlBitSum >> 1) & 1);
        // Calculate [t]
        // TODO: ADD F_AND here, Correct?
        u8 t = and_wrapper(party_id, cmp_tau_0, cmp_tau_1, peer);
        GroupElement sign(((party_id-1) == 1) ? -1 : +1, Bout);
        // Sign = -1 for p1, 1 for p0
        GroupElement real_payload;
        multiplexer2(party_id, &real_idx, &zero_payload, &payload[i + 1],
                     &real_payload, 1, peer);
        GroupElement W_CW_0 = real_payload + levelSum * (-sign);
        GroupElement W_CW_1 = real_payload + levelSum * sign;

        // TODO: Add mux2 here
        multiplexer2(party_id, &t, &W_CW_0, &W_CW_1, &W_CW[i + 1], (int32_t)1, peer);
        reconstruct((int32_t)1, &W_CW[i + 1], Bout);
    }
    return {Bin, Bout, 1, scw, W_CW, tau};
}


void evaliDCFNext(int party, uint64_t idx, block* st_s, u8* st_t, block* cw, u8* t_l, u8* t_r,
                  GroupElement* W_cw, block* res_s, u8* res_t, GroupElement* y){
    // Input explanation:
    // st_s: current node
    // st_s: current control bit
    // cw: correction words
    // t_l t_r : tau
    // W: for convert

    osuCrypto::AES AESInstance;

    static const block notOneBlock = osuCrypto::toBlock(~0, ~1);
    static const block notThreeBlock = osuCrypto::toBlock(~0, ~3);
    const static block pt[2] = {ZeroBlock, OneBlock};
    block ct[2];

    block nextLevelSeedTemp;
    u8 nextLevelControlBitTemp;

    AESInstance.setKey(*st_s);
    AESInstance.ecbEncTwoBlocks(pt, ct);
    if (*st_t == (u8)1){
        nextLevelSeedTemp = ct[idx] ^ *cw;
        nextLevelControlBitTemp = lsb(ct[idx]) ^ ((idx==(uint64_t)0) ? *t_l : *t_r);
    }

    // Make conversion
    uint64_t W;
    two_pc_convert(W_cw->bitsize, nextLevelSeedTemp, &W, res_s);

    // Transfer t
    *res_t = nextLevelControlBitTemp;
    GroupElement sign = GroupElement(party==2?0:(-1));
    *y = sign * (W + ((nextLevelControlBitTemp == (u8)1) ? *W_cw : 0));
}

void evaliDCF(int party, GroupElement *res, GroupElement idx, const DPFKeyPack &key){
    *res = (1 - idx[0]) * key.g[0];
    block st = key.k[0];
    u8 t = party - 2;
    GroupElement layerRes(0, res->bitsize);
    for(int i=0; i < idx.bitsize - 1; i++){
        evaliDCFNext(party, idx[i], &st, &t, &(key.k[i + 1]), &(key.v[i * 2]),
                     &(key.v[i * 2 + 1]), &(key.g[i + 1]), &st, &t, &layerRes);
        *res = *res + (1 - idx[i] * layerRes);
    }
}