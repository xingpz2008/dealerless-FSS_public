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

#include "2pc_dcf.h"

using namespace osuCrypto;

inline int bytesize(const int bitsize) {
    return (bitsize % 8) == 0 ? bitsize / 8 : (bitsize / 8)  + 1;
}

iDCFKeyPack keyGeniDCF(int party_id, int Bin, int Bout,
                      GroupElement idx, GroupElement* payload, bool masked)
{
    // This is the 2pc generation of DCF Key, proceed with multiple payload
    // The diff between DCF and iDPF is that:
    // 1. the length of n change to n-1
    // 2. payload from beta2 to beta_n (Do not use first beta in Gen directly)
    // 3. real beta have to be determined using mux (maybe the same as iDPF?)
    // 4. We first prepare the digdec of real idx, then call keyGen of iDPF.

    // Step 1: prepare for the DigDec decomposition of x from msb to lsb
    // Particularly, we construct from lsb to msb, then reverse it.
    // For masked iDCF, we create mask in iDCF Gen func.
    u8* real_idx = new u8[Bin];
    u8 level_and_res = 0;
    GroupElement* mask = new GroupElement(0, Bin);
    if (masked){
        prng.SetSeed(osuCrypto::toBlock(party_id, time(NULL)));
        auto mask_s = prng.get<int>();
        mask->value = mask_s;
        idx = idx + *mask;
    }
    for (int i = 0; i < Bin; i++) {
        real_idx[Bin - i - 1] = idx[Bin - i - 1] ^ level_and_res;
        level_and_res = check_bit_overflow(party_id, idx[Bin - i - 1], level_and_res, peer);
    }

    // Step 2: prepare payload list
    GroupElement* real_payload = new GroupElement[Bin];
    GroupElement* tmp_payload = new GroupElement[Bin];
    for (int i = 0; i < Bin; i++){
        tmp_payload[i] = GroupElement(payload->value, payload->bitsize);
        real_payload[i].bitsize = Bout;
    }
    multiplexer(party_id, real_idx, tmp_payload, real_payload, Bin, peer);


    // Step 3. Invoke Key Gen of iDPF
    // Here we start from real_payload[1], to use beta 2 to beta n
    DPFKeyPack idpf_key(keyGeniDPF(party_id, Bin - 1, payload->bitsize, real_idx,
                                   &(real_payload[1]), true));

    // Step 4. Generate Triples. We have to generate n beaver triplets.
    GroupElement* a = new GroupElement[Bin];
    GroupElement* b = new GroupElement[Bin];
    GroupElement* c = new GroupElement[Bin];
    for (int i = 0; i < Bin; i++){
        a[i].bitsize = Bout;
        b[i].bitsize = Bout;
        c[i].bitsize = Bout;
    }
    // call beaver triplet generation
    beaver_mult_offline(party_id, a, b, c, peer, Bin);

    // Free space
    delete[] tmp_payload;
    delete[] real_idx;

    return {idpf_key.Bin, idpf_key.Bout, idpf_key.groupSize, idpf_key.k, idpf_key.g, idpf_key.v, real_payload, mask, a, b, c};
}

newDCFKeyPack keyGenNewDCF(int party_id, int Bin, int Bout, GroupElement idx, GroupElement payload){
    osuCrypto::AES AESInstance;

    static const block notOneBlock = osuCrypto::toBlock(~0, ~1);
    static const block notThreeBlock = osuCrypto::toBlock(~0, ~3);
    static const block ThreeBlock = osuCrypto::toBlock(~0, 3);
    const static block pt[4] = {ZeroBlock, OneBlock, notThreeBlock, ThreeBlock};

    prng.SetSeed(osuCrypto::toBlock(party_id, time(NULL)));
    auto s = prng.get<std::array<block, 1>>();

    // Initialize storage
    block ct[4];
    int lastLevelNodes = 1 << Bin;
    auto* levelNodes = new block[lastLevelNodes];
    auto* nextLevelNodes = new block[lastLevelNodes];
    auto* thisLevelV = new block[lastLevelNodes];
    auto* nextLevelControlBits = new u8[lastLevelNodes];
    u8* levelControlBits = new u8[lastLevelNodes];
    auto* convert_val = new uint64_t;
    auto* null_block = new block;

    levelNodes[0] = s[0];
    levelControlBits[0] = (u8)(party_id-2);
    GroupElement v_alpha(0, Bout);

    // The format of the final key is: s|CW_i|W_CW -> s|(s|V_CW|t|t)...|W_CW
    // lambda| n lambda | n GE |2n u8|GE
    u8* tau = new u8[Bin * 2];
    auto* scw = new block[Bin + 1];
    auto* vcw = new GroupElement[Bin + 1];
    scw[0] = s[0];
    block sigma;

    // Get bits value
    u8* real_idx = new u8[Bin];
    u8 level_and_res = 0;
    for (int i = 0; i < Bin; i++) {
        real_idx[Bin - i - 1] = idx[Bin - i - 1] ^ level_and_res;
        level_and_res = check_bit_overflow(party_id, idx[Bin - i - 1], level_and_res, peer);
    }

    // Body iteration
    for (int i = 0; i < Bin; i++){
        block leftChildren = ZeroBlock;
        block rightChildren = ZeroBlock;
        int expandNum = 1 << i;
        GroupElement v0(0, Bout);
        GroupElement v1(0, Bout);
        for (int j = 0; j < expandNum; j++) {
            // To expand, we first set AES enc keys, with 2^i AES instances
            AESInstance.setKey(levelNodes[j]);

            // Then we call enc to get 2 blocks, as left and right child in the next level
            AESInstance.ecbEncFourBlocks(pt, ct);
            leftChildren = leftChildren ^ ct[0];
            rightChildren = rightChildren ^ ct[1];
            thisLevelV[2 * j] = ct[2];
            thisLevelV[2 * j + 1] = ct[3];
            nextLevelNodes[2 * j] = ct[0];
            nextLevelNodes[2 * j + 1] = ct[1];
        }

        uint8_t mux_input = real_idx[i] ^ (party_id - 2);
        multiplexer2(party_id, &mux_input, &leftChildren, &rightChildren, &sigma, (int32_t)1,
                     peer);
        u8 tau_0 = lsb(leftChildren) ^ real_idx[i] ^ (u8)(party_id - 2);
        u8 tau_1 = lsb(rightChildren) ^ real_idx[i];

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

        uint64_t thisControlBitSum = 0;

        for (int j = 0; j < expandNum; j++) {
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

            // Compute CW now (Convert)
            two_pc_convert(Bout, &(thisLevelV[2 * j]), convert_val, null_block);
            v0 = v0 + (*convert_val % (1ULL << Bout));
            two_pc_convert(Bout, &(thisLevelV[2 * j + 1]), convert_val, null_block);
            v1 = v1 + (*convert_val % (1ULL << Bout));

            // Get control bit sum (prev level)
            thisControlBitSum += (uint64_t)levelControlBits[j];
        }

        u8 cmp_tau_0_ = (u8)(thisControlBitSum & 1);
        u8 cmp_tau_1_ = (u8)((thisControlBitSum >> 1) & 1);
        u8 g = cmp_2bit_opt(party_id, cmp_tau_0_, cmp_tau_1_, peer);

        // We reuse mux_input here, get phi
        GroupElement phi_input_A = v0;
        GroupElement phi_input_B = v1;
        if ((party_id - 2) == 0){
            phi_input_A = phi_input_A * (-1);
            phi_input_B = phi_input_B * (-1);
        }
        GroupElement* phi_output = new GroupElement;
        phi_output->bitsize = Bout;
        multiplexer2(party_id, &mux_input, &phi_input_A, &phi_input_B, phi_output, 1, peer);
        GroupElement theta(0, Bout);
        theta = *phi_output + (v0 + v1) * (((party_id - 2) == 0) ? 1 : (-1));

        // Get eta
        GroupElement* eta_output = new GroupElement;
        eta_output->bitsize = Bout;
        GroupElement zero(0 ,Bout);
        multiplexer2(party_id, &(real_idx[i]), &zero, &payload, eta_output, 1, peer);

        // Set Vcw
        GroupElement vcw_0 = *phi_output - v_alpha + *eta_output;
        GroupElement vcw_1 = -*phi_output + v_alpha - *eta_output;
        GroupElement* vcw_output = new GroupElement;
        multiplexer2(party_id, &g, &vcw_0, &vcw_1, vcw_output, 1, peer);

        reconstruct(vcw_output);
        vcw[i] = *vcw_output;

        GroupElement* g_a = new GroupElement;
        g_a->bitsize = Bout;
        B2A(party_id, &g, g_a, 1, Bout, peer);
        GroupElement v_alpha_hat = v_alpha + theta + (*g_a * (-2) + 1) * *vcw_output;
        reconstruct(&v_alpha_hat);
        v_alpha = v_alpha_hat;

        delete phi_output;
        delete eta_output;
        delete vcw_output;
        delete g_a;

        for (int j = 0; j < expandNum; j++){
            // We now move updated seeds to levelNodes list
            levelNodes[2 * j] = nextLevelNodes[2 * j];
            levelNodes[2 * j + 1] = nextLevelNodes[2 * j + 1];
            // We also need to update level Control bits
            levelControlBits[2 * j] = nextLevelControlBits[2 * j];
            levelControlBits[2 * j + 1] = nextLevelControlBits[2 * j + 1];
        }
    }
    // Evaluate the last CW
    // To begin with, we add all control bits together
    uint64_t controlBitSum = 0;
    // We also need to add all Converted elements
    uint64_t lastLevelElements[lastLevelNodes];
    uint64_t lastLevelSum = 0;
    for (int i = 0; i < lastLevelNodes; i++){
        two_pc_convert(Bout, &(levelNodes[i]), &lastLevelElements[i], null_block);
        lastLevelSum = lastLevelSum + lastLevelElements[i];
        controlBitSum = controlBitSum + (uint64_t)levelControlBits[i];
    }
    u8 cmp_tau_0 = (u8)(controlBitSum & 1);
    u8 cmp_tau_1 = (u8)((controlBitSum >> 1) & 1);
    u8 t = cmp_2bit_opt(party_id, cmp_tau_1, cmp_tau_0, peer);
    GroupElement sign(((party_id-2) == 1) ? 1 : -1, Bout);
    GroupElement W_CW_0 = -v_alpha + lastLevelSum * sign;
    GroupElement W_CW_1 = v_alpha + lastLevelSum * (-sign);
    auto* W_CW = new GroupElement(0, Bout);
    multiplexer2(party_id, &t, &W_CW_0, &W_CW_1, W_CW, 1, peer);
    reconstruct(W_CW);

    vcw[Bin] = *W_CW;

    delete W_CW;
    delete[] real_idx;
    delete[] levelNodes;
    delete[] nextLevelNodes;
    delete[] nextLevelControlBits;
    delete[] levelControlBits;
    delete[] thisLevelV;
    delete convert_val;
    delete null_block;

    return {Bin, Bout, scw, vcw, tau};
}


void evaliDCFNext(int party, uint64_t idx, block* st_s, u8* st_t, block* cw, u8* t_l, u8* t_r,
                  const GroupElement W_cw, block* res_s, u8* res_t, GroupElement* y){
    // Input explanation:
    // st_s: current node
    // st_s: current control bit
    // cw: correction words
    // t_l t_r : tau
    // W: for convert
    //std:: cout << "In EvalNext, started bit size = " << W_cw.bitsize << "." << std::endl;
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
    }else{
        nextLevelSeedTemp = ct[idx];
        nextLevelControlBitTemp = lsb(ct[idx]);
    }

    // Make conversion
    uint64_t W;

    two_pc_convert(y->bitsize, &nextLevelSeedTemp, &W, res_s);

    // Transfer t
    *res_t = nextLevelControlBitTemp;
    GroupElement sign = GroupElement(party==2?0:(-1), W_cw.bitsize);
    *y = sign * (W + ((nextLevelControlBitTemp == (u8)1) ?W_cw : 0));
}

void evaliDCF(int party, GroupElement *res, GroupElement idx, const iDCFKeyPack key, bool masked){

    // DPF key structure:
    // k: Scw, 0 for root seed, loop start from 1
    // g: Wcw, mask term in Group, don't have to modify
    // v: Tcw, control bit correction, don't have to modify

    // Parse DCF Key
    block st = key.k[0];
    GroupElement beta_0 = *key.beta_0;
    GroupElement mask = *key.random_mask;
    if (masked){
        idx = idx + mask;
        reconstruct(1, &idx, idx.bitsize);
    }
    GroupElement* Wcw_list = new GroupElement[idx.bitsize - 1];
    u8* tau_list = new u8[2 * (idx.bitsize - 1)];
    block* CW_list = new block[idx.bitsize - 1];
    for (int i = 0; i < idx.bitsize - 1; i++){
        Wcw_list[i] = key.g[i];
        tau_list[2 * i] = key.v[2 * i];
        tau_list[2 * i + 1] = key.v[2 * i + 1];
        CW_list[i] = key.k[i + 1];
    }

    // Perform Evaluation

    *res = (1 - idx[0]) * beta_0;
    u8 t = (u8)(party - 2);
    GroupElement layerRes(0, res->bitsize);
    block level_st = st;
    u8 level_t = t;
    for(int i = 0; i < idx.bitsize - 1; i++){
        evaliDCFNext(party, idx[i], &st, &t, &(CW_list[i]), &(tau_list[i * 2]),
                     &(tau_list[i * 2 + 1]), Wcw_list[i], &level_st, &level_t, &layerRes);
        st = level_st;
        t = level_t;
        *res = *res + (1 - idx[i + 1] * layerRes);
    }
    delete[] Wcw_list;
    delete[] tau_list;
    delete[] CW_list;
}

void evaliDCF(int party, GroupElement *res, GroupElement idx, const iDCFKeyPack key){
    // Implementation of 2pc masked DCF
    int Bin = idx.bitsize;
    block st = key.k[0];
    GroupElement beta_0 = *key.beta_0;
    GroupElement mask = *key.random_mask;
    GroupElement masked_idx = idx + mask;
    reconstruct(1, &masked_idx, idx.bitsize);
    GroupElement Wcw_list[idx.bitsize - 1];
    u8* tau_list = new u8[2 * (idx.bitsize - 1)];
    block* CW_list = new block[idx.bitsize - 1];
    for (int i = 0; i < idx.bitsize - 1; i++){
        Wcw_list[i] = key.g[i];
        tau_list[2 * i] = key.v[2 * i];
        tau_list[2 * i + 1] = key.v[2 * i + 1];
        CW_list[i] = key.k[i + 1];
    }
    GroupElement* a = key.a;
    GroupElement* b = key.b;
    GroupElement* c = key.c;

    // Create 2 multiplication list
    GroupElement multi_list_0[Bin];
    GroupElement multi_list_1[Bin];
    multi_list_0[0].value = (uint64_t)party - idx[0];
    multi_list_0[0].bitsize = idx.bitsize;
    multi_list_1[0] = beta_0;

    // Perform Evaluation on public input x+r
    // Here we directly perform evaluation, then batch multiplication
    u8 t = (u8)(party - 2);
    GroupElement layerRes(0, res->bitsize);
    block level_st = st;
    u8 level_t = t;
    for(int i = 0; i < idx.bitsize - 1; i++){
        evaliDCFNext(party, masked_idx[i], &st, &t, &(CW_list[i]), &(tau_list[i * 2]),
                     &(tau_list[i * 2 + 1]), Wcw_list[i], &level_st, &level_t, &layerRes);
        st = level_st;
        t = level_t;
        multi_list_0[i + 1].value = (uint64_t)party - idx[i+1];
        multi_list_0[i + 1].bitsize = idx.bitsize;
        multi_list_1[i + 1] = layerRes;
    }

    // Perform multiplication
    GroupElement multi_list_output[Bin];
    beaver_mult_online(party, multi_list_0, multi_list_1, a, b, c, multi_list_output, Bin, peer);

    for (int i = 0; i < Bin; i++){
        *res = *res + multi_list_output[i];
    }

    delete[] tau_list;
    delete[] CW_list;
}

void evaliDCF(int party, GroupElement* res, GroupElement* idx, iDCFKeyPack* keyList, int size, int max_bitsize){
    // This is the batched implementation of masked DCF evaluation
    int Bin[size];
    block st[size];
    GroupElement beta_0[size];
    GroupElement mask[size];
    GroupElement masked_idx[size];
    GroupElement Wcw_list[size * (max_bitsize - 1)];
    u8* tau_list = new u8[size * 2 * (max_bitsize - 1)];
    block* CW_list = new block[size * (max_bitsize - 1)];
    GroupElement a[size * max_bitsize];
    GroupElement b[size * max_bitsize];
    GroupElement c[size * max_bitsize];
    GroupElement multi_list_0[max_bitsize * size];
    GroupElement multi_list_1[max_bitsize * size];
    u8 t[size];
    GroupElement layerRes[size];
    block level_st[size];
    u8 level_t[size];
    GroupElement multi_list_output[size * max_bitsize];

    for (int i = 0; i < size; i++){
        // Parse section
        Bin[i] = idx[i].bitsize;
        st[i] = keyList[i].k[0];
        beta_0[i] = *(keyList[i].beta_0);
        mask[i] = *(keyList[i].random_mask);
        multi_list_0[0 + i * max_bitsize].value = (uint64_t)party - idx[i][0];
        multi_list_0[0 + i * max_bitsize].bitsize = idx[i].bitsize;
        multi_list_1[0 + i * max_bitsize] = beta_0[i];
        layerRes[i] = GroupElement(0, res[i].bitsize);
        level_st[i] = st[i];
        t[i] = (u8)(party - 2);
        level_t[i] = t[i];
        for (int j = 0; j < idx[i].bitsize - 1; j++){
            Wcw_list[j + i * (max_bitsize - 1)] = keyList[i].g[j];
            tau_list[0 + 2 * j + i * (max_bitsize - 1)] = keyList[i].v[2 * j];
            tau_list[1 + 2 * j + i * (max_bitsize - 1)] = keyList[i].v[2 * j + 1];
            CW_list[j + i * (max_bitsize - 1)] = keyList[i].k[j + 1];
        }
        for (int j = 0; j < Bin[i]; j++){
            a[j + i * max_bitsize] = keyList[i].a[j];
            b[j + i * max_bitsize] = keyList[i].b[j];
            c[j + i * max_bitsize] = keyList[i].c[j];
        }
        // Reconstruct masked input
        masked_idx[i] = idx[i] + mask[i];
    }

    // Execute reconstruct, round ++, assume on max bitsize
    reconstruct(size, masked_idx, max_bitsize);

    // Execute batched DCF evaluation
#pragma omp parallel for
    for (int i = 0; i < size; i++){
        for (int j = 0; j < idx[i].bitsize - 1; j++){
            evaliDCFNext(party, idx[i][j], &(st[i]), &t[i], &(CW_list[j + i * (max_bitsize - 1)]),
                         &(tau_list[0 + 2 * j + i * (max_bitsize - 1)]), &(tau_list[1 + 2 * j + i * (max_bitsize - 1)]),
                         Wcw_list[j + i * (max_bitsize - 1)], &(level_st[i]), &(level_t[i]), &layerRes[i]);
#pragma omp critical
            {
                st[i] = level_st[i];
                t[i] = level_t[i];
                multi_list_0[1 + j + i * max_bitsize].value = (uint64_t)party - idx[i][i + 1];
                multi_list_0[1 + j + i * max_bitsize].bitsize = idx[i].bitsize;
                multi_list_1[1 + j + i * max_bitsize] = layerRes[i];
            }
        }
    }

    beaver_mult_online(party, multi_list_0, multi_list_1, a, b, c, multi_list_output, size * max_bitsize, peer);

    for (int i = 0; i < size; i++){
        for (int j = 0; j < Bin[i]; j++){
            res[i] = res[i] + multi_list_output[j + i * max_bitsize];
        }
    }

    delete[] tau_list;
    delete[] CW_list;
}

void evalNewDCF(int party, GroupElement* res, GroupElement* idx, newDCFKeyPack* keyList, int size, int max_bitsize){
    // Assume uniform bitsize = max_bitsize
    int Bin[size];
    int Bout[size];
    GroupElement* g_list[size];
    u8* t_list[size];
    block* s_list[size];
    u8 controlBit[size];
    GroupElement V[size];
    osuCrypto::AES AESInstance[size];
    block levelNodes[size];
    uint64_t* converted_val = new uint64_t[size];
    block* null_block = new block[size];

    static const block notOneBlock = osuCrypto::toBlock(~0, ~1);
    static const block notThreeBlock = osuCrypto::toBlock(~0, ~3);
    static const block ThreeBlock = osuCrypto::toBlock(~0, 3);
    const static block pt[4] = {ZeroBlock, OneBlock, notThreeBlock, ThreeBlock};
    block* ct = new block[4 * size];

    // Init all variables
    for (int i = 0; i < size; i++){
       // Parse key first
       Bin[i] = keyList[i].Bin;
       Bout[i] = keyList[i].Bout;
       controlBit[i] = (u8)(party - 2);
       V[i].value = 0;
       V[i].bitsize = Bout[i];
       g_list[i] = keyList[i].g;
       t_list[i] = keyList[i].v;
       s_list[i] = keyList[i].k;
       levelNodes[i] = s_list[i][0];
    }

    // Body iteration
    for (int i = 0; i < max_bitsize; i++) {

        for (int j = 0; j < size; j++) {

                AESInstance[j].setKey(levelNodes[j]);
                AESInstance[j].ecbEncFourBlocks(pt, &(ct[4 * j]));
                if (idx[j][i] == (u8) 0) {
                    two_pc_convert(Bout[j], &(ct[j * 4 + 2]), &(converted_val[j]), &(null_block[j]));
                } else {
                    two_pc_convert(Bout[j], &(ct[j * 4 + 3]), &(converted_val[j]), &(null_block[j]));
                }
                V[j] = V[j] +
                       (converted_val[j] + (uint64_t) controlBit[j] * g_list[j][i]) * (((party - 2) == 0) ? 1 : (-1));
                if (controlBit[j] == (u8) 1) {
                    // Apply correction words
                    levelNodes[j] = ct[4 * j + (int) (idx[j][i])] ^ s_list[j][i + 1];
                    controlBit[j] = lsb(ct[4 * j + (int) (idx[j][i])]) ^ t_list[j][2 * i + (int) (idx[j][i])];
                } else {
                    levelNodes[j] = ct[4 * j + (int) (idx[j][i])];
                    controlBit[j] = lsb(ct[4 * j + (int) (idx[j][i])]);
                }

        }
    }

    // Final V calculation
    for (int i = 0; i < size; i++){
        two_pc_convert(Bout[i], &(levelNodes[i]), &(converted_val[i]), &(null_block[i]));
        res[i] = V[i] + (((party - 2) == 0) ? 1 : (-1)) * (converted_val[i] + g_list[i][Bin[i]] * (uint64_t)controlBit[i]);
    }

    delete[] converted_val;
    delete[] null_block;
    delete[] ct;
}