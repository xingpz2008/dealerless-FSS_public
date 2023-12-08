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
    std::cout << "==========iDCF Gen==========" << std::endl;
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
        std::cout << "Idx (from lsb) = " << (int) idx[Bin - i - 1] << std::endl;
        std::cout << "Real idx " << Bin - i - 1 << "= " << (int)real_idx[Bin - i - 1];
        level_and_res = check_bit_overflow(party_id, idx[Bin - i - 1], level_and_res, peer);
        std::cout << ", level and res = " << (int)level_and_res << std::endl;
    }

    // Step 2: prepare payload list
    GroupElement* real_payload = new GroupElement[Bin];
    GroupElement* tmp_payload = new GroupElement[Bin];
    for (int i = 0; i < Bin; i++){
        tmp_payload[i] = GroupElement(payload->value, payload->bitsize);
        real_payload[i].bitsize = Bout;
        //multiplexer(party_id, &real_idx[i], &tmp_payload[i], &real_payload[i], Bin, peer);
    }
    //multiplexer(party_id, real_idx, tmp_payload, real_payload, Bin, peer);
    for (int i = 0; i < Bin; i++){
        std::cout<< "Prev Gen Payload Bitsize = " << real_payload[i].bitsize << std::endl;
    }

    insecure_multiplexer(party_id, real_idx, tmp_payload, real_payload, Bin, peer);

    for (int i = 0; i < Bin; i++){
        std::cout<< "Gen Payload Bitsize = " << real_payload[i].bitsize << std::endl;
    }

    // Step 3. Invoke Key Gen of iDPF
    // Here we start from real_payload[1], to use beta 2 to beta n
    DPFKeyPack idpf_key(keyGeniDPF(party_id, Bin - 1, payload->bitsize, real_idx,
                                   &(real_payload[1]), true));

    // Free space
    delete[] tmp_payload;
    delete[] real_idx;

    return {idpf_key.Bin, idpf_key.Bout, idpf_key.groupSize, idpf_key.k, (const GroupElement*)idpf_key.g, idpf_key.v, &(real_payload[0]), mask};
}


void evaliDCFNext(int party, uint64_t idx, block* st_s, u8* st_t, block* cw, u8* t_l, u8* t_r,
                  const GroupElement W_cw, block* res_s, u8* res_t, GroupElement* y){
    // Input explanation:
    // st_s: current node
    // st_s: current control bit
    // cw: correction words
    // t_l t_r : tau
    // W: for convert
    std:: cout << "In EvalNext, started bit size = " << W_cw.bitsize << "." << std::endl;
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
    std:: cout << "In EvalNext, 2. bit size = " << W_cw.bitsize << "."<< std::endl;

    // Make conversion
    uint64_t W;

    //W = 0;
    //*res_s = osuCrypto::toBlock((u8)0);
    two_pc_convert(y->bitsize, &nextLevelSeedTemp, &W, res_s);
    std:: cout << "In EvalNext, 3. bit size = " << W_cw.bitsize << "."<< std::endl;

    // Transfer t
    *res_t = nextLevelControlBitTemp;
    GroupElement sign = GroupElement(party==2?0:(-1), W_cw.bitsize);
    //GroupElement _W_cw(W_cw->value, W_cw->bitsize);
    std::cout << "In EvalNext, original bit size = " << W_cw.bitsize << "."<< std::endl;
    *y = sign * (W + ((nextLevelControlBitTemp == (u8)1) ?W_cw : 0));
    std::cout << "In EvalNext, afterward bit size = " << W_cw.bitsize << "."<< std::endl;
}

void evaliDCF(int party, GroupElement *res, GroupElement idx, const iDCFKeyPack key, bool masked){

    // DPF key structure:
    // k: Scw, 0 for root seed, loop start from 1
    // g: Wcw, mask term in Group, don't have to modify
    // v: Tcw, control bit correction, don't have to modify
    std::cout << "==========iDCF Eval==========" << std::endl;

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