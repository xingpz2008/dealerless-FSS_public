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
                      GroupElement idx, GroupElement* payload)
{
    // This is the 2pc generation of DCF Key, proceed with multiple payload
    // The diff between DCF and iDPF is that:
    // 1. the length of n change to n-1
    // 2. payload from beta2 to beta_n (Do not use first beta in Gen directly)
    // 3. real beta have to be determined using mux (maybe the same as iDPF?)
    // 4. We first prepare the digdec of real idx, then call keyGen of iDPF.

    // Step 1: prepare for the DigDec decomposition of x from msb to lsb
    // Particularly, we construct from lsb to msb, then reverse it.
    u8* real_idx = new u8[Bin];
    u8 level_and_res = 0;
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
        tmp_payload[i] = *payload;
    }
    multiplexer(party_id, real_idx, tmp_payload, real_payload, Bin, peer);

    // Step 3. Invoke Key Gen of iDPF
    // Here we start from real_payload[1], to use beta 2 to beta n
    DPFKeyPack idpf_key(keyGeniDPF(party_id, Bin - 1, payload->bitsize, idx, &(real_payload[1])));

    return {&idpf_key, &(real_payload[0])};
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
    }else{
        nextLevelSeedTemp = ct[idx];
        nextLevelControlBitTemp = lsb(ct[idx]);
    }

    // Make conversion
    uint64_t W;
    two_pc_convert(W_cw->bitsize, nextLevelSeedTemp, &W, res_s);

    // Transfer t
    *res_t = nextLevelControlBitTemp;
    GroupElement sign = GroupElement(party==2?0:(-1), W_cw->bitsize);
    *y = sign * (W + ((nextLevelControlBitTemp == (u8)1) ? *W_cw : 0));
}

void evaliDCF(int party, GroupElement *res, GroupElement idx, const iDCFKeyPack &key){

    // DPF key structure:
    // k: Scw, 0 for root seed, loop start from 1
    // g: Wcw, mask term in Group, don't have to modify
    // v: Tcw, control bit correction, don't have to modify

    *res = (1 - idx[0]) * *(key.beta_0);
    block st = key.idpf_key->k[0];
    u8 t = (u8)(party - 2);
    GroupElement layerRes(0, res->bitsize);
    for(int i = 0; i < idx.bitsize - 1; i++){
        evaliDCFNext(party, idx[i], &st, &t, &(key.idpf_key->k[i + 1]), &(key.idpf_key->v[i * 2]),
                     &(key.idpf_key->v[i * 2 + 1]), &(key.idpf_key->g[i]), &st, &t, &layerRes);
        *res = *res + (1 - idx[i + 1] * layerRes);
    }
}