//
// Created by root on 12/6/23.
//

#include "2pc_api.h"

ModularKeyPack modular_offline(int party_id, GroupElement N, GroupElement* res){
    // This is the offline function of modular
    // We need a secure comparison
    ModularKeyPack output;
    GroupElement* one = new GroupElement(1, res->bitsize);
    output.iDCFKey = keyGeniDCF(party_id, N.bitsize, res->bitsize, N, one);
    output.Bin = N.bitsize;
    output.Bout = res->bitsize;
    output.N = N.value;
    free(one);
    return output;
}

GroupElement modular(int party_id, GroupElement input, int N, ModularKeyPack key){
    assert(key.N == N);
    // Assume the input is no longer bigger than 2*N
    GroupElement* comparison_res = new GroupElement(-1, input.bitsize);
    evaliDCF(party_id, comparison_res, input, key.iDCFKey);
    return input - *comparison_res * N;
}