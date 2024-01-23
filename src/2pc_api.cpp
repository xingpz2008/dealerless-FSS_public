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
    delete one;
    return output;
}

GroupElement modular(int party_id, GroupElement input, int N, ModularKeyPack key){
    assert(key.N == N);
    // Assume the input is no bigger than 2*N
    GroupElement* comparison_res = new GroupElement(-1, input.bitsize);
    evaliDCF(party_id, comparison_res, input, key.iDCFKey);
    freeModularKeyPack(key);
    return input - *comparison_res * N;
}

TRKeyPack truncate_and_reduce_offline(int party_id, int l, int s){
    // We use s + 1 bit comparison
    TRKeyPack output;
    output.Bin = s;
    output.Bout = l - s;
    output.s = s;
    GroupElement two_power_s_minus_one((1ULL << s) - 1, s);
    GroupElement* one = new GroupElement(1, output.Bout);
    output.iDCFKey = keyGeniDCF(party_id, output.Bin + 1, output.Bout, two_power_s_minus_one, one);
    delete one;
    return output;
}

GroupElement truncate_and_reduce(int party_id, GroupElement input, int s, TRKeyPack key){
    assert(s == key.s);
    GroupElement output(0, input.bitsize - s);
    // Parse input as l-s and l bit
    auto segmented_ge = segment(input, s);
    // Eval iDCF
    GroupElement* comparison_res = new GroupElement(-1, input.bitsize - s);
    evaliDCF(party_id, comparison_res, segmented_ge.second, key.iDCFKey);
    output = segmented_ge.first + *comparison_res;
    delete comparison_res;
    // Need free TR Key
    freeTRKeyPack(key);
    return output;
}