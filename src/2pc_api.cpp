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

ContainmentKeyPack containment_offline(int party_id, GroupElement* knots_list, int knots_size){
    // In the implementation, we assume that there are two fixed knots on 0 and 2^s-1
    // knot list and knot size do not contain this, i.e. we actually have size+1 intervals
    ContainmentKeyPack output;
    output.Bin = knots_list[0].bitsize;
    output.Bout = output.Bin;
    output.AList = new GroupElement[knots_size - 1];
    output.BList = new GroupElement[knots_size - 1];
    output.CList = new GroupElement[knots_size - 1];
    output.iDCFKeyList = new iDCFKeyPack[knots_size];
    output.CtnNum = knots_size;
    beaver_mult_offline(party_id, output.AList, output.BList, output.CList, peer, knots_size - 1);
    GroupElement* one = new GroupElement(0, output.Bout);
    for (int i = 0; i < knots_size; i++){
        output.iDCFKeyList[i] = keyGeniDCF(party_id, output.Bin, output.Bout, knots_list[i], one);
    }
    delete one;
    return output;
}

void containment(int party_id, GroupElement input, GroupElement* output, int knots_size, ContainmentKeyPack key){
    // Iterative arithmetic AND for constant online rounds?
    // Batched reconstruction of GE
    // we only output [0,x1,x2,...,N] segments, i.e. same as knots size
    assert(knots_size == key.CtnNum);
    assert(knots_size > 0);
    GroupElement* input_array = new GroupElement[knots_size];
    GroupElement* dcf_output = new GroupElement[knots_size];

    for (int i = 0; i < knots_size; i++){
        input_array[i] = input;
        dcf_output[i].bitsize = output[i].bitsize;
    }

    evaliDCF(party_id, dcf_output, input_array, key.iDCFKeyList, knots_size, input.bitsize);

    // Observation: We only need knots_num - 1 multiplication as the first segment is identical to DCF output.
    output[0] = dcf_output[0];
    GroupElement* multA = new GroupElement[knots_size - 1];
    GroupElement* multB = new GroupElement[knots_size - 1];
    for (int i = 0; i < knots_size - 1; i++){
        multA[i] = dcf_output[i + 1];
        multB[i] = dcf_output[i] * -1 + (uint64_t)party_id;
    }
    beaver_mult_online(party_id, multA, multB, key.AList, key.BList, key.CList, &(output[1]), knots_size - 1, peer);

    delete[] dcf_output;
    delete[] input_array;
    delete[] multA;
    delete[] multB;
}