//
// Created by root on 12/6/23.
//

#include "2pc_api.h"

ModularKeyPack modular_offline(int party_id, GroupElement N, GroupElement* res){
    // This is the offline function of modular
    // We need a secure comparison
    // WARNING: This input N should be additive shared N
    // WARNING: Shared payload!
    ModularKeyPack output;
    GroupElement* one = new GroupElement((uint64_t)(party_id - 2), res->bitsize);
    output.iDCFKey = keyGeniDCF(party_id, N.bitsize, res->bitsize, N, one);
    output.Bin = N.bitsize;
    output.Bout = res->bitsize;
    delete one;
    return output;
}

GroupElement modular(int party_id, GroupElement input, int N, ModularKeyPack key){
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
    GroupElement two_power_s_minus_one((uint64_t)(party_id - 2) * ((1ULL << s) - 1), s);
    GroupElement* one = new GroupElement((uint64_t)(party_id - 2), output.Bout);
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
    // WARNING: The input of knots list should be secret shared!
    ContainmentKeyPack output;
    output.Bin = knots_list[0].bitsize;
    output.Bout = output.Bin;
    output.AList = new GroupElement[knots_size - 1];
    output.BList = new GroupElement[knots_size - 1];
    output.CList = new GroupElement[knots_size - 1];
    output.iDCFKeyList = new iDCFKeyPack[knots_size];
    output.CtnNum = knots_size;
    beaver_mult_offline(party_id, output.AList, output.BList, output.CList, peer, knots_size - 1);
    GroupElement* one = new GroupElement((uint64_t)(party_id - 2), output.Bout);
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
    freeContainmentKeyPack(key);
}

DigDecKeyPack digdec_offline(int party_id, int Bin, int NewBitSize){
    DigDecKeyPack output;
    int SegNum = Bin / NewBitSize + ((Bin % NewBitSize == 0) ? 0 : 1);
    output.Bin = Bin;
    output.NewBitSize = NewBitSize;
    output.SegNum = SegNum;
    // The number of DCF invocation is decided by SegNum
    // We have to generate multiple DPF and DCF Keys as the random mask cannot be reused
    // We need SegNum - 1 keys as the most significant segmentation do not need comparison?
    iDCFKeyPack* iDCFKeyList = new iDCFKeyPack[SegNum - 1];
    DPFKeyPack* DPFKeyList = new DPFKeyPack[SegNum - 1];
    output.iDCFKeyList = iDCFKeyList;
    output.DPFKeyList = DPFKeyList;
    GroupElement two_power_s_minus_one = GroupElement((uint64_t)(party_id - 2) * ((1ULL << NewBitSize) - 1), NewBitSize);
    GroupElement one = GroupElement((uint64_t)(party_id - 2), NewBitSize);
    // For comparison input, we use n+1 bit
    GroupElement two_power_s_minus_one_ = GroupElement((uint64_t)(party_id - 2) * ((1ULL << NewBitSize) - 1), NewBitSize + 1);
    GroupElement* one_ = new GroupElement((uint64_t)(party_id - 2), NewBitSize);
    for (int i = 0; i < SegNum - 1; i++){
        output.DPFKeyList[i] = keyGenDPF(party_id, NewBitSize, NewBitSize, two_power_s_minus_one, one, true);
        output.iDCFKeyList[i] = keyGeniDCF(party_id, NewBitSize + 1, NewBitSize, two_power_s_minus_one_, one_);
    }
    // Perform multiplication offline, we need segNum - 1 AND (replaced by arithmetic multiplication)
    GroupElement* A = new GroupElement[SegNum - 1];
    GroupElement* B = new GroupElement[SegNum - 1];
    GroupElement* C = new GroupElement[SegNum - 1];
    beaver_mult_offline(party_id, A, B, C, peer, SegNum - 1);
    delete one_;
    return output;
}

void digdec(int party_id, GroupElement input, GroupElement* output, int NewBitSize, DigDecKeyPack key){
    assert(NewBitSize == key.NewBitSize);
    int SegNum = key.SegNum;
    GroupElement* parsed_input = new GroupElement[SegNum];
    GroupElement* w = new GroupElement[SegNum];
    GroupElement* e = new GroupElement[SegNum];
    GroupElement* u = new GroupElement[SegNum - 1];
    GroupElement* v = new GroupElement[SegNum - 1];

    // Generate KeyList for DCF and DPF
    iDCFKeyPack* iDCFKeyList = key.iDCFKeyList;
    DPFKeyPack* DPFKeyList = key.DPFKeyList;

    GroupElement* AList = key.AList;
    GroupElement* BList = key.BList;
    GroupElement* CList = key.CList;

    for (int i = 0; i < SegNum; i++){
        // Execute parse
        parsed_input[i] = input >> (NewBitSize * i);
        parsed_input[i].value = parsed_input[i].value & ((uint64_t(1) << NewBitSize) - 1);
        // We need NewBitSize or NewBitSize + 1 ?
        parsed_input[i].bitsize = NewBitSize;

        // Init Bit Size for w e u v
        w[i].bitsize = NewBitSize;
        e[i].bitsize = NewBitSize;
    }

    // Perform comparison and equality test
    evalDPF(party_id, e, parsed_input, DPFKeyList, SegNum - 1, NewBitSize);

    // Need to change bit length to NewBitSize + 1 ?
    for (int i = 0; i < SegNum; i++){
        parsed_input[i].bitsize = NewBitSize + 1;
    }
    evaliDCF(party_id, w, parsed_input, iDCFKeyList, SegNum - 1, NewBitSize + 1);

    // Recover Bit size
    for (int i = 0; i < SegNum; i++){
        parsed_input[i].bitsize = NewBitSize;
    }

    // Perform AND multiplication, which requires multiple online rounds. This is inevitable
    // TODO: Check online overhead w/o DigDec
    // TODO: Check output order from high bit or low bit?
    u[0] = GroupElement(0, NewBitSize);
    output[0] = parsed_input[0];
    for (int i = 0; i < SegNum - 1; i++){
        u[i].bitsize = NewBitSize;
        v[i].bitsize = NewBitSize;
        beaver_mult_online(party_id, u[i], e[i], AList[i], BList[i], CList[i],
                           v + i * sizeof(GroupElement), peer);
        // We directly ADD v and w, as there is no possibility that v=w=1 (e=w=1 is impossible)
        output[i + 1] = parsed_input[i + 1] + v[i] + w[i];
    }

    freeDigDecKeyPack(key);
    delete[] parsed_input;
    delete[] w;
    delete[] e;
    delete[] u;
    delete[] v;
    return;
}