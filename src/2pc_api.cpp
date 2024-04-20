//
// Created by root on 12/6/23.
//

#include "2pc_api.h"

ModularKeyPack modular_offline(int party_id, GroupElement N, int Bout){
    // This is the offline function of modular
    // We need a secure comparison
    // WARNING: Shared payload!
    ModularKeyPack output;
    GroupElement* one = new GroupElement((uint64_t)(party_id - 2), Bout);
    GroupElement shared_N = N * (uint64_t)(party_id - 2);
    output.iDCFKey = keyGeniDCF(party_id, N.bitsize, Bout, shared_N, one);
    output.Bin = N.bitsize;
    output.Bout = Bout;
    delete one;
    return output;
}

GroupElement modular(int party_id, GroupElement input, int N, ModularKeyPack key){
    // Assume the input is no bigger than 2*N
    GroupElement* comparison_res = new GroupElement(-1, input.bitsize);
    evaliDCF(party_id, comparison_res, input, key.iDCFKey);
    freeModularKeyPack(key);
    GroupElement output = input - (GroupElement(uint64_t(party_id - 2), input.bitsize) - *comparison_res) * N;
    delete comparison_res;
    return output;
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

ContainmentKeyPack containment_offline(int party_id, int Bout, GroupElement* knots_list, int knots_size){
    // In the implementation, we assume that there are two fixed knots on 0 and 2^s-1
    // knot list and knot size do not contain this, i.e. we actually have size+1 intervals
    // WARNING: The input of knots list should be secret shared!
    ContainmentKeyPack output;
    output.Bin = knots_list[0].bitsize;
    output.Bout = Bout;
    output.AList = new GroupElement[knots_size];
    output.BList = new GroupElement[knots_size];
    output.CList = new GroupElement[knots_size];
    output.iDCFKeyList = new iDCFKeyPack[knots_size];
    output.CtnNum = knots_size;
    beaver_mult_offline(party_id, output.AList, output.BList, output.CList, peer, knots_size);
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
    // The output should be knots_size + 1 vector
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
    GroupElement* multA = new GroupElement[knots_size];
    GroupElement* multB = new GroupElement[knots_size];
    for (int i = 0; i < knots_size - 1; i++){
        multA[i] = dcf_output[i + 1];
        multB[i] = dcf_output[i] * -1 + (uint64_t)(party_id - 2);
    }
    multA[knots_size - 1] = GroupElement((uint64_t)(party_id - 2), multA[0].bitsize);
    multB[knots_size - 1] = dcf_output[knots_size - 1] * -1 + (uint64_t)(party_id - 2);
    beaver_mult_online(party_id, multA, multB, key.AList, key.BList, key.CList,
                       &(output[1]), knots_size, peer);

    delete[] dcf_output;
    delete[] input_array;
    delete[] multA;
    delete[] multB;
    freeContainmentKeyPack(key);
}

DigDecKeyPack digdec_offline(int party_id, int Bin, int NewBitSize){
    DigDecKeyPack output;
    int SegNum = Bin / NewBitSize + ((Bin % NewBitSize == 0) ? 1 : 0);
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
    // Beaver triplet should be new bitsize bit.
    GroupElement* A = new GroupElement[SegNum - 1];
    GroupElement* B = new GroupElement[SegNum - 1];
    GroupElement* C = new GroupElement[SegNum - 1];
    for (int i = 0; i < SegNum - 1; i++){
        A[i].bitsize = NewBitSize;
        B[i].bitsize = NewBitSize;
        C[i].bitsize = NewBitSize;
    }
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

DPFKeyPack pub_lut_offline(int party_id, int idx_bitlen, int lut_bitlen){
    // Offline stage of lut functionality
    prng.SetSeed(osuCrypto::toBlock(party_id, time(NULL)));
    auto s = prng.get<int>();
    GroupElement lut_index_shared(s, idx_bitlen);
    mod(lut_index_shared);
    GroupElement* lut_index_shared_ptr = new GroupElement(0, idx_bitlen);
    lut_index_shared_ptr->value = lut_index_shared.value;
    GroupElement one(party_id - 2, lut_bitlen);
    DPFKeyPack output = keyGenDPF(party_id, idx_bitlen, lut_bitlen, lut_index_shared, one, false);
    // Parse random info into it.
    output.random_mask = lut_index_shared_ptr;
    return output;
}

GroupElement pub_lut(int party_id, GroupElement input, GroupElement* table, GroupElement* shifted_full_domain_res,
                 int table_size, int output_bitlen, DPFKeyPack key){
    // This is the implementation of DPF based public lookup table protocol
    // This considers a masked input, i.e. x=c -> x+r=c+r
    // However, we do not have to reconstruct input at first. We perform the DPF evaluation at place r.
    GroupElement output(0, output_bitlen);

    // Perform evalAll
    GroupElement* full_domain_res = new GroupElement[table_size];
    // GroupElement* shifted_full_domain_res = new GroupElement[table_size];
    for(int i = 0; i < table_size; i++){
        // Init res bit size
        full_domain_res[i].bitsize = table[i].bitsize;
    }
    int full_domain_length = (int)log2ceil(table_size);
    evalAll(party_id, full_domain_res, key, full_domain_length);

    // Then process the shift of the vector.
    // reconstruct input - r, parse random index.
    GroupElement key_index = *(key.random_mask);
    GroupElement shift_amount = input - key_index;
    reconstruct(&shift_amount);
    GroupElement negative_point(1ULL << (shift_amount.bitsize - 1), shift_amount.bitsize);

    // if bigger, then it is negative, causing ---x---r----, i.e. vector to left
    bool left_flag = (shift_amount > negative_point);
    GroupElement abs_val = left_flag ? shift_amount :
            GroupElement((1ULL << shift_amount.bitsize) - shift_amount.value, shift_amount.bitsize);
    mod(abs_val);
    bool output_vector = (shifted_full_domain_res != NULL);
    if (!output_vector){
        shifted_full_domain_res = new GroupElement[table_size];
    }
    for (int i = 0; i < table_size; i++){
        int real_vector_idx = (i + abs_val.value * (2 * (int)left_flag - 1)) % (1ULL << table_size);
        shifted_full_domain_res[i] = full_domain_res[real_vector_idx];
        // Perform multiplication on local table
        output = output + shifted_full_domain_res[i] * table[i];
    }

    if (!output_vector){
        delete[] shifted_full_domain_res;
    }
    delete[] full_domain_res;
    delete[] key.k;
    delete[] key.g;
    delete[] key.v;
    delete[] key.random_mask;
    return output;
}

PrivateLutKey pri_lut_offline(int party_id, int idx_bitlen, int lut_bitlen, GroupElement* priList){
    PrivateLutKey output;
    int entry = 1 << idx_bitlen;
    output.entryNum = entry;
    output.lut_bitlen = lut_bitlen;

    prng.SetSeed(osuCrypto::toBlock(party_id, time(NULL)));
    auto s = prng.get<int>();
    s = s % (1ULL << idx_bitlen);
    GroupElement random_mask(s, idx_bitlen);
    output.DPFKeyList = new DPFKeyPack[entry];
    for(int i = 0; i < entry; i++){
        output.DPFKeyList[i] = keyGenDPF(party_id, idx_bitlen, lut_bitlen, (random_mask + i) * (uint64_t)(party_id - 2),
                                         priList[i], false);
    }
    output.random_mask = random_mask;
    return output;
}

GroupElement pri_lut(int party_id, GroupElement idx, PrivateLutKey key){
    // Parse key
    GroupElement random_mask = key.random_mask;
    int entryNum = key.entryNum;
    DPFKeyPack* DPFKeyList = key.DPFKeyList;
    GroupElement output(0, key.lut_bitlen);
    GroupElement real_input = idx + random_mask;
    reconstruct(&real_input);
    GroupElement* tmp_output = new GroupElement(0, key.lut_bitlen);
    for (int i = 0; i < entryNum; i++){
        evalDPF(party_id, tmp_output, real_input, DPFKeyList[i], false);
        output = output + *(tmp_output);
    }

    delete tmp_output;
    return output;
}

SplinePolyApproxKeyPack spline_poly_approx_offline(int party_id, int Bin, int Bout,
                                                   GroupElement* publicCoefficientList, int degree, int segNum){
    // Offline generation of spline polynomial approximation
    // The input of publicCoefficient should be a, b, c for each interval (assume 2-degree)
    SplinePolyApproxKeyPack output;
    output.Bin = Bin;
    output.Bout = Bout;
    output.degNum = degree;
    output.segNum = segNum;
    int truncation_bits = Bin / segNum;
    switch (degree) {
        case 2:{
            // For two-degree polynomial, we have three coefficient ax2+bx+c -> ax2+(b-2ar)x+c+r2
            // The output coefficient list is stored as follows: aaaaabbbbbccccc
            GroupElement* coefficientList = new GroupElement[3 * segNum];
            GroupElement random_mask;
            prng.SetSeed(osuCrypto::toBlock(party_id, time(NULL)));
            random_mask = GroupElement(prng.get<uint64_t>(), Bin);
            mod(random_mask);
            for (int i = 0; i < segNum; i++){
                // create a:
                // Converting into shares
                coefficientList[i] = publicCoefficientList[i] * (uint64_t)(party_id - 2);
            }
            // create b:
            // There should be a multiplication with a and r, here we need seg + 1 MTs in all
            GroupElement* tmpA = new GroupElement[1 + segNum];
            GroupElement* tmpB = new GroupElement[1 + segNum];
            GroupElement* tmpC = new GroupElement[1 + segNum];
            GroupElement* mulA = new GroupElement[1 + segNum];
            GroupElement* mulB = new GroupElement[1 + segNum];
            GroupElement* mulRes = new GroupElement[1 + segNum];
            for (int j = 0; j < 1 + segNum; j++){
                tmpA[j].bitsize = Bin;
                tmpB[j].bitsize = Bin;
                tmpC[j].bitsize = Bin;
                if (j < segNum){
                    mulA[j] = coefficientList[j];
                }else{
                    mulA[j] = random_mask;
                }
                mulB[j] = random_mask;
                mulRes[j].bitsize = Bin;
            }
            // TODO: check overhead statics here, put this multiplication overhead into full offline!
            beaver_mult_offline(party_id, tmpA, tmpB, tmpC, peer, 1 + segNum);
            beaver_mult_online(party_id, mulA, mulB, tmpA, tmpB, tmpC,
                               mulRes, 1 + segNum, peer);
            // put b and c into their correct position
            for (int i = 0; i < segNum; i++){
                coefficientList[segNum + i] = publicCoefficientList[segNum + i] * (uint64_t)(party_id - 2)
                        - mulRes[i] * 2;
                coefficientList[2 * segNum + i] = publicCoefficientList[2 * segNum + i] * (uint64_t )(party_id - 2)
                        + mulRes[segNum];
            }
            delete[] tmpA;
            delete[] tmpB;
            delete[] tmpC;
            delete[] mulA;
            delete[] mulB;
            delete[] mulRes;

            output.coefficientList = coefficientList;
            output.random_mask = random_mask;
            output.TRKey = truncate_and_reduce_offline(party_id, Bin, truncation_bits);
            output.PriLUTKeyList = new PrivateLutKey[degree + 1];
            for (int i = 0; i < degree + 1; i++){
                output.PriLUTKeyList[i] = pri_lut_offline(party_id, log2ceil(segNum),
                                                          Bout, &(coefficientList[i * segNum]));
            }
            break;
        }
        default:{
            std::cout << "[ERROR] Unsupported approx degree!" << std::endl;
            exit(-1);
        }
    }
    return output;
}

GroupElement spline_poly_approx(int party_id, GroupElement input, SplinePolyApproxKeyPack key){
    // Implementation of spline approximation online stage, the output of this function is the approximation
    // on each interval, which have to be multiplied with containment result manually!

    // Note: we can directly call segment() for GE in segmentation.

    // Parse key
    int Bin = key.Bin;
    int degNum = key.degNum;
    int segNum = key.segNum;
    GroupElement* coefficientList = key.coefficientList;
    GroupElement random_mask = key.random_mask;
    TRKeyPack TRKey = key.TRKey;
    PrivateLutKey* PriLUTKeyList = key.PriLUTKeyList;
    GroupElement output(0, coefficientList[0].bitsize);

    switch (degNum) {
        case 2:{
            // Now reconstruct input on all intervals
            GroupElement real_input = input + random_mask;
            reconstruct(&real_input);
            GroupElement truncated_input = truncate_and_reduce(party_id, real_input * (uint64_t)(party_id - 2), input.bitsize / segNum, TRKey);
            // Call LUT
            // For degNum approx, we have deg + 1 coefficient
            // fetch coefficient
            GroupElement lut_output[degNum + 1];
            for (int i = 0; i < degNum + 1; i++){
                lut_output[i] = pri_lut(party_id, truncated_input, PriLUTKeyList[i]);
            }

            // Perform multiplication
            output = lut_output[0] * real_input * real_input + lut_output[1] * real_input + lut_output[2];
            delete[] lut_output;
            break;
        }
        default:{
            freeSplinePolyApproxKeyPack(key);
            std::cout << "[ERROR] Unsupported approx degree!" << std::endl;
            exit(-1);
        }
    }
    freeSplinePolyApproxKeyPack(key);
    return output;
}