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


#include "2pc_api.h"

#include <vector>

namespace {

u8 wrap_of_shared_value(int party_id, GroupElement share) {
    const uint64_t mask =
        share.bitsize == 64 ? ~uint64_t(0) : ((uint64_t(1) << share.bitsize) - 1);
    GroupElement mill_input = party_id == SERVER
                                  ? share
                                  : GroupElement(mask - share.value, share.bitsize);
    u8 wrap = 0;
    peer->mill(&wrap, &mill_input, 1);
    return wrap;
}

GroupElement overflow_on_addition(int party_id, GroupElement lhs, GroupElement rhs,
                                  int output_bits) {
    assert(lhs.bitsize == rhs.bitsize);
    GroupElement sum = lhs + rhs;
    u8 wrap_bits[] = {
        wrap_of_shared_value(party_id, sum),
        wrap_of_shared_value(party_id, lhs),
        wrap_of_shared_value(party_id, rhs),
    };
    GroupElement arithmetic_wraps[] = {
        GroupElement(0, output_bits),
        GroupElement(0, output_bits),
        GroupElement(0, output_bits),
    };
    B2A(party_id, wrap_bits, arithmetic_wraps, 3, output_bits, peer);

    const __uint128_t local_sum =
        static_cast<__uint128_t>(lhs.value) + static_cast<__uint128_t>(rhs.value);
    const uint64_t local_carry = local_sum >> lhs.bitsize;
    return arithmetic_wraps[0] - arithmetic_wraps[1] - arithmetic_wraps[2] +
           GroupElement(local_carry, output_bits);
}

GroupElement zero_extend_shared_value(int party_id, GroupElement share,
                                      int output_bits) {
    assert(output_bits >= share.bitsize);
    if (output_bits == share.bitsize) {
        return share;
    }

    u8 wrap = wrap_of_shared_value(party_id, share);
    GroupElement arithmetic_wrap = B2A(party_id, wrap, output_bits, peer);

    GroupElement extended_share(share.value, output_bits);
    return extended_share -
           arithmetic_wrap * (uint64_t(1) << share.bitsize);
}

GroupElement zero_extend_public_value(GroupElement value, int output_bits) {
    assert(output_bits >= value.bitsize);
    return GroupElement(value.value, output_bits);
}

GroupElement sign_extend_public_value(GroupElement value, int output_bits) {
    assert(output_bits >= value.bitsize);
    uint64_t extended_value = value.value;
    if (value.bitsize < 64 &&
        value.value > ((uint64_t(1) << (value.bitsize - 1)) - 1)) {
        extended_value |= ((uint64_t(1) << (output_bits - value.bitsize)) - 1)
                          << value.bitsize;
    }
    return GroupElement(extended_value, output_bits);
}

}  // namespace

GroupElement zero_extend(int party_id, GroupElement input, int output_bits) {
    return zero_extend_shared_value(party_id, input, output_bits);
}

ComparisonKeyPack ring_extend_offline(int party_id, int input_bits,
                                      int output_bits) {
    assert(output_bits >= input_bits);
    GroupElement threshold(
        (uint64_t)(party_id - 2) * (uint64_t(1) << input_bits),
        input_bits + 1);
    GroupElement one((uint64_t)(party_id - 2), output_bits);
    return comparison_offline(party_id, input_bits + 1, output_bits,
                              threshold, one, true);
}

GroupElement ring_extend(int party_id, GroupElement input, int output_bits,
                         const ComparisonKeyPack& key) {
    assert(output_bits >= input.bitsize);
    if (output_bits == input.bitsize) {
        return input;
    }

    GroupElement lifted_input(input.value, input.bitsize + 1);
    GroupElement is_below_threshold = comparison(party_id, lifted_input, key);

    GroupElement one((uint64_t)(party_id - 2), output_bits);
    GroupElement carry = one - is_below_threshold;
    return GroupElement(input.value, output_bits) -
           carry * (uint64_t(1) << input.bitsize);
}

ComparisonKeyPack comparison_offline(int party_id, int Bin, int Bout, GroupElement c, const GroupElement& payload, bool public_payload = true){
    // c -> input
    // payload -> output
    // Algorithm 6 consumes arithmetic payload shares through FMUL.
    // Keep the flag for the existing API, but do not use the old local product shortcut.
    (void) public_payload;
    assert((Bin == c.bitsize) && (Bout == payload.bitsize));
    ComparisonKeyPack key;
    key.Bin = c.bitsize;
    key.Bout = Bout;
    auto rng = secure_prng();
    GroupElement r = random_ge_from_prng(rng, c.bitsize);
    key.mask = r;

    // Algorithm 6 needs the overflow bit of r + c in the input ring.
    GroupElement r_plus_c = r + c;
    GroupElement g_ = overflow_on_addition(party_id, r, c, Bout);
    GroupElement a(-1, Bout);
    GroupElement b(-1, Bout);
    GroupElement mult_c(-1, Bout);
    beaver_mult_offline(party_id, &a, &b, &mult_c, peer, 1);
    GroupElement g_A = beaver_mult_online(party_id, payload, g_, a, b, mult_c, peer);
    key.correction = g_A;

    // Invoke 2 DCFs.
    key.DCFKeyList[0] = keyGenNewDCF(party_id, Bin, Bout, r, -payload);
    key.DCFKeyList[1] = keyGenNewDCF(party_id, Bin, Bout, r_plus_c, payload);

    return key;
}

ComparisonKeyPack comparison_offline(int party_id, int Bin, int Bout, GroupElement c,
                                     const GroupElement* payload, bool public_payload){
    return comparison_offline(party_id, Bin, Bout, c, *payload, public_payload);
}

void comparison(int party_id, GroupElement* res, GroupElement idx, const ComparisonKeyPack& key){
    *res = comparison(party_id, idx, key);
}

GroupElement comparison(int party_id, GroupElement idx, const ComparisonKeyPack& key){
    // Single comparison implementation
    GroupElement real_idx = idx + key.mask;
    reconstruct(&real_idx);
    std::array<GroupElement, 2> y;
    GroupElement eval_idx[2] = {real_idx, real_idx};
    for (int i = 0; i < 2; i++){
        y[i].bitsize = key.Bout;
    }

    evalNewDCF(party_id, y.data(), eval_idx, key.DCFKeyList.data(), 2, key.Bin);

    return y[0] + y[1] + key.correction;
}

void comparison(int party_id, GroupElement* res, const GroupElement* idx, const ComparisonKeyPack* KeyList,
                int size, int max_bitsize){
    std::vector<GroupElement> real_idx(size);
    std::vector<GroupElement> eval_idx(2 * size);
    std::vector<GroupElement> y(2 * size);
    std::vector<newDCFKeyPack> unifiedKeyList(2 * size);
    for (int i = 0; i < size; i++){
        real_idx[i] = idx[i] + KeyList[i].mask;
        y[2 * i].bitsize = KeyList[i].Bout;
        y[2 * i + 1].bitsize = KeyList[i].Bout;
        unifiedKeyList[2 * i] = KeyList[i].DCFKeyList[0];
        unifiedKeyList[2 * i + 1] = KeyList[i].DCFKeyList[1];
    }
    reconstruct(size, real_idx.data(), max_bitsize);
    for (int i = 0; i < size; i++){
        eval_idx[2 * i] = real_idx[i];
        eval_idx[2 * i + 1] = real_idx[i];
    }

    evalNewDCF(party_id, y.data(), eval_idx.data(), unifiedKeyList.data(), 2 * size, max_bitsize);

    for (int i = 0; i < size; i++){
        res[i] = y[2 * i] + y[2 * i + 1] + KeyList[i].correction;
    }

}

ModularKeyPack modular_offline(int party_id, GroupElement N, int Bout){
    // This is the offline function of modular
    // We need a secure comparison
    // WARNING: Shared payload!
    ModularKeyPack output;
    GroupElement one((uint64_t)(party_id - 2), Bout);
    GroupElement shared_N = N * (uint64_t)(party_id - 2);
    output.ComparisonKey = comparison_offline(party_id, N.bitsize, Bout, shared_N, one);
    output.Bin = N.bitsize;
    output.Bout = Bout;
    return output;
}

GroupElement modular(int party_id, GroupElement input, int N, const ModularKeyPack& key){
    // Assume the input is no bigger than 2*N
    GroupElement comparison_res = comparison(party_id, input, key.ComparisonKey);
    GroupElement output = input - (GroupElement(uint64_t(party_id - 2), input.bitsize) - comparison_res) * N;
    return output;
}

ComparisonKeyPack sign_extend_offline(int party_id, int input_bits, int output_bits) {
    GroupElement sign_threshold(
        (uint64_t)(party_id - 2) * (uint64_t(1) << (input_bits - 1)),
        input_bits);
    GroupElement one((uint64_t)(party_id - 2), output_bits);
    return comparison_offline(party_id, input_bits, output_bits,
                              sign_threshold, one);
}

GroupElement sign_extend_with_key(int party_id, GroupElement input,
                                  int output_bits, const ComparisonKeyPack& key) {
    GroupElement is_nonnegative = comparison(party_id, input, key);
    GroupElement unsigned_input = zero_extend_shared_value(party_id, input,
                                                           output_bits);
    GroupElement one((uint64_t)(party_id - 2), output_bits);
    GroupElement sign = one - is_nonnegative;
    return unsigned_input - sign * (uint64_t(1) << input.bitsize);
}

TRKeyPack truncate_and_reduce_offline(int party_id, int l, int s){
    // We use s + 1 bit comparison
    TRKeyPack output;
    output.Bin = s;
    output.Bout = l - s;
    output.s = s;
    GroupElement two_power_s((uint64_t)(party_id - 2) * (1ULL << s), s + 1);
    GroupElement one((uint64_t)(party_id - 2), output.Bout);
    output.ComparisonKey = comparison_offline(party_id, output.Bin + 1, output.Bout, two_power_s, one);
    return output;
}

GroupElement truncate_and_reduce(int party_id, GroupElement input, int s, const TRKeyPack& key){
    assert(s == key.s);
    if (s == 0) {
        return input;
    }
    GroupElement output(0, input.bitsize - s);
    // Parse input as l-s and l bit
    auto segmented_ge = segment(input, s);
    // Lift the low shares before comparison so their addition keeps the carry bit.
    segmented_ge.second.bitsize = s + 1;
    // Eval iDCF
    GroupElement comparison_res = comparison(party_id, segmented_ge.second, key.ComparisonKey);
    GroupElement one((uint64_t)(party_id - 2), input.bitsize - s);
    GroupElement carry = one - comparison_res;
    output = segmented_ge.first + carry;
    return output;
}

ContainmentKeyPack containment_offline(int party_id, int Bout, const GroupElement* knots_list, int knots_size){
    // In the implementation, we assume that there are two fixed knots on 0 and 2^s-1
    // knot list and knot size do not contain this, i.e. we actually have size+1 intervals
    // WARNING: The input of knots list should be secret shared!
    ContainmentKeyPack output;
    output.Bin = knots_list[0].bitsize;
    output.Bout = Bout;
    const int mult_count = knots_size - 1;
    if (mult_count > 0) {
        output.AList = makeKeyArray<GroupElement>(mult_count);
        output.BList = makeKeyArray<GroupElement>(mult_count);
        output.CList = makeKeyArray<GroupElement>(mult_count);
    }
    output.ComparisonKeyList = makeKeyArray<ComparisonKeyPack>(knots_size);
    output.CtnNum = knots_size;
    for (int i = 0; i < mult_count; i++){
        output.AList[i].bitsize = output.Bout;
        output.BList[i].bitsize = output.Bout;
        output.CList[i].bitsize = output.Bout;
    }
    if (mult_count > 0) {
        beaver_mult_offline(party_id, output.AList, output.BList, output.CList,
                            peer, mult_count);
    }
    GroupElement one((uint64_t)(party_id - 2), output.Bout);
    for (int i = 0; i < knots_size; i++){
        output.ComparisonKeyList[i] = comparison_offline(party_id, output.Bin, output.Bout, knots_list[i], one);
    }
    return output;
}

ContainmentKeyPack containment_offline_public(int party_id, int Bout,
                                              const GroupElement* knots_list,
                                              int knots_size) {
    std::vector<GroupElement> shared_knots(knots_size);
    for (int i = 0; i < knots_size; i++) {
        shared_knots[i] = knots_list[i] * (uint64_t)(party_id - 2);
    }
    ContainmentKeyPack output = containment_offline(
        party_id, Bout, shared_knots.data(), knots_size);
    return output;
}

void containment(int party_id, GroupElement input, GroupElement* output, int knots_size, const ContainmentKeyPack& key){
    // Iterative arithmetic AND for constant online rounds?
    // Batched reconstruction of GE
    // The output should be knots_size + 1 vector
    assert(knots_size == key.CtnNum);
    assert(knots_size > 0);
    std::vector<GroupElement> input_array(knots_size);
    std::vector<GroupElement> dcf_output(knots_size);

    for (int i = 0; i < knots_size + 1; i++){
        output[i] = GroupElement(0, key.Bout);
    }
    for (int i = 0; i < knots_size; i++){
        input_array[i] = input;
        dcf_output[i].bitsize = key.Bout;
    }

    comparison(party_id, dcf_output.data(), input_array.data(), key.ComparisonKeyList, knots_size, input.bitsize);

    // Endpoints are local: output[0] = c[0], output[last] = 1 - c[last].
    output[0] = dcf_output[0];
    const int mult_count = knots_size - 1;
    std::vector<GroupElement> multA(mult_count);
    std::vector<GroupElement> multB(mult_count);
    for (int i = 0; i < mult_count; i++){
        multA[i] = dcf_output[i + 1];
        multB[i] = dcf_output[i] * -1 + (uint64_t)(party_id - 2);
    }
    if (mult_count > 0) {
        beaver_mult_online(party_id, multA.data(), multB.data(), key.AList, key.BList,
                           key.CList, &(output[1]), mult_count, peer);
    }
    output[knots_size] =
        GroupElement((uint64_t)(party_id - 2), key.Bout) -
        dcf_output[knots_size - 1];
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
    output.ComparisonKeyList = makeKeyArray<ComparisonKeyPack>(SegNum - 1);
    output.DPFKeyList = makeKeyArray<DPFKeyPack>(SegNum - 1);
    GroupElement two_power_s_minus_one = GroupElement((uint64_t)(party_id - 2) * ((1ULL << NewBitSize) - 1), NewBitSize);
    GroupElement one = GroupElement((uint64_t)(party_id - 2), NewBitSize);
    // For comparison input, we use n+1 bit
    GroupElement two_power_s_ =
        GroupElement((uint64_t)(party_id - 2) * (1ULL << NewBitSize), NewBitSize + 1);
    GroupElement one_((uint64_t)(party_id - 2), NewBitSize);
    for (int i = 0; i < SegNum - 1; i++){
        output.DPFKeyList[i] = keyGenDPF(party_id, NewBitSize, NewBitSize, two_power_s_minus_one, one, true);
        output.ComparisonKeyList[i] =
            comparison_offline(party_id, NewBitSize + 1, NewBitSize, two_power_s_, one_);
    }
    // Perform multiplication offline, we need segNum - 1 AND (replaced by arithmetic multiplication)
    // Beaver triplet should be new bitsize bit.
    output.AList = makeKeyArray<GroupElement>(SegNum - 1);
    output.BList = makeKeyArray<GroupElement>(SegNum - 1);
    output.CList = makeKeyArray<GroupElement>(SegNum - 1);
    for (int i = 0; i < SegNum - 1; i++){
        output.AList[i].bitsize = NewBitSize;
        output.BList[i].bitsize = NewBitSize;
        output.CList[i].bitsize = NewBitSize;
    }
    beaver_mult_offline(party_id, output.AList, output.BList, output.CList,
                        peer, SegNum - 1);
    return output;
}

void digdec(int party_id, GroupElement input, GroupElement* output, int NewBitSize, const DigDecKeyPack& key){
    assert(NewBitSize == key.NewBitSize);
    int SegNum = key.SegNum;
    std::vector<GroupElement> parsed_input(SegNum);
    std::vector<GroupElement> w(SegNum);
    std::vector<GroupElement> e(SegNum);
    std::vector<GroupElement> u(SegNum - 1);
    std::vector<GroupElement> v(SegNum - 1);

    // Generate KeyList for DCF and DPF
    const ComparisonKeyPack* ComparisonKeyList = key.ComparisonKeyList;
    const DPFKeyPack* DPFKeyList = key.DPFKeyList;

    const GroupElement* AList = key.AList;
    const GroupElement* BList = key.BList;
    const GroupElement* CList = key.CList;

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
    std::vector<GroupElement> equality_input(SegNum - 1);
    for (int i = 0; i < SegNum - 1; i++){
        equality_input[i] = parsed_input[i];
    }
    evalDPF(party_id, e.data(), equality_input.data(), DPFKeyList, SegNum - 1, NewBitSize);

    // Need to change bit length to NewBitSize + 1 ?
    for (int i = 0; i < SegNum; i++){
        parsed_input[i].bitsize = NewBitSize + 1;
    }
    comparison(party_id, w.data(), parsed_input.data(), ComparisonKeyList, SegNum - 1, NewBitSize + 1);
    for (int i = 0; i < SegNum - 1; i++){
        w[i] = GroupElement((uint64_t)(party_id - 2), NewBitSize) - w[i];
    }

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
        v[i] = beaver_mult_online(party_id, u[i], e[i], AList[i], BList[i],
                                  CList[i], peer);
        // We directly ADD v and w, as there is no possibility that v=w=1 (e=w=1 is impossible)
        output[i + 1] = parsed_input[i + 1] + v[i] + w[i];
        if (i + 1 < SegNum - 1){
            u[i + 1] = v[i] + w[i];
        }
    }
    return;
}

DPFKeyPack pub_lut_offline(int party_id, int idx_bitlen, int lut_bitlen){
    // Offline stage of lut functionality
    auto rng = secure_prng();
    GroupElement lut_index_shared = random_ge_from_prng(rng, idx_bitlen);
    GroupElement one(party_id - 2, lut_bitlen);
    DPFKeyPack output = keyGenDPF(party_id, idx_bitlen, lut_bitlen, lut_index_shared, one, false);
    // Parse random info into it.
    output.random_mask = std::make_shared<GroupElement>(lut_index_shared);
    return output;
}

GroupElement pub_lut(int party_id, GroupElement input, const GroupElement* table, GroupElement* shifted_full_domain_res,
                 int table_size, int output_bitlen, const DPFKeyPack& key){
    // This is the implementation of DPF based public lookup table protocol
    // This considers a masked input, i.e. x=c -> x+r=c+r
    // However, we do not have to reconstruct input at first. We perform the DPF evaluation at place r.
    GroupElement output(0, output_bitlen);

    // Perform evalAll
    std::vector<GroupElement> full_domain_res(table_size);
    for(int i = 0; i < table_size; i++){
        // Init res bit size
        full_domain_res[i].bitsize = table[i].bitsize;
    }
    int full_domain_length = (int)log2ceil(table_size);
    evalAll(party_id, full_domain_res.data(), key, full_domain_length);

    // Then process the shift of the vector.
    // reconstruct input - r, parse random index.
    GroupElement key_index = *(key.random_mask);
    GroupElement shift_amount = input - key_index;
    reconstruct(&shift_amount);
    std::vector<GroupElement> local_shifted_full_domain_res;
    if (shifted_full_domain_res == nullptr) {
        local_shifted_full_domain_res.resize(table_size);
        shifted_full_domain_res = local_shifted_full_domain_res.data();
    }
    const int shift = shift_amount.value % table_size;
    for (int i = 0; i < table_size; i++){
        int real_vector_idx = (i + table_size - shift) % table_size;
        shifted_full_domain_res[i] = full_domain_res[real_vector_idx];
        // Perform multiplication on local table
        output = output + shifted_full_domain_res[i] * table[i];
    }
    return output;
}

PrivateLutKey pri_lut_offline(int party_id, int idx_bitlen, int lut_bitlen, const GroupElement* priList){
    PrivateLutKey output;
    int entry = 1 << idx_bitlen;
    output.entryNum = entry;
    output.lut_bitlen = lut_bitlen;

    auto rng = secure_prng();
    GroupElement random_mask = random_ge_from_prng(rng, idx_bitlen);
    output.DPFKeyList = makeKeyArray<DPFKeyPack>(entry);
    for(int i = 0; i < entry; i++){
        GroupElement shifted_mask =
            random_mask + GroupElement(i * static_cast<uint64_t>(party_id - 2), idx_bitlen);
        output.DPFKeyList[i] =
            keyGenDPF(party_id, idx_bitlen, lut_bitlen, shifted_mask, priList[i], false);
    }
    output.random_mask = random_mask;
    return output;
}

GroupElement pri_lut(int party_id, GroupElement idx, const PrivateLutKey& key){
    // Parse key
    GroupElement random_mask = key.random_mask;
    int entryNum = key.entryNum;
    const DPFKeyPack* DPFKeyList = key.DPFKeyList;
    GroupElement output(0, key.lut_bitlen);
    GroupElement real_input = idx + random_mask;
    reconstruct(&real_input);
    for (int i = 0; i < entryNum; i++){
        output = output + evalDPF(party_id, real_input, DPFKeyList[i], false);
    }

    return output;
}

SplinePolyApproxKeyPack spline_poly_approx_offline(int party_id, int Bin, int Bout,
                                                   const GroupElement* publicCoefficientList, int degree,
                                                   int segNum, int fixed_scale){
    // Offline generation of spline polynomial approximation
    // The input of publicCoefficient should be a, b, c for each interval (assume 2-degree)
    SplinePolyApproxKeyPack output;
    output.Bin = Bin;
    output.Bout = Bout;
    output.degNum = degree;
    output.segNum = segNum;
    output.fixed_scale = fixed_scale;
    output.EvalSignKeyList = NULL;
    output.EvalExtendKeyList = NULL;
    output.EvalScaleTRKeyList = NULL;
    output.EvalAList = NULL;
    output.EvalBList = NULL;
    output.EvalCList = NULL;
    int truncation_bits = Bin - log2floor(segNum);
    switch (degree) {
        case 2:{
            // The output coefficient list is stored as follows: aaaaabbbbbccccc
            output.coefficientList = makeKeyArray<GroupElement>(3 * segNum);
            GroupElement* coefficientList = output.coefficientList.data();
            GroupElement random_mask;
            auto rng = secure_prng();
            random_mask = random_ge_from_prng(rng, Bout);
            if (fixed_scale > 0) {
                const int product_bits = Bout + fixed_scale;
                for (int i = 0; i < segNum; i++){
                    GroupElement public_a =
                        sign_extend_public_value(publicCoefficientList[i],
                                                 product_bits);
                    GroupElement public_b =
                        sign_extend_public_value(
                            publicCoefficientList[segNum + i], product_bits);
                    GroupElement public_c =
                        sign_extend_public_value(
                            publicCoefficientList[2 * segNum + i],
                            product_bits);
                    coefficientList[i] =
                        public_a * (uint64_t)(party_id - 2);
                    coefficientList[segNum + i] =
                        public_b * (uint64_t)(party_id - 2);
                    coefficientList[2 * segNum + i] =
                        public_c * (uint64_t)(party_id - 2);
                }

                output.EvalScaleTRKeyList = makeKeyArray<TRKeyPack>(degree + 1);
                for (int i = 0; i < degree + 1; i++) {
                    output.EvalScaleTRKeyList[i] =
                        truncate_and_reduce_offline(party_id, product_bits,
                                                    fixed_scale);
                }
                output.EvalExtendKeyList = makeKeyArray<ComparisonKeyPack>(2);
                output.EvalExtendKeyList[0] =
                    ring_extend_offline(party_id, Bin, product_bits);
                output.EvalExtendKeyList[1] =
                    ring_extend_offline(party_id, Bout, product_bits);
                output.EvalAList = makeKeyArray<GroupElement>(degree + 1);
                output.EvalBList = makeKeyArray<GroupElement>(degree + 1);
                output.EvalCList = makeKeyArray<GroupElement>(degree + 1);
                for (int i = 0; i < degree + 1; i++) {
                    output.EvalAList[i].bitsize = product_bits;
                    output.EvalBList[i].bitsize = product_bits;
                    output.EvalCList[i].bitsize = product_bits;
                }
                beaver_mult_offline(party_id, output.EvalAList, output.EvalBList,
                                    output.EvalCList, peer, degree + 1);
            } else {
                if (Bout > Bin) {
                    output.EvalExtendKeyList = makeKeyArray<ComparisonKeyPack>(1);
                    output.EvalExtendKeyList[0] =
                        ring_extend_offline(party_id, Bin, Bout);
                }
                // For z = x + r, rewrite ax^2 + bx + c as
                // az^2 + (b - 2ar)z + (ar^2 - br + c).
                for (int i = 0; i < segNum; i++){
                    // create a:
                    // Converting into shares
                    coefficientList[i] =
                        zero_extend_public_value(publicCoefficientList[i], Bout) *
                        (uint64_t)(party_id - 2);
                }
                // create b:
                // There should be a multiplication with a and r, here we need seg + 1 MTs in all
                std::vector<GroupElement> tmpA(1 + segNum);
                std::vector<GroupElement> tmpB(1 + segNum);
                std::vector<GroupElement> tmpC(1 + segNum);
                std::vector<GroupElement> mulA(1 + segNum);
                std::vector<GroupElement> mulB(1 + segNum);
                std::vector<GroupElement> mulRes(1 + segNum);
                for (int j = 0; j < 1 + segNum; j++){
                    tmpA[j].bitsize = Bout;
                    tmpB[j].bitsize = Bout;
                    tmpC[j].bitsize = Bout;
                    if (j < segNum){
                        mulA[j] = coefficientList[j];
                    }else{
                        mulA[j] = random_mask;
                    }
                    mulB[j] = random_mask;
                    mulRes[j].bitsize = Bout;
                }
                // TODO: check overhead statics here, put this multiplication overhead into full offline!
                beaver_mult_offline(party_id, tmpA.data(), tmpB.data(),
                                    tmpC.data(), peer, 1 + segNum);
                beaver_mult_online(party_id, mulA.data(), mulB.data(),
                                   tmpA.data(), tmpB.data(), tmpC.data(),
                                   mulRes.data(), 1 + segNum, peer);
                // put b and c into their correct position
                for (int i = 0; i < segNum; i++){
                    GroupElement public_a =
                        zero_extend_public_value(publicCoefficientList[i], Bout);
                    GroupElement public_b =
                        zero_extend_public_value(publicCoefficientList[segNum + i], Bout);
                    GroupElement public_c =
                        zero_extend_public_value(publicCoefficientList[2 * segNum + i], Bout);
                    coefficientList[segNum + i] =
                            public_b * (uint64_t)(party_id - 2) - mulRes[i] * 2;
                    coefficientList[2 * segNum + i] =
                            public_c * (uint64_t)(party_id - 2)
                            + public_a * mulRes[segNum]
                            - public_b * random_mask;
                }
            }

            output.random_mask = random_mask;
            output.TRKey = truncate_and_reduce_offline(party_id, Bin, truncation_bits);
            output.PriLUTKeyList = makeKeyArray<PrivateLutKey>(degree + 1);
            for (int i = 0; i < degree + 1; i++){
                output.PriLUTKeyList[i] = pri_lut_offline(party_id, log2ceil(segNum),
                                                          coefficientList[i * segNum].bitsize,
                                                          &(coefficientList[i * segNum]));
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

GroupElement spline_poly_approx(int party_id, GroupElement input, const SplinePolyApproxKeyPack& key){
    // Implementation of spline approximation online stage, the output of this function is the approximation
    // on each interval, which have to be multiplied with containment result manually!

    // Note: we can directly call segment() for GE in segmentation.

    // Parse key
    int Bin = key.Bin;
    int degNum = key.degNum;
    int segNum = key.segNum;
    const GroupElement* coefficientList = key.coefficientList;
    GroupElement random_mask = key.random_mask;
    const TRKeyPack& TRKey = key.TRKey;
    const PrivateLutKey* PriLUTKeyList = key.PriLUTKeyList;
    GroupElement output(0, coefficientList[0].bitsize);

    switch (degNum) {
        case 2:{
            GroupElement truncated_input = truncate_and_reduce(
                    party_id, input, input.bitsize - log2floor(segNum), TRKey);
            // Call LUT
            // For degNum approx, we have deg + 1 coefficient
            // fetch coefficient
            GroupElement lut_output[degNum + 1];
            for (int i = 0; i < degNum + 1; i++){
                lut_output[i] = pri_lut(party_id, truncated_input, PriLUTKeyList[i]);
            }

            // Perform multiplication
            if (key.fixed_scale > 0) {
                const int product_bits = key.Bout + key.fixed_scale;
                GroupElement extended_input = ring_extend(
                    party_id, input, product_bits, key.EvalExtendKeyList[0]);

                GroupElement raw_x_squared = beaver_mult_online(
                    party_id, extended_input, extended_input, key.EvalAList[0],
                    key.EvalBList[0], key.EvalCList[0], peer);
                GroupElement x_squared = truncate_and_reduce(
                    party_id, raw_x_squared, key.fixed_scale,
                    key.EvalScaleTRKeyList[0]);
                GroupElement x_squared_extended =
                    ring_extend(party_id, x_squared, product_bits,
                                key.EvalExtendKeyList[1]);

                GroupElement raw_ax_squared = beaver_mult_online(
                    party_id, lut_output[0], x_squared_extended,
                    key.EvalAList[1], key.EvalBList[1], key.EvalCList[1],
                    peer);
                GroupElement ax_squared = truncate_and_reduce(
                    party_id, raw_ax_squared, key.fixed_scale,
                    key.EvalScaleTRKeyList[1]);

                GroupElement raw_bx = beaver_mult_online(
                    party_id, lut_output[1], extended_input, key.EvalAList[2],
                    key.EvalBList[2], key.EvalCList[2], peer);
                GroupElement bz = truncate_and_reduce(
                    party_id, raw_bx, key.fixed_scale,
                    key.EvalScaleTRKeyList[2]);
                output = ax_squared + bz +
                         GroupElement(lut_output[2].value, key.Bout);
            } else {
                // Now reconstruct input on all intervals
                GroupElement extended_input =
                    key.EvalExtendKeyList == NULL
                        ? input
                        : ring_extend(party_id, input, random_mask.bitsize,
                                      key.EvalExtendKeyList[0]);
                GroupElement real_input = extended_input + random_mask;
                reconstruct(&real_input);
                output = lut_output[0] * real_input * real_input +
                         lut_output[1] * real_input + lut_output[2];
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

SplinePolyApproxKeyPack spline_poly_approx_offline_legacy_no_online_beaver(
    int party_id, int Bin, int Bout, const GroupElement* publicCoefficientList,
    int degree, int segNum, int fixed_scale) {
    // Deprecated baseline for performance comparisons only.
    //
    // This preserves the paper-style masked coefficient rewrite for the
    // fixed-point path, so online evaluation only multiplies selected secret
    // coefficients by public powers of z = x + r. It is not correctness-safe
    // for the current step-by-step fixed-point truncation semantics.
    if (fixed_scale == 0) {
        return spline_poly_approx_offline(
            party_id, Bin, Bout, publicCoefficientList, degree, segNum,
            fixed_scale);
    }
    if (degree != 2) {
        std::cout << "[ERROR] Unsupported approx degree!" << std::endl;
        exit(-1);
    }

    SplinePolyApproxKeyPack output;
    output.Bin = Bin;
    output.Bout = Bout;
    output.degNum = degree;
    output.segNum = segNum;
    output.fixed_scale = fixed_scale;
    output.EvalSignKeyList = NULL;
    output.EvalExtendKeyList = NULL;
    output.EvalScaleTRKeyList = NULL;
    output.EvalAList = NULL;
    output.EvalBList = NULL;
    output.EvalCList = NULL;

    output.coefficientList = makeKeyArray<GroupElement>(3 * segNum);
    GroupElement* coefficientList = output.coefficientList.data();
    auto rng = secure_prng();
    GroupElement random_mask = random_ge_from_prng(rng, Bin);

    const int product_bits = Bout + fixed_scale;
    GroupElement r_extended =
        zero_extend_shared_value(party_id, random_mask, product_bits);
    GroupElement rr_a(0, product_bits), rr_b(0, product_bits);
    GroupElement rr_c(0, product_bits);
    beaver_mult_offline(party_id, &rr_a, &rr_b, &rr_c, peer, 1);
    GroupElement rr_raw =
        beaver_mult_online(party_id, r_extended, r_extended, rr_a, rr_b, rr_c,
                           peer);
    TRKeyPack rr_tr_key =
        truncate_and_reduce_offline(party_id, product_bits, fixed_scale);
    GroupElement r_squared =
        truncate_and_reduce(party_id, rr_raw, fixed_scale, rr_tr_key);
    GroupElement r_squared_extended =
        zero_extend_shared_value(party_id, r_squared, product_bits);

    for (int i = 0; i < segNum; i++) {
        GroupElement public_a(publicCoefficientList[i].value, Bout);
        GroupElement public_b(publicCoefficientList[segNum + i].value, Bout);
        GroupElement public_c(publicCoefficientList[2 * segNum + i].value,
                              Bout);
        GroupElement public_a_extended =
            sign_extend_public_value(public_a, product_bits);
        GroupElement public_b_extended =
            sign_extend_public_value(public_b, product_bits);

        TRKeyPack ar_tr_key =
            truncate_and_reduce_offline(party_id, product_bits, fixed_scale);
        TRKeyPack br_tr_key =
            truncate_and_reduce_offline(party_id, product_bits, fixed_scale);
        TRKeyPack ar2_tr_key =
            truncate_and_reduce_offline(party_id, product_bits, fixed_scale);
        GroupElement ar = truncate_and_reduce(
            party_id, r_extended * public_a_extended, fixed_scale, ar_tr_key);
        GroupElement br = truncate_and_reduce(
            party_id, r_extended * public_b_extended, fixed_scale, br_tr_key);
        GroupElement ar2 = truncate_and_reduce(
            party_id, r_squared_extended * public_a_extended, fixed_scale,
            ar2_tr_key);

        coefficientList[i] = public_a * (uint64_t)(party_id - 2);
        coefficientList[segNum + i] =
            public_b * (uint64_t)(party_id - 2) - ar * 2;
        coefficientList[2 * segNum + i] =
            public_c * (uint64_t)(party_id - 2) + ar2 - br;
    }

    output.EvalSignKeyList = makeKeyArray<ComparisonKeyPack>(degree);
    output.EvalScaleTRKeyList = makeKeyArray<TRKeyPack>(degree);
    for (int i = 0; i < degree; i++) {
        output.EvalSignKeyList[i] =
            sign_extend_offline(party_id, Bout, product_bits);
        output.EvalScaleTRKeyList[i] =
            truncate_and_reduce_offline(party_id, product_bits, fixed_scale);
    }

    output.random_mask = random_mask;
    const int truncation_bits = Bin - log2floor(segNum);
    output.TRKey = truncate_and_reduce_offline(party_id, Bin, truncation_bits);
    output.PriLUTKeyList = makeKeyArray<PrivateLutKey>(degree + 1);
    for (int i = 0; i < degree + 1; i++) {
        output.PriLUTKeyList[i] = pri_lut_offline(
            party_id, log2ceil(segNum), Bout, &(coefficientList[i * segNum]));
    }

    return output;
}

GroupElement spline_poly_approx_legacy_no_online_beaver(
    int party_id, GroupElement input, const SplinePolyApproxKeyPack& key) {
    // Deprecated baseline for performance comparisons only. For fixed-point
    // Approx this can produce mask-dependent numerical errors.
    if (key.fixed_scale == 0) {
        return spline_poly_approx(party_id, input, key);
    }
    if (key.degNum != 2) {
        std::cout << "[ERROR] Unsupported approx degree!" << std::endl;
        exit(-1);
    }

    const int product_bits = key.Bout + key.fixed_scale;
    GroupElement truncated_input = truncate_and_reduce(
        party_id, input, input.bitsize - log2floor(key.segNum), key.TRKey);
    GroupElement lut_output[3];
    for (int i = 0; i < 3; i++) {
        lut_output[i] =
            pri_lut(party_id, truncated_input, key.PriLUTKeyList[i]);
    }

    GroupElement extended_input =
        zero_extend_shared_value(party_id, input, key.random_mask.bitsize);
    GroupElement real_input = extended_input + key.random_mask;
    reconstruct(&real_input);
    GroupElement real_input_base(real_input.value, key.Bout);
    GroupElement real_input_squared =
        scale_mult(real_input_base, real_input_base, key.fixed_scale);
    GroupElement real_input_extended =
        zero_extend_public_value(real_input_base, product_bits);
    GroupElement real_input_squared_extended =
        zero_extend_public_value(real_input_squared, product_bits);

    GroupElement coefficient_a = sign_extend_with_key(
        party_id, lut_output[0], product_bits, key.EvalSignKeyList[0]);
    GroupElement coefficient_b = sign_extend_with_key(
        party_id, lut_output[1], product_bits, key.EvalSignKeyList[1]);

    GroupElement az = truncate_and_reduce(
        party_id, coefficient_a * real_input_squared_extended,
        key.fixed_scale, key.EvalScaleTRKeyList[0]);
    GroupElement bz = truncate_and_reduce(
        party_id, coefficient_b * real_input_extended, key.fixed_scale,
        key.EvalScaleTRKeyList[1]);
    GroupElement output = az + bz + lut_output[2];

    return output;
}
