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

#include "2pc_math.h"

namespace {

void use_raw_transform_slopes(GroupElement* coefficients, int interval_count,
                              int scale) {
    const int scale_factor = 1 << scale;
    for (int group = 0; group < 2; group++) {
        for (int interval = 0; interval < interval_count; interval++) {
            GroupElement& coefficient =
                coefficients[group * interval_count + interval];
            coefficient = GroupElement(
                getSignedValue(coefficient) / scale_factor, coefficient.bitsize);
        }
    }
}

void set_raw_tangent_transform(GroupElement* coefficients, int bitsize, int scale) {
    coefficients[0] = GroupElement(1, bitsize);
    coefficients[1] = GroupElement(-1, bitsize);
    coefficients[2] = GroupElement(1, bitsize);
    coefficients[3] = GroupElement(-1, bitsize);
    coefficients[4] = GroupElement(0, bitsize);
    coefficients[5] = GroupElement(1, bitsize, scale);
}

void set_raw_sine_transform(GroupElement* coefficients, int bitsize, int scale) {
    coefficients[0] = GroupElement(1, bitsize);
    coefficients[1] = GroupElement(1, bitsize);
    coefficients[2] = GroupElement(1, bitsize);
    coefficients[3] = GroupElement(-1, bitsize);
    coefficients[4] = GroupElement(1, bitsize);
    coefficients[5] = GroupElement(-1, bitsize);
    coefficients[6] = GroupElement(1, bitsize);
    coefficients[7] = GroupElement(-1, bitsize);
    coefficients[8] = GroupElement(0, bitsize, scale);
    coefficients[9] = GroupElement(1, bitsize, scale);
    coefficients[10] = GroupElement(-1, bitsize, scale);
    coefficients[11] = GroupElement(2, bitsize, scale);
}

void set_raw_cosine_transform(GroupElement* coefficients, int bitsize, int scale) {
    coefficients[0] = GroupElement(1, bitsize);
    coefficients[1] = GroupElement(-1, bitsize);
    coefficients[2] = GroupElement(-1, bitsize);
    coefficients[3] = GroupElement(1, bitsize);
    coefficients[4] = GroupElement(1, bitsize);
    coefficients[5] = GroupElement(-1, bitsize);
    coefficients[6] = GroupElement(1, bitsize);
    coefficients[7] = GroupElement(-1, bitsize);
    coefficients[8] = GroupElement(0, bitsize, scale);
    coefficients[9] = GroupElement(1, bitsize, scale);
    coefficients[10] = GroupElement(-1, bitsize, scale);
    coefficients[11] = GroupElement(2, bitsize, scale);
}

GroupElement project_ring(GroupElement value, int bitsize) {
    return GroupElement(value.value, bitsize);
}

}  // namespace

SineKeyPack sine_offline(int party_id, int Bin, int Bout, int scale, bool using_lut,
                         int digdec_new_bitsize, int approx_segNum, int approx_deg){
    // This function is the offline stage of sine
    // params: segNum -> DigDec SegNum; approx_segNum -> approximation seg Num
    SineKeyPack output;
    output.Bin = Bin;
    output.scale = scale;
    output.using_lut = using_lut;
    output.Bout = Bout;
    output.LUTProductTRKeyList = NULL;
    output.ModExtendKey = ring_extend_offline(party_id, scale + 1, scale + 2);
    // First, we need a mod key
    output.ModKey = modular_offline(party_id, GroupElement(2, Bin, scale), 2 + scale);
    int MTList_len = 2;
    if (using_lut){
        output.digdec_new_bitsize = digdec_new_bitsize;
        output.approx_segNum = -1;
        output.approx_deg = -1;
        // create dig dec keys
        output.DigDecKey = digdec_offline(party_id, scale - 1, digdec_new_bitsize);
        int digdec_segNum = (scale - 1) / digdec_new_bitsize + (((scale - 1) % digdec_new_bitsize == 0) ? 0 : 1);
        DPFKeyPack* EvalAllKeyList = new DPFKeyPack[digdec_segNum];
        const int product_bits = Bout + scale;
        for (int i = 0; i < digdec_segNum; i++){
            // Here we need random idx at r, which do not require mask because it was used in EvalAll.
            EvalAllKeyList[i] =
                pub_lut_offline(party_id, digdec_new_bitsize, product_bits);
        }
        output.EvalAllKeyList = EvalAllKeyList;
        output.LUTProductTRKeyList = new TRKeyPack[2];
        for (int i = 0; i < 2; i++) {
            output.LUTProductTRKeyList[i] =
                truncate_and_reduce_offline(party_id, product_bits, scale);
        }
        // Prepare MTs for digdec combination
        // There are the need of 2 MTs for specialized transformation.
        if (digdec_segNum < 5){
            MTList_len += (digdec_segNum - 1) * (1 << (digdec_segNum - 1));
        }else{
            std::cout << "[ERROR] Digit Decomposition only supports 0-4 segments." << std::endl;
            exit(-1);
        }
    }else{
        const int approx_eval_bits =
            fixed_point_approx_eval_bits(Bout, scale);
        // Note: this new bitsize is used for truncation, not digdec!
        // assert((scale - 1) / digdec_new_bitsize == approx_segNum);
        output.digdec_new_bitsize = digdec_new_bitsize;
        output.approx_segNum = approx_segNum;
        output.approx_deg = approx_deg;
        // We only have poly_seg - 1 knots_list for poly_approx
        output.EvalAllKeyList = NULL;
        // Generate spline approx key
        // The first step is to construct public coefficient list
        // uuid encoding: f+d+s<2>
        // (f)unction : 0->sin, 1->cos, 2->tan
        // (d)egree : 1 / 2
        // (s)egNum: 02, 04, 08, 16, 32, 64
        // Example: 0216 = 2 deg poly-approx to sine with 16 segs
        // create uuid
        int approx_uuid = 0 * 1000 + approx_deg * 100 + approx_segNum;
        GroupElement* publicCoefficientList = new GroupElement[(1 + approx_deg) * approx_segNum];
        create_approx_spline(approx_uuid, approx_eval_bits, scale,
                             publicCoefficientList);
        output.SplineApproxKey = spline_poly_approx_offline(
            party_id, scale - 1, approx_eval_bits, publicCoefficientList,
            approx_deg, approx_segNum, scale);
        delete[] publicCoefficientList;
    }
    // One containment key determines the half-period interval. Its output is
    // locally projected into the evaluation and transform rings as needed.
    GroupElement* first_knots_list = new GroupElement[3];
    for (int i = 0; i < 3; i++){
        first_knots_list[i] = GroupElement(0.5 * (i + 1), 2 + scale, scale);
    }
    // if we apply approx spline, the range should be 0 - 0.5
    const int approx_eval_bits =
        using_lut ? Bout : output.SplineApproxKey.Bout;
    const int ctn_bits =
        approx_eval_bits > 2 + scale ? approx_eval_bits : 2 + scale;
    output.CtnKey =
        containment_offline_public(party_id, ctn_bits, first_knots_list, 3);

    output.MTList_len = MTList_len;
    GroupElement* AList = new GroupElement[MTList_len];
    GroupElement* BList = new GroupElement[MTList_len];
    GroupElement* CList = new GroupElement[MTList_len];
    // The bit size of MTs are different, for specialized transformation, it requires 1 Bout, 1 (2+s)
    // For MTs on digdec, we need bit size = Bout
    for (int i = 0; i < MTList_len; i++){
        AList[i].bitsize =
            (i == MTList_len - 1) ? (2 + scale) : approx_eval_bits;
        BList[i].bitsize =
            (i == MTList_len - 1) ? (2 + scale) : approx_eval_bits;
        CList[i].bitsize =
            (i == MTList_len - 1) ? (2 + scale) : approx_eval_bits;
    }
    if (using_lut) {
        for (int i = 0; i < 2; i++) {
            AList[i].bitsize = Bout + scale;
            BList[i].bitsize = Bout + scale;
            CList[i].bitsize = Bout + scale;
        }
    }
    if (using_lut) {
        beaver_mult_offline(party_id, AList, BList, CList, peer, 2);
        beaver_mult_offline(party_id, &(AList[MTList_len - 2]),
                            &(BList[MTList_len - 2]), &(CList[MTList_len - 2]),
                            peer, 1);
    } else {
        beaver_mult_offline(party_id, AList, BList, CList, peer, MTList_len - 1);
    }
    beaver_mult_offline(party_id, &(AList[MTList_len - 1]), &(BList[MTList_len - 1]), &(CList[MTList_len - 1]),
                        peer, 1);
    output.AList = AList;
    output.BList = BList;
    output.CList = CList;

    delete[] first_knots_list;

    return output;
}

GroupElement sine(int party_id, GroupElement input, const SineKeyPack& key){
    // This is the implementation of sine pi * x
    GroupElement output(0, input.bitsize);
    GroupElement x_mod = ring_extend(
        party_id, segment(input, key.scale + 1).second, key.scale + 2,
        key.ModExtendKey);
    GroupElement* v = new GroupElement[4];
    containment(party_id, x_mod, v, 3, key.CtnKey);
    GroupElement* transform_coefficients = new GroupElement[3 * 4];
    for (int i = 0; i < 12; i++){
        transform_coefficients[i].bitsize = key.scale + 2;
    }
    set_raw_sine_transform(transform_coefficients, key.scale + 2, key.scale);
    // Compute coefficients
    GroupElement m[3];
    const int transform_bits = key.scale + 2;
    const int eval_bits =
        key.using_lut ? key.Bout : key.SplineApproxKey.Bout;
    for (int i = 0; i < 3; i++){
        m[i].bitsize = i == 0 ? eval_bits : transform_bits;
        m[i].value = 0;
        for (int j = 0; j < 4; j++){
            if (i == 0) {
                GroupElement sign(getSignedValue(transform_coefficients[j]),
                                  eval_bits);
                m[i] = m[i] + project_ring(v[j], eval_bits) * sign;
            } else {
                m[i] = m[i] +
                       project_ring(v[j], transform_bits) *
                           transform_coefficients[i * 4 + j];
            }
        }
    }
    GroupElement* x_transform = new GroupElement(0, key.scale + 2);
    beaver_mult_online(party_id, m[1], x_mod, key.AList[key.MTList_len - 1], key.BList[key.MTList_len - 1],
                       key.CList[key.MTList_len - 1], x_transform, peer);
    *x_transform = *x_transform + m[2];
    GroupElement x_frac = segment(*x_transform, key.scale - 1).second;
    GroupElement y_0 = GroupElement(0, input.bitsize);
    if (key.using_lut){
        // Call digdec first
        int digdec_segNum = (key.scale - 1) / key.digdec_new_bitsize +
                (((key.scale - 1) % key.digdec_new_bitsize == 0) ? 0 : 1);
        GroupElement* x_seg = new GroupElement[digdec_segNum];
        digdec(party_id, x_frac, x_seg, key.digdec_new_bitsize, key.DigDecKey);
        // For each segment, call lut, x_seg 0 is the lowest segment
        // Here we want the shifted_vector, so call it at once
        GroupElement** shifted_vector_list = new GroupElement * [digdec_segNum];
        GroupElement** publicSinList = new GroupElement * [digdec_segNum];
        GroupElement** publicCosList = new GroupElement * [digdec_segNum];
        GroupElement sin_lut_output[digdec_segNum];
        GroupElement cos_lut_output[digdec_segNum];
        const int lut_output_bits = input.bitsize + key.scale;
        for (int i = 0; i < digdec_segNum; i++){
            shifted_vector_list[i] = new GroupElement[1 << key.digdec_new_bitsize];
            publicSinList[i] = new GroupElement[1 << key.digdec_new_bitsize];
            publicCosList[i] = new GroupElement[1 << key.digdec_new_bitsize];
        }
        create_sub_lut(0, key.scale - 1, lut_output_bits, key.scale,
                       digdec_segNum, publicSinList);
        create_sub_lut(1, key.scale - 1, lut_output_bits, key.scale,
                       digdec_segNum, publicCosList);
        for (int i = 0; i < digdec_segNum; i++){
            // We evaluate sin, for cos, we just use the vector to do inner product
            sin_lut_output[i] = pub_lut(party_id, x_seg[i], publicSinList[i],
                                        shifted_vector_list[i], 1 << key.digdec_new_bitsize,
                                        lut_output_bits, key.EvalAllKeyList[i]);
            cos_lut_output[i].bitsize = sin_lut_output[i].bitsize;
            cos_lut_output[i].value = 0;
            for (int j = 0; j < 1 << key.digdec_new_bitsize; j++){
                cos_lut_output[i] = cos_lut_output[i] + shifted_vector_list[i][j] * publicCosList[i][j];
            }
        }
        GroupElement y_[2] = {GroupElement(0, input.bitsize), GroupElement(0, input.bitsize)};
        // Reconstruct the lut output
        switch (digdec_segNum) {
            case 2:{
                GroupElement mulA[2] = {sin_lut_output[0], cos_lut_output[0]};
                GroupElement mulB[2] = {cos_lut_output[1], sin_lut_output[1]};
                beaver_mult_online(party_id, mulA, mulB, key.AList, key.BList,
                                   key.CList, y_, 2, peer);
                GroupElement scaled_products[] = {
                    truncate_and_reduce(
                        party_id, y_[0], key.scale, key.LUTProductTRKeyList[0]),
                    truncate_and_reduce(
                        party_id, y_[1], key.scale, key.LUTProductTRKeyList[1]),
                };
                y_0 = scaled_products[0] + scaled_products[1];
                break;
            }
        }
        for (int i = 0; i < digdec_segNum; i++) {
            delete[] shifted_vector_list[i];
            delete[] publicSinList[i];
            delete[] publicCosList[i];
        }
        delete[] shifted_vector_list;
        delete[] publicSinList;
        delete[] publicCosList;
        delete[] x_seg;
    }else{
        y_0 = spline_poly_approx(party_id, x_frac, key.SplineApproxKey);
    }
    beaver_mult_online(party_id, m[0], y_0, key.AList[key.MTList_len - 2],
                       key.BList[key.MTList_len - 2],key.CList[key.MTList_len - 2],
                       &output, peer);
    if (!key.using_lut && key.SplineApproxKey.Bout != key.Bout) {
        output = GroupElement(output.value, key.Bout);
    }

    delete[] v;
    delete[] transform_coefficients;
    delete x_transform;
    return output;
}

CosineKeyPack cosine_offline(int party_id, int Bin, int Bout, int scale, bool using_lut,
                             int digdec_new_bitsize, int approx_segNum, int approx_deg){
    // This function is the offline stage of sine
    // params: segNum -> DigDec SegNum; approx_segNum -> approximation seg Num
    CosineKeyPack output;
    output.Bin = Bin;
    output.scale = scale;
    output.using_lut = using_lut;
    output.Bout = Bout;
    output.LUTProductTRKeyList = NULL;
    output.ModExtendKey = ring_extend_offline(party_id, scale + 1, scale + 2);
    // First, we need a mod key
    output.ModKey = modular_offline(party_id, GroupElement(2, Bin, scale), 2 + scale);
    int MTList_len = 2;
    if (using_lut){
        output.digdec_new_bitsize = digdec_new_bitsize;
        output.approx_segNum = -1;
        output.approx_deg = -1;
        // create dig dec keys
        output.DigDecKey = digdec_offline(party_id, scale - 1, digdec_new_bitsize);
        int digdec_segNum = (scale - 1) / digdec_new_bitsize + (((scale - 1) % digdec_new_bitsize == 0) ? 0 : 1);
        DPFKeyPack* EvalAllKeyList = new DPFKeyPack[digdec_segNum];
        const int product_bits = Bout + scale;
        for (int i = 0; i < digdec_segNum; i++){
            // Here we need random idx at r, which do not require mask because it was used in EvalAll.
            EvalAllKeyList[i] =
                pub_lut_offline(party_id, digdec_new_bitsize, product_bits);
        }
        output.EvalAllKeyList = EvalAllKeyList;
        output.LUTProductTRKeyList = new TRKeyPack[2];
        for (int i = 0; i < 2; i++) {
            output.LUTProductTRKeyList[i] =
                truncate_and_reduce_offline(party_id, product_bits, scale);
        }
        // Prepare MTs for digdec combination
        // There are the need of 2 MTs for specialized transformation.
        if (digdec_segNum < 5){
            MTList_len += (digdec_segNum - 1) * (1 << (digdec_segNum - 1));
        }else{
            std::cout << "[ERROR] Digit Decomposition only supports 0-4 segments." << std::endl;
            exit(-1);
        }
    }else{
        const int approx_eval_bits =
            fixed_point_approx_eval_bits(Bout, scale);
        // Note: this new bitsize is used for truncation, not digdec!
        output.digdec_new_bitsize = digdec_new_bitsize;
        output.approx_segNum = approx_segNum;
        output.approx_deg = approx_deg;
        // We only have poly_seg - 1 knots_list for poly_approx
        output.EvalAllKeyList = NULL;
        // Generate spline approx key
        // The first step is to construct public coefficient list
        // uuid encoding: f+d+s<2>
        // (f)unction : 0->sin, 1->cos, 2->tan
        // (d)egree : 1 / 2
        // (s)egNum: 02, 04, 08, 16, 32, 64
        // Example: 0216 = 2 deg poly-approx to sine with 16 segs
        // create uuid
        int approx_uuid = 1 * 1000 + approx_deg * 100 + approx_segNum;
        GroupElement* publicCoefficientList = new GroupElement[(1 + approx_deg) * approx_segNum];
        create_approx_spline(approx_uuid, approx_eval_bits, scale,
                             publicCoefficientList);
        output.SplineApproxKey = spline_poly_approx_offline(
            party_id, scale - 1, approx_eval_bits, publicCoefficientList,
            approx_deg, approx_segNum, scale);
        delete[] publicCoefficientList;
    }
    // One containment key determines the half-period interval. Its output is
    // locally projected into the evaluation and transform rings as needed.
    GroupElement* first_knots_list = new GroupElement[3];
    for (int i = 0; i < 3; i++){
        first_knots_list[i] = GroupElement(0.5 * (i + 1), 2 + scale, scale);
    }
    // if we apply approx spline, the range should be 0 - 0.5
    const int approx_eval_bits =
        using_lut ? Bout : output.SplineApproxKey.Bout;
    const int ctn_bits =
        approx_eval_bits > 2 + scale ? approx_eval_bits : 2 + scale;
    output.CtnKey =
        containment_offline_public(party_id, ctn_bits, first_knots_list, 3);

    output.MTList_len = MTList_len;
    GroupElement* AList = new GroupElement[MTList_len];
    GroupElement* BList = new GroupElement[MTList_len];
    GroupElement* CList = new GroupElement[MTList_len];
    // The bit size of MTs are different, for specialized transformation, it requires 1 Bout, 1 (2+s)
    // For MTs on digdec, we need bit size = Bout
    for (int i = 0; i < MTList_len; i++){
        AList[i].bitsize =
            (i == MTList_len - 1) ? (2 + scale) : approx_eval_bits;
        BList[i].bitsize =
            (i == MTList_len - 1) ? (2 + scale) : approx_eval_bits;
        CList[i].bitsize =
            (i == MTList_len - 1) ? (2 + scale) : approx_eval_bits;
    }
    if (using_lut) {
        for (int i = 0; i < 2; i++) {
            AList[i].bitsize = Bout + scale;
            BList[i].bitsize = Bout + scale;
            CList[i].bitsize = Bout + scale;
        }
    }
    if (using_lut) {
        beaver_mult_offline(party_id, AList, BList, CList, peer, 2);
        beaver_mult_offline(party_id, &(AList[MTList_len - 2]),
                            &(BList[MTList_len - 2]), &(CList[MTList_len - 2]),
                            peer, 1);
    } else {
        beaver_mult_offline(party_id, AList, BList, CList, peer, MTList_len - 1);
    }
    beaver_mult_offline(party_id, &(AList[MTList_len - 1]), &(BList[MTList_len - 1]), &(CList[MTList_len - 1]),
                        peer, 1);
    output.AList = AList;
    output.BList = BList;
    output.CList = CList;

    delete[] first_knots_list;

    return output;
}

GroupElement cosine(int party_id, GroupElement input, const CosineKeyPack& key){
    // This is the implementation of cosine pi * x
    GroupElement output(0, input.bitsize);
    GroupElement x_mod = ring_extend(
        party_id, segment(input, key.scale + 1).second, key.scale + 2,
        key.ModExtendKey);
    GroupElement* v = new GroupElement[4];
    containment(party_id, x_mod, v, 3, key.CtnKey);
    GroupElement* transform_coefficients = new GroupElement[3 * 4];
    for (int i = 0; i < 12; i++){
        transform_coefficients[i].bitsize = key.scale + 2;
    }
    set_raw_cosine_transform(transform_coefficients, key.scale + 2, key.scale);
    // Compute coefficients
    GroupElement m[3];
    const int transform_bits = key.scale + 2;
    const int eval_bits =
        key.using_lut ? key.Bout : key.SplineApproxKey.Bout;
    for (int i = 0; i < 3; i++){
        m[i].bitsize = i == 0 ? eval_bits : transform_bits;
        m[i].value = 0;
        for (int j = 0; j < 4; j++){
            if (i == 0) {
                GroupElement sign(getSignedValue(transform_coefficients[j]),
                                  eval_bits);
                m[i] = m[i] + project_ring(v[j], eval_bits) * sign;
            } else {
                m[i] = m[i] +
                       project_ring(v[j], transform_bits) *
                           transform_coefficients[i * 4 + j];
            }
        }
    }
    GroupElement* x_transform = new GroupElement(0, key.scale + 2);
    beaver_mult_online(party_id, m[1], x_mod, key.AList[key.MTList_len - 1], key.BList[key.MTList_len - 1],
                       key.CList[key.MTList_len - 1], x_transform, peer);
    *x_transform = *x_transform + m[2];
    GroupElement x_frac = segment(*x_transform, key.scale - 1).second;
    GroupElement y_0 = GroupElement(0, input.bitsize);
    if (key.using_lut){
        // Call digdec first
        int digdec_segNum = (key.scale - 1) / key.digdec_new_bitsize +
                            (((key.scale - 1) % key.digdec_new_bitsize == 0) ? 0 : 1);
        GroupElement* x_seg = new GroupElement[digdec_segNum];
        digdec(party_id, x_frac, x_seg, key.digdec_new_bitsize, key.DigDecKey);
        // For each segment, call lut, x_seg 0 is the lowest segment
        // Here we want the shifted_vector, so call it at once
        GroupElement* shifted_vector_list[digdec_segNum];
        GroupElement* publicSinList[digdec_segNum];
        GroupElement* publicCosList[digdec_segNum];
        GroupElement sin_lut_output[digdec_segNum];
        GroupElement cos_lut_output[digdec_segNum];
        const int lut_output_bits = input.bitsize + key.scale;
        for (int i = 0; i < digdec_segNum; i++){
            shifted_vector_list[i] = new GroupElement[1 << key.digdec_new_bitsize];
            publicSinList[i] = new GroupElement[1 << key.digdec_new_bitsize];
            publicCosList[i] = new GroupElement[1 << key.digdec_new_bitsize];
        }
        create_sub_lut(0, key.scale - 1, lut_output_bits, key.scale,
                       digdec_segNum, publicSinList);
        create_sub_lut(1, key.scale - 1, lut_output_bits, key.scale,
                       digdec_segNum, publicCosList);
        for (int i = 0; i < digdec_segNum; i++){
            // We evaluate sin, for cos, we just use the vector to do inner product
            sin_lut_output[i] = pub_lut(party_id, x_seg[i], publicSinList[i],
                                        shifted_vector_list[i], 1 << key.digdec_new_bitsize,
                                        lut_output_bits, key.EvalAllKeyList[i]);
            cos_lut_output[i].bitsize = sin_lut_output[i].bitsize;
            cos_lut_output[i].value = 0;
            for (int j = 0; j < 1 << key.digdec_new_bitsize; j++){
                cos_lut_output[i] = cos_lut_output[i] + shifted_vector_list[i][j] * publicCosList[i][j];
            }
        }
        GroupElement y_[2] = {GroupElement(0, input.bitsize), GroupElement(0, input.bitsize)};
        // Reconstruct the lut output
        switch (digdec_segNum) {
            case 2:{
                GroupElement mulA[2] = {cos_lut_output[0], sin_lut_output[0]};
                GroupElement mulB[2] = {cos_lut_output[1], sin_lut_output[1]};
                beaver_mult_online(party_id, mulA, mulB, key.AList, key.BList,
                                   key.CList, y_, 2, peer);
                GroupElement scaled_products[] = {
                    truncate_and_reduce(
                        party_id, y_[0], key.scale, key.LUTProductTRKeyList[0]),
                    truncate_and_reduce(
                        party_id, y_[1], key.scale, key.LUTProductTRKeyList[1]),
                };
                y_0 = scaled_products[0] - scaled_products[1];
                break;
            }
        }
        for (int i = 0; i < digdec_segNum; i++) {
            delete[] shifted_vector_list[i];
            delete[] publicSinList[i];
            delete[] publicCosList[i];
        }
        delete[] x_seg;
    }else{
        y_0 = spline_poly_approx(party_id, x_frac, key.SplineApproxKey);
    }
    beaver_mult_online(party_id, m[0], y_0, key.AList[key.MTList_len - 2],
                       key.BList[key.MTList_len - 2],key.CList[key.MTList_len - 2],
                       &output, peer);
    if (!key.using_lut && key.SplineApproxKey.Bout != key.Bout) {
        output = GroupElement(output.value, key.Bout);
    }

    delete[] v;
    delete[] transform_coefficients;
    delete x_transform;
    return output;
}

TangentKeyPack tangent_offline(int party_id, int Bin, int Bout, int scale, bool using_lut,
                               int approx_segNum, int approx_deg){
    // This function is the offline stage of tangent
    // params: segNum -> DigDec SegNum; approx_segNum -> approximation seg Num
    TangentKeyPack output;
    output.Bin = Bin;
    output.scale = scale;
    output.using_lut = using_lut;
    output.Bout = Bout;
    output.LUTProductTRKeyList = NULL;
    output.ModExtendKey = ring_extend_offline(party_id, scale, scale + 1);
    // First, we need a mod key
    output.ModKey = modular_offline(party_id, GroupElement(1, Bin, scale), 1 + scale);
    int MTList_len = 2;
    if (using_lut){
        output.digdec_new_bitsize = -1;
        output.approx_segNum = -1;
        output.approx_deg = -1;
        DPFKeyPack* EvalAllKeyList = new DPFKeyPack[1];
        for (int i = 0; i < 1; i++){
            // Digit Decomposition is inapplicable for tangent.
            // Here we need random idx at r, which do not require mask because it was used in EvalAll.
            EvalAllKeyList[i] = pub_lut_offline(party_id, (scale - 1), Bout);
        }
        output.EvalAllKeyList = EvalAllKeyList;
    }else{
        const int approx_eval_bits =
            fixed_point_approx_eval_bits(Bout, scale);
        // Note: this new bitsize is used for truncation, not digdec!
        output.digdec_new_bitsize = -1;
        output.approx_segNum = approx_segNum;
        output.approx_deg = approx_deg;
        // We only have poly_seg - 1 knots_list for poly_approx
        output.EvalAllKeyList = NULL;
        // Generate spline approx key
        // The first step is to construct public coefficient list
        // uuid encoding: f+d+s<2>
        // (f)unction : 0->sin, 1->cos, 2->tan
        // (d)egree : 1 / 2
        // (s)egNum: 02, 04, 08, 16, 32, 64
        // Example: 0216 = 2 deg poly-approx to sine with 16 segs
        // create uuid
        int approx_uuid = 2 * 1000 + approx_deg * 100 + approx_segNum;
        GroupElement* publicCoefficientList = new GroupElement[(1 + approx_deg) * approx_segNum];
        create_approx_spline(approx_uuid, approx_eval_bits, scale,
                             publicCoefficientList);
        output.SplineApproxKey = spline_poly_approx_offline(
            party_id, scale - 1, approx_eval_bits, publicCoefficientList,
            approx_deg, approx_segNum, scale);
        delete[] publicCoefficientList;
    }
    // One containment key determines the half-period interval. Its output is
    // locally projected into the evaluation and transform rings as needed.
    GroupElement* first_knots_list = new GroupElement[1];
    for (int i = 0; i < 1; i++){
        first_knots_list[i] = GroupElement(0.5 * (i + 1), 1 + scale, scale);
    }
    // if we apply approx spline, the range should be 0 - 0.5
    const int approx_eval_bits =
        using_lut ? Bout : output.SplineApproxKey.Bout;
    const int ctn_bits =
        approx_eval_bits > 1 + scale ? approx_eval_bits : 1 + scale;
    output.CtnKey =
        containment_offline_public(party_id, ctn_bits, first_knots_list, 1);

    output.MTList_len = MTList_len;
    GroupElement* AList = new GroupElement[MTList_len];
    GroupElement* BList = new GroupElement[MTList_len];
    GroupElement* CList = new GroupElement[MTList_len];
    // The bit size of MTs are different, for specialized transformation, it requires 1 Bout, 1 (2+s)
    // For MTs on digdec, we need bit size = Bout
    for (int i = 0; i < MTList_len; i++){
        AList[i].bitsize =
            (i == MTList_len - 1) ? (1 + scale) : approx_eval_bits;
        BList[i].bitsize =
            (i == MTList_len - 1) ? (1 + scale) : approx_eval_bits;
        CList[i].bitsize =
            (i == MTList_len - 1) ? (1 + scale) : approx_eval_bits;
    }
    beaver_mult_offline(party_id, AList, BList, CList, peer, MTList_len - 1);
    beaver_mult_offline(party_id, &(AList[MTList_len - 1]), &(BList[MTList_len - 1]), &(CList[MTList_len - 1]),
                        peer, 1);
    output.AList = AList;
    output.BList = BList;
    output.CList = CList;

    delete[] first_knots_list;

    return output;
}

GroupElement tangent(int party_id, GroupElement input, const TangentKeyPack& key){
    // This is the implementation of tangent pi * x
    GroupElement output(0, input.bitsize);
    GroupElement x_mod = ring_extend(
        party_id, segment(input, key.scale).second, key.scale + 1,
        key.ModExtendKey);
    GroupElement* v = new GroupElement[2];
    containment(party_id, x_mod, v, 1, key.CtnKey);
    GroupElement* transform_coefficients = new GroupElement[3 * 2];
    for (int i = 0; i < 6; i++){
        transform_coefficients[i].bitsize = key.scale + 1;
    }
    create_approx_spline(2000, key.scale + 1, key.scale, transform_coefficients);
    set_raw_tangent_transform(transform_coefficients, key.scale + 1, key.scale);
    // Compute coefficients
    GroupElement m[3];
    const int transform_bits = key.scale + 1;
    const int eval_bits =
        key.using_lut ? key.Bout : key.SplineApproxKey.Bout;
    for (int i = 0; i < 3; i++){
        m[i].bitsize = i == 0 ? eval_bits : transform_bits;
        m[i].value = 0;
        for (int j = 0; j < 2; j++){
            if (i == 0) {
                GroupElement sign(getSignedValue(transform_coefficients[j]),
                                  eval_bits);
                m[i] = m[i] + project_ring(v[j], eval_bits) * sign;
            } else {
                m[i] = m[i] +
                       project_ring(v[j], transform_bits) *
                           transform_coefficients[i * 2 + j];
            }
        }
    }
    GroupElement* x_transform = new GroupElement(0, key.scale + 1);
    beaver_mult_online(party_id, m[1], x_mod, key.AList[key.MTList_len - 1], key.BList[key.MTList_len - 1],
                       key.CList[key.MTList_len - 1], x_transform, peer);
    *x_transform = *x_transform + m[2];
    GroupElement x_frac = segment(*x_transform, key.scale - 1).second;
    GroupElement y_0 = GroupElement(0, input.bitsize);
    if (key.using_lut){
        // Call digdec first
        int digdec_segNum = 1;
        const int tangent_lut_bits = key.scale - 1;
        GroupElement* x_seg = new GroupElement[digdec_segNum];
        x_seg[0] = x_frac;
        // For each segment, call lut, x_seg 0 is the lowest segment
        // Here we want the shifted_vector, so call it at once
        GroupElement** shifted_vector_list = new GroupElement * [digdec_segNum];
        GroupElement** publicTanList = new GroupElement * [digdec_segNum];
        GroupElement* tan_lut_output = new GroupElement[digdec_segNum];
        for (int i = 0; i < digdec_segNum; i++){
            shifted_vector_list[i] = new GroupElement[1 << tangent_lut_bits];
            publicTanList[i] = new GroupElement[1 << tangent_lut_bits];
        }
        create_sub_lut(2, tangent_lut_bits, input.bitsize, key.scale,
                       digdec_segNum, publicTanList);
        for (int i = 0; i < digdec_segNum; i++){
            tan_lut_output[i] = pub_lut(party_id, x_seg[i], publicTanList[i],
                                        shifted_vector_list[i], 1 << tangent_lut_bits,
                                        input.bitsize, key.EvalAllKeyList[i]);
        }
        y_0 = tan_lut_output[0];
        for (int i = 0; i < digdec_segNum; i++) {
            delete[] shifted_vector_list[i];
            delete[] publicTanList[i];
        }
        delete[] shifted_vector_list;
        delete[] publicTanList;
        delete[] tan_lut_output;
        delete[] x_seg;
    }else{
        y_0 = spline_poly_approx(party_id, x_frac, key.SplineApproxKey);
    }
    beaver_mult_online(party_id, m[0], y_0, key.AList[key.MTList_len - 2],
                       key.BList[key.MTList_len - 2],key.CList[key.MTList_len - 2],
                       &output, peer);
    if (!key.using_lut && key.SplineApproxKey.Bout != key.Bout) {
        output = GroupElement(output.value, key.Bout);
    }

    delete[] v;
    delete[] transform_coefficients;
    delete x_transform;
    return output;
}

ProximityKeyPack proximity_offline(int party_id, int Bin, int scale, bool using_lut, int digdec_new_bitsize,
                                   int approx_segNum, int approx_deg){
    // delta = sin^2 pi [(xA-xB)/2] + cos pi xA * cos pi xB * sin^2 pi [(yA-yB)/2]
    ProximityKeyPack output;

    output.Bin = Bin;
    output.Bout = Bin;
    output.scale = scale;

    output.SineKeyList = new SineKeyPack[2];
    output.SineKeyList[0] = sine_offline(party_id, Bin, Bin, scale, using_lut, digdec_new_bitsize,
                                         approx_segNum, approx_deg);
    output.SineKeyList[1] = sine_offline(party_id, Bin, Bin, scale, using_lut, digdec_new_bitsize,
                                         approx_segNum, approx_deg);

    output.CosineKeyList = new CosineKeyPack[2];
    output.CosineKeyList[0] = cosine_offline(party_id, Bin, Bin, scale, using_lut, digdec_new_bitsize,
                                             approx_segNum, approx_deg);
    output.CosineKeyList[1] = cosine_offline(party_id, Bin, Bin, scale, using_lut, digdec_new_bitsize,
                                             approx_segNum, approx_deg);

    output.Alist = new GroupElement[4];
    output.Blist = new GroupElement[4];
    output.Clist = new GroupElement[4];
    output.ProductTRKeyList = new TRKeyPack[4];
    output.ProductExtendKeyList = new ComparisonKeyPack[6];
    const int product_bits = Bin + scale;
    for (int i = 0; i < 4; i++) {
        output.Alist[i].bitsize = product_bits;
        output.Blist[i].bitsize = product_bits;
        output.Clist[i].bitsize = product_bits;
        output.ProductTRKeyList[i] = truncate_and_reduce_offline(party_id, product_bits, scale);
    }
    for (int i = 0; i < 4; i++) {
        output.ProductExtendKeyList[i] =
            ring_extend_offline(party_id, Bin, product_bits);
    }
    for (int i = 4; i < 6; i++) {
        output.ProductExtendKeyList[i] =
            ring_extend_offline(party_id, Bin, product_bits);
    }
    beaver_mult_offline(party_id, output.Alist, output.Blist, output.Clist, peer, 4);

    return output;
}

GroupElement proximity(int party_id, GroupElement xA, GroupElement yA, GroupElement xB, GroupElement yB,
                       const ProximityKeyPack& key){
    // delta = sin^2 pi [(xA-xB)/2] + cos pi xA * cos pi xB * sin^2 pi [(yA-yB)/2]
    int scale = key.scale;
    GroupElement front_input = scale_mult((xA - xB), GroupElement(0.5, xA.bitsize, scale), scale);
    GroupElement back_input = scale_mult((yA - yB), GroupElement(0.5, xA.bitsize, scale), scale);
    GroupElement _front_output = sine(party_id, front_input, key.SineKeyList[0]);

    GroupElement _back_output_0 = cosine(party_id, xA, key.CosineKeyList[0]);
    GroupElement _back_output_1 = cosine(party_id, xB, key.CosineKeyList[1]);
    GroupElement _back_output_2 = sine(party_id, back_input, key.SineKeyList[1]);

    const int product_bits = key.Bin + scale;
    GroupElement* mulA = new GroupElement[3];
    GroupElement* mulB = new GroupElement[3];
    GroupElement* batch_mul_output = new GroupElement[3];
    GroupElement front_extended = ring_extend(
        party_id, _front_output, product_bits, key.ProductExtendKeyList[0]);
    GroupElement back_cos_0_extended = ring_extend(
        party_id, _back_output_0, product_bits, key.ProductExtendKeyList[1]);
    GroupElement back_sin_extended = ring_extend(
        party_id, _back_output_2, product_bits, key.ProductExtendKeyList[2]);
    GroupElement back_cos_1_extended = ring_extend(
        party_id, _back_output_1, product_bits, key.ProductExtendKeyList[3]);

    mulA[0] = front_extended;
    mulA[1] = back_cos_0_extended;
    mulA[2] = back_sin_extended;
    mulB[0] = front_extended;
    mulB[1] = back_cos_1_extended;
    mulB[2] = back_sin_extended;
    for (int i = 0; i < 3; i++){
        batch_mul_output[i].bitsize = product_bits;
    }
    beaver_mult_online(party_id, mulA, mulB, key.Alist, key.Blist, key.Clist, batch_mul_output,
                       3, peer);

    GroupElement front_output = truncate_and_reduce(party_id, batch_mul_output[0], scale,
                                                    key.ProductTRKeyList[0]);
    GroupElement back_output_0 = truncate_and_reduce(party_id, batch_mul_output[1], scale,
                                                     key.ProductTRKeyList[1]);
    GroupElement back_output_1 = truncate_and_reduce(party_id, batch_mul_output[2], scale,
                                                     key.ProductTRKeyList[2]);
    GroupElement* back_output = new GroupElement(0, product_bits);
    beaver_mult_online(party_id,
                       ring_extend(party_id, back_output_0, product_bits,
                                   key.ProductExtendKeyList[4]),
                       ring_extend(party_id, back_output_1, product_bits,
                                   key.ProductExtendKeyList[5]),
                       key.Alist[3], key.Blist[3], key.Clist[3],
                       back_output, peer);
    GroupElement back_output_truncated = truncate_and_reduce(party_id, *back_output, scale,
                                                             key.ProductTRKeyList[3]);
    GroupElement output = front_output + back_output_truncated;

    delete[] mulA;
    delete[] mulB;
    delete[] batch_mul_output;
    delete back_output;
    return output;
}

BiometricKeyPack biometric_offline(int party_id, int Bin, int scale, bool using_lut,
                                   int approx_segNum, int approx_deg) {
    BiometricKeyPack output;

    output.Bin = Bin;
    output.Bout = Bin;
    output.scale = scale;
    output.using_lut = using_lut;

    output.TangentKeyList = new TangentKeyPack[4];
    for (int i = 0; i < 4; i++){
        output.TangentKeyList[i] = tangent_offline(party_id, Bin, Bin, scale, using_lut, approx_segNum, approx_deg);
    }

    return output;
}

void biometric(int party_id, GroupElement xA, GroupElement yA, GroupElement xB, GroupElement yB,
               GroupElement* output, const BiometricKeyPack& key){
    tangent(party_id, xA, key.TangentKeyList[0]);
    tangent(party_id, xB, key.TangentKeyList[1]);
    tangent(party_id, yA, key.TangentKeyList[2]);
    tangent(party_id, yB, key.TangentKeyList[3]);
}
