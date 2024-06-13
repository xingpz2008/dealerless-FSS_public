//
// Created by root on 4/16/24.
//

#include "2pc_math.h"

SineKeyPack sine_offline(int party_id, int Bin, int Bout, int scale, bool using_lut,
                         int digdec_new_bitsize, int approx_segNum, int approx_deg){
    // This function is the offline stage of sine
    // params: segNum -> DigDec SegNum; approx_segNum -> approximation seg Num
    SineKeyPack output;
    output.Bin = Bin;
    output.scale = scale;
    output.using_lut = using_lut;
    output.Bout = Bout;
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
        for (int i = 0; i < digdec_segNum; i++){
            // Here we need random idx at r, which do not require mask because it was used in EvalAll.
            EvalAllKeyList[i] = pub_lut_offline(party_id, digdec_new_bitsize, Bout);
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
        create_approx_spline(approx_uuid, scale - 1, scale, publicCoefficientList);
        output.SplineApproxKey = spline_poly_approx_offline(party_id, scale - 1, Bout, publicCoefficientList,
                                                            approx_deg, approx_segNum);
        delete[] publicCoefficientList;
    }
    // Then, we need containment key. How many containment key do we need?
    // Correction: We do not apply digdec when using approx
    // LUT : only one ctn key; Approx: 2
    // The first CTN is to determine which half period the input belongs to
    // The following CTN is to determine which spline of approx the input belongs to.
    GroupElement* first_knots_list = new GroupElement[3];
    for (int i = 0; i < 3; i++){
        first_knots_list[i] = GroupElement(0.5 * (i + 1), 2 + scale, scale);
    }
    // if we apply approx spline, the range should be 0 - 0.5
    output.CtnKey = containment_offline(party_id, 2 + scale, first_knots_list, 3);

    output.MTList_len = MTList_len;
    GroupElement* AList = new GroupElement[MTList_len];
    GroupElement* BList = new GroupElement[MTList_len];
    GroupElement* CList = new GroupElement[MTList_len];
    // The bit size of MTs are different, for specialized transformation, it requires 1 Bout, 1 (2+s)
    // For MTs on digdec, we need bit size = Bout
    for (int i = 0; i < MTList_len; i++){
        AList[i].bitsize = (i == MTList_len - 1) ? Bout : (2 + scale);
        BList[i].bitsize = (i == MTList_len - 1) ? Bout : (2 + scale);
        CList[i].bitsize = (i == MTList_len - 1) ? Bout : (2 + scale);
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

GroupElement sine(int party_id, GroupElement input, SineKeyPack key){
    // This is the implementation of sine pi * x
    GroupElement output(0, input.bitsize);
    GroupElement x_ = segment(input, key.scale + 2).second;
    GroupElement x_mod = modular(party_id, x_, (2 * key.scale % (1ULL<<input.bitsize)), key.ModKey);
    GroupElement* v = new GroupElement[4];
    containment(party_id, x_mod, v, 3, key.CtnKey);
    GroupElement* transform_coefficients = new GroupElement[3 * 4];
    for (int i = 0; i < 12; i++){
        transform_coefficients[i].bitsize = key.scale + 2;
    }
    create_approx_spline(0000, key.scale + 2, key.scale, transform_coefficients);
    // Compute coefficients
    GroupElement m[3];
    for (int i = 0; i < 3; i++){
        m[i].bitsize = key.scale + 2;
        m[i].value = 0;
        for (int j = 0; j < 4; j++){
            m[i] = m[i] + (v[j] * transform_coefficients[i * 4 + j]);
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
        for (int i = 0; i < digdec_segNum; i++){
            shifted_vector_list[i] = new GroupElement[1 << key.digdec_new_bitsize];
            publicSinList[i] = new GroupElement[1 << key.digdec_new_bitsize];
            publicCosList[i] = new GroupElement[1 << key.digdec_new_bitsize];
        }
        create_sub_lut(0, key.digdec_new_bitsize, input.bitsize, key.scale,
                       digdec_segNum, publicSinList);
        create_sub_lut(1, key.digdec_new_bitsize, input.bitsize, key.scale,
                       digdec_segNum, publicCosList);
        for (int i = 0; i < digdec_segNum; i++){
            // We evaluate sin, for cos, we just use the vector to do inner product
            sin_lut_output[i] = pub_lut(party_id, x_seg[i], publicSinList[i],
                                        shifted_vector_list[i], 1 << key.digdec_new_bitsize,
                                        input.bitsize, key.EvalAllKeyList[i]);
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
                GroupElement mulA[2] = {sin_lut_output[0], cos_lut_output[1]};
                GroupElement mulB[2] = {cos_lut_output[0], sin_lut_output[1]};
                beaver_mult_online(party_id, mulA, mulB, key.AList, key.BList,
                                   key.CList, y_, 2, peer);
                y_0 = y_[0] + y_[1];
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
                       key.AList[key.MTList_len - 2],key.AList[key.MTList_len - 2],
                       &output, peer);

    delete[] v;
    delete[] transform_coefficients;
    delete x_transform;
    return output;
}
