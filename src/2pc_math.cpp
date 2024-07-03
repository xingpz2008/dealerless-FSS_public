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
        output.EvalAllKeyList = EvalAllKeyList;
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
        //GroupElement* shifted_vector_list[digdec_segNum];
        GroupElement** shifted_vector_list = new GroupElement * [digdec_segNum];
        GroupElement** publicSinList = new GroupElement * [digdec_segNum];
        GroupElement** publicCosList = new GroupElement * [digdec_segNum];
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
            //std::cout << "Iteration i = " << i << ", dicdec_segNum = " << digdec_segNum << std::endl;
            //std::cout << "x_seg[i] = " << x_seg[i].value << std::endl;
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
                GroupElement mulA[2] = {sin_lut_output[0], cos_lut_output[0]};
                GroupElement mulB[2] = {cos_lut_output[1], sin_lut_output[1]};
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
    //freeSineKeyPack(key);
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
        output.EvalAllKeyList = EvalAllKeyList;
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
        int approx_uuid = 1 * 1000 + approx_deg * 100 + approx_segNum;
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

GroupElement cosine(int party_id, GroupElement input, CosineKeyPack key){
    // This is the implementation of cosine pi * x
    GroupElement output(0, input.bitsize);
    GroupElement x_ = segment(input, key.scale + 2).second;
    GroupElement x_mod = modular(party_id, x_, (2 * key.scale % (1ULL<<input.bitsize)), key.ModKey);
    GroupElement* v = new GroupElement[4];
    containment(party_id, x_mod, v, 3, key.CtnKey);
    GroupElement* transform_coefficients = new GroupElement[3 * 4];
    for (int i = 0; i < 12; i++){
        transform_coefficients[i].bitsize = key.scale + 2;
    }
    create_approx_spline(1000, key.scale + 2, key.scale, transform_coefficients);
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
                GroupElement mulA[2] = {cos_lut_output[0], sin_lut_output[0]};
                GroupElement mulB[2] = {cos_lut_output[1], sin_lut_output[1]};
                beaver_mult_online(party_id, mulA, mulB, key.AList, key.BList,
                                   key.CList, y_, 2, peer);
                y_0 = y_[0] - y_[1];
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
    //freeCosineKeyPack(key);
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
        // Note: this new bitsize is used for truncation, not digdec!
        // assert((scale - 1) / digdec_new_bitsize == approx_segNum);
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
    GroupElement* first_knots_list = new GroupElement[1];
    for (int i = 0; i < 1; i++){
        first_knots_list[i] = GroupElement(0.5 * (i + 1), 1 + scale, scale);
    }
    // if we apply approx spline, the range should be 0 - 0.5
    output.CtnKey = containment_offline(party_id, 1 + scale, first_knots_list, 1);

    output.MTList_len = MTList_len;
    GroupElement* AList = new GroupElement[MTList_len];
    GroupElement* BList = new GroupElement[MTList_len];
    GroupElement* CList = new GroupElement[MTList_len];
    // The bit size of MTs are different, for specialized transformation, it requires 1 Bout, 1 (2+s)
    // For MTs on digdec, we need bit size = Bout
    for (int i = 0; i < MTList_len; i++){
        AList[i].bitsize = (i == MTList_len - 1) ? Bout : (1 + scale);
        BList[i].bitsize = (i == MTList_len - 1) ? Bout : (1 + scale);
        CList[i].bitsize = (i == MTList_len - 1) ? Bout : (1 + scale);
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

GroupElement tangent(int party_id, GroupElement input, TangentKeyPack key){
    // This is the implementation of tangent pi * x
    GroupElement output(0, input.bitsize);
    GroupElement x_ = segment(input, key.scale + 1).second;
    GroupElement x_mod = modular(party_id, x_, (2 * key.scale % (1ULL<<input.bitsize)), key.ModKey);
    GroupElement* v = new GroupElement[2];
    containment(party_id, x_mod, v, 1, key.CtnKey);
    GroupElement* transform_coefficients = new GroupElement[3 * 2];
    for (int i = 0; i < 6; i++){
        transform_coefficients[i].bitsize = key.scale + 1;
    }
    create_approx_spline(2000, key.scale + 1, key.scale, transform_coefficients);
    // Compute coefficients
    GroupElement m[3];
    for (int i = 0; i < 3; i++){
        m[i].bitsize = key.scale + 2;
        m[i].value = 0;
        for (int j = 0; j < 2; j++){
            m[i] = m[i] + (v[j] * transform_coefficients[i * 2 + j]);
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
        key.digdec_new_bitsize = key.scale - 1;
        GroupElement* x_seg = new GroupElement[digdec_segNum];
        x_seg[0] = x_frac;
        // For each segment, call lut, x_seg 0 is the lowest segment
        // Here we want the shifted_vector, so call it at once
        GroupElement** shifted_vector_list = new GroupElement * [digdec_segNum];
        GroupElement** publicTanList = new GroupElement * [digdec_segNum];
        GroupElement* tan_lut_output = new GroupElement[digdec_segNum];
        for (int i = 0; i < digdec_segNum; i++){
            shifted_vector_list[i] = new GroupElement[1 << key.digdec_new_bitsize];
            publicTanList[i] = new GroupElement[1 << key.digdec_new_bitsize];
        }
        create_sub_lut(2, key.digdec_new_bitsize, input.bitsize, key.scale,
                       digdec_segNum, publicTanList);
        for (int i = 0; i < digdec_segNum; i++){
            //std::cout << "Iteration i = " << i << ", dicdec_segNum = " << digdec_segNum << std::endl;
            //std::cout << "x_seg[i] = " << x_seg[i].value << std::endl;
            tan_lut_output[i] = pub_lut(party_id, x_seg[i], publicTanList[i],
                                        shifted_vector_list[i], 1 << key.digdec_new_bitsize,
                                        input.bitsize, key.EvalAllKeyList[i]);
        }
        for (int i = 0; i < digdec_segNum; i++) {
            delete[] shifted_vector_list[i];
            delete[] publicTanList[i];
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
    //freeTangentKeyPack(key);
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
    beaver_mult_offline(party_id, output.Alist, output.Blist, output.Clist, peer, 4);

    return output;
}

GroupElement proximity(int party_id, GroupElement xA, GroupElement yA, GroupElement xB, GroupElement yB,
                       ProximityKeyPack key){
    // delta = sin^2 pi [(xA-xB)/2] + cos pi xA * cos pi xB * sin^2 pi [(yA-yB)/2]
    int scale = key.scale;
    GroupElement front_input = scale_mult((xA - xB), GroupElement(0.5, xA.bitsize, scale), scale);
    GroupElement back_input = scale_mult((yA - yB), GroupElement(0.5, xA.bitsize, scale), scale);
    GroupElement _front_output = sine(party_id, front_input, key.SineKeyList[0]);

    GroupElement _back_output_0 = cosine(party_id, xA, key.CosineKeyList[0]);
    GroupElement _back_output_1 = cosine(party_id, xB, key.CosineKeyList[1]);
    GroupElement _back_output_2 = sine(party_id, back_input, key.SineKeyList[1]);

    GroupElement* mulA = new GroupElement[3];
    GroupElement* mulB = new GroupElement[3];
    GroupElement* batch_mul_output = new GroupElement[3];
    mulA[0] = _front_output;
    mulA[1] = _back_output_0;
    mulA[2] = _back_output_2;
    mulB[0] = _front_output;
    mulB[1] = _back_output_1;
    mulB[2] = _back_output_2;
    for (int i = 0; i < 3; i++){
        batch_mul_output[i].bitsize = key.Bin;
    }
    beaver_mult_online(party_id, mulA, mulB, key.Alist, key.Blist, key.Clist, batch_mul_output,
                       3, peer);

    GroupElement front_output = batch_mul_output[0];
    GroupElement* back_output = new GroupElement(0, key.Bin);
    beaver_mult_online(party_id, batch_mul_output[1], batch_mul_output[2], key.Alist[3], key.Blist[3],
                       key.Clist[3], back_output, peer);
    GroupElement output = front_output + *back_output;

    // freeProximityKeyPack(key);
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
               GroupElement* output, BiometricKeyPack key){
    tangent(party_id, xA, key.TangentKeyList[0]);
    tangent(party_id, xB, key.TangentKeyList[1]);
    tangent(party_id, yA, key.TangentKeyList[2]);
    tangent(party_id, yB, key.TangentKeyList[3]);
}