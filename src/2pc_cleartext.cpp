/*
 * Description:
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
#include "2pc_cleartext.h"

GroupElement inner_product(GroupElement* A, GroupElement* B, int size, int scale){
    GroupElement output(0, A[0].bitsize);
    for (int i = 0; i < size; i++){
        if (!(A[i].value == 0)){
            output = output + B[i];
        }
    }
    return output;
}

GroupElement cleartext_sin(GroupElement input, int scale, bool using_lut){
    assert (((scale - 1) % 2) == 0);
    int Bin = input.bitsize;
    GroupElement output(0, Bin);
    GroupElement _x_mod = segment(input, scale + 2).second;
    GroupElement two = GroupElement(2, 2 + scale, scale);
    GroupElement x_mod = _x_mod;
    if (_x_mod > two){
        x_mod = _x_mod - two;
    }
    GroupElement interval[4];
    for (int i = 0; i <4; i++){
        interval[i] = GroupElement(0, 2 + scale);
    }
    for (int i = 0; i < 4; i++){
        if (x_mod < GroupElement(0.5, 2 + scale, scale)){
            interval[0] = GroupElement(1, 2 + scale, scale);
        }
        if (x_mod > GroupElement(0.5, 2 + scale, scale) && x_mod < GroupElement(1, 2 + scale, scale)){
            interval[1] = GroupElement(1, 2 + scale, scale);
        }
        if (x_mod > GroupElement(1, 2 + scale, scale) && x_mod < GroupElement(1.5, 2 + scale, scale)){
            interval[2] = GroupElement(1, 2 + scale, scale);
        }
        if (x_mod > GroupElement(1.5, 2 + scale, scale)){
            interval[3] = GroupElement(1, 2 + scale, scale);
        }
    }
    GroupElement* trans_list = new GroupElement[12];
    // We start with aaaa
    create_approx_spline(0000, 2 + scale, scale, trans_list);
    GroupElement a = inner_product(interval, trans_list, 4, scale);
    GroupElement b = inner_product(interval, &(trans_list[4]), 4, scale);
    GroupElement c = inner_product(interval, &(trans_list[8]), 4, scale);

    GroupElement _x_frac = scale_mult(b, x_mod, scale) + c;
    GroupElement x_frac = segment(_x_frac, scale - 1).second;

    if (using_lut){
        GroupElement* sin_lut[2];
        GroupElement* cos_lut[2];
        sin_lut[0] = new GroupElement[1 << ((scale - 1) / 2)];
        sin_lut[1] = new GroupElement[1 << ((scale - 1) / 2)];
        cos_lut[0] = new GroupElement[1 << ((scale - 1) / 2)];
        cos_lut[1] = new GroupElement[1 << ((scale - 1) / 2)];

        create_sub_lut(0, (scale - 1), Bin, scale, 2, sin_lut);
        create_sub_lut(1, (scale - 1), Bin, scale, 2, cos_lut);

        // fetch value
        GroupElement x_high = segment(x_frac, (scale - 1) / 2).first;
        GroupElement x_low = segment(x_frac, (scale - 1) / 2).second;

        // sin(x+y) = sinxcosy+cosxsiny
        GroupElement dpf_x_high[1 << ((scale - 1) / 2)];
        GroupElement dpf_x_low[1 << ((scale - 1) / 2)];

        for (int i = 0; i < (1 << ((scale - 1) / 2)); i++){
            dpf_x_high[i] = GroupElement(0, Bin);
            dpf_x_low[i] = GroupElement(0, Bin);
        }

        dpf_x_high[x_high.value] = GroupElement(1, Bin, scale);
        dpf_x_low[x_low.value] = GroupElement(1, Bin, scale);

        GroupElement sin_x = inner_product(dpf_x_high, sin_lut[1], 1 << ((scale - 1) / 2), scale);
        GroupElement cos_y = inner_product(dpf_x_low, cos_lut[0], 1 << ((scale - 1) / 2), scale);
        GroupElement cos_x = inner_product(dpf_x_high, cos_lut[1], 1 << ((scale - 1) / 2), scale);
        GroupElement sin_y = inner_product(dpf_x_low, sin_lut[0], 1 << ((scale - 1) / 2), scale);

        GroupElement tmp_res = scale_mult(sin_x, cos_y, scale) + scale_mult(cos_x, sin_y, scale);

        output = scale_mult(tmp_res, a, scale);

        delete[] sin_lut[0];
        delete[] sin_lut[1];
        delete[] cos_lut[0];
        delete[] cos_lut[1];
    }else{
        GroupElement x_tr = segment(x_frac, scale - 5).first;
        GroupElement* coefs = new GroupElement[48];
        // Changed, scale - 1 to ell
        create_approx_spline(0216, Bin, scale, coefs);
        // ax2+bx+c -> ax2+(b-2ar)x+c+r2 ,def
        int r = 0;
        GroupElement mask = GroupElement(r, Bin, scale);
        mod(mask);
        for (int i = 0; i < 16; i++){
            coefs[16 + i] = coefs[16 + i] - scale_mult(coefs[i], mask, scale) - scale_mult(coefs[i], mask, scale);
            // coefs[16 + i] = coefs[16 + i] - scale_mult(scale_mult(coefs[i], mask, scale), GroupElement(2, scale - 1, scale), scale);
            coefs[32 + i] = coefs[32 + i] + scale_mult(mask, mask, scale);
        }
        // fecth coef
        GroupElement* dpf_output = new GroupElement[16];

        // Note: We modify here as 1 cannot be represented in Fixed-pt Arithmetic thus cause 0 output.
        // This modification do not affect the correctness of protocol as the implementation is priLUT with l_out bitlength.
        for (int i = 0; i < 16; i++){
            dpf_output[i] = GroupElement(0, Bin);
        }
        dpf_output[x_tr.value] = GroupElement(1, Bin);
        GroupElement d = inner_product(dpf_output, coefs, 16, scale);
        GroupElement e = inner_product(dpf_output, &(coefs[16]), 16, scale);
        GroupElement f = inner_product(dpf_output, &(coefs[32]), 16, scale);

        x_frac.bitsize = Bin;
        a.bitsize = Bin;
        GroupElement x2 = scale_mult(x_frac, x_frac, scale);
        GroupElement ax2 = scale_mult(d, x2, scale);
        GroupElement bx = scale_mult(e, x_frac, scale);
        GroupElement tmp_res = ax2 + bx + f;
        output = scale_mult(tmp_res, a, scale);
        delete[] coefs;
        delete[] dpf_output;
    }


    delete[] trans_list;
    return output;
}

GroupElement cleartext_cosine(GroupElement input, int scale, bool using_lut){
    assert (((scale - 1) % 2) == 0);
    int Bin = input.bitsize;
    GroupElement output(0, Bin);
    GroupElement _x_mod = segment(input, scale + 2).second;
    GroupElement two = GroupElement(2, 2 + scale, scale);
    GroupElement x_mod = _x_mod;
    if (_x_mod > two){
        x_mod = _x_mod - two;
    }
    GroupElement interval[4];
    for (int i = 0; i <4; i++){
        interval[i] = GroupElement(0, 2 + scale);
    }
    for (int i = 0; i < 4; i++){
        if (x_mod < GroupElement(0.5, 2 + scale, scale)){
            interval[0] = GroupElement(1, 2 + scale, scale);
        }
        if (x_mod > GroupElement(0.5, 2 + scale, scale) && x_mod < GroupElement(1, 2 + scale, scale)){
            interval[1] = GroupElement(1, 2 + scale, scale);
        }
        if (x_mod > GroupElement(1, 2 + scale, scale) && x_mod < GroupElement(1.5, 2 + scale, scale)){
            interval[2] = GroupElement(1, 2 + scale, scale);
        }
        if (x_mod > GroupElement(1.5, 2 + scale, scale)){
            interval[3] = GroupElement(1, 2 + scale, scale);
        }
    }
    GroupElement* trans_list = new GroupElement[12];
    // We start with aaaa
    create_approx_spline(1000, 2 + scale, scale, trans_list);
    GroupElement a = inner_product(interval, trans_list, 4, scale);
    GroupElement b = inner_product(interval, &(trans_list[4]), 4, scale);
    GroupElement c = inner_product(interval, &(trans_list[8]), 4, scale);

    GroupElement _x_frac = scale_mult(b, x_mod, scale) + c;
    GroupElement x_frac = segment(_x_frac, scale - 1).second;

    if (using_lut){
        GroupElement* sin_lut[2];
        GroupElement* cos_lut[2];
        sin_lut[0] = new GroupElement[1 << ((scale - 1) / 2)];
        sin_lut[1] = new GroupElement[1 << ((scale - 1) / 2)];
        cos_lut[0] = new GroupElement[1 << ((scale - 1) / 2)];
        cos_lut[1] = new GroupElement[1 << ((scale - 1) / 2)];

        create_sub_lut(0, (scale - 1), Bin, scale, 2, sin_lut);
        create_sub_lut(1, (scale - 1), Bin, scale, 2, cos_lut);

        // fetch value
        GroupElement x_high = segment(x_frac, (scale - 1) / 2).first;
        GroupElement x_low = segment(x_frac, (scale - 1) / 2).second;

        // cos(x+y) = cosxcosy-sinxsiny
        GroupElement dpf_x_high[1 << ((scale - 1) / 2)];
        GroupElement dpf_x_low[1 << ((scale - 1) / 2)];

        for (int i = 0; i < (1 << ((scale - 1) / 2)); i++){
            dpf_x_high[i] = GroupElement(0, Bin);
            dpf_x_low[i] = GroupElement(0, Bin);
        }

        dpf_x_high[x_high.value] = GroupElement(1, Bin, scale);
        dpf_x_low[x_low.value] = GroupElement(1, Bin, scale);

        GroupElement sin_x = inner_product(dpf_x_high, sin_lut[1], 1 << ((scale - 1) / 2), scale);
        GroupElement cos_y = inner_product(dpf_x_low, cos_lut[0], 1 << ((scale - 1) / 2), scale);
        GroupElement cos_x = inner_product(dpf_x_high, cos_lut[1], 1 << ((scale - 1) / 2), scale);
        GroupElement sin_y = inner_product(dpf_x_low, sin_lut[0], 1 << ((scale - 1) / 2), scale);

        GroupElement tmp_res = scale_mult(cos_x, cos_y, scale) - scale_mult(sin_x, sin_y, scale);

        output = scale_mult(tmp_res, a, scale);

        delete[] sin_lut[0];
        delete[] sin_lut[1];
        delete[] cos_lut[0];
        delete[] cos_lut[1];
    }else{
        GroupElement x_tr = segment(x_frac, scale - 5).first;
        GroupElement* coefs = new GroupElement[48];
        // Changed, scale - 1 to ell
        create_approx_spline(1216, Bin, scale, coefs);
        // ax2+bx+c -> ax2+(b-2ar)x+c+r2 ,def
        int r = 0;
        GroupElement mask = GroupElement(r, Bin, scale);
        mod(mask);
        for (int i = 0; i < 16; i++){
            coefs[16 + i] = coefs[16 + i] - scale_mult(coefs[i], mask, scale) - scale_mult(coefs[i], mask, scale);
            // coefs[16 + i] = coefs[16 + i] - scale_mult(scale_mult(coefs[i], mask, scale), GroupElement(2, scale - 1, scale), scale);
            coefs[32 + i] = coefs[32 + i] + scale_mult(mask, mask, scale);
        }
        // fecth coef
        GroupElement dpf_output[16];

        // Note: We modify here as 1 cannot be represented in Fixed-pt Arithmetic thus cause 0 output.
        // This modification do not affect the correctness of protocol as the implementation is priLUT with l_out bitlength.
        for (int i = 0; i < 16; i++){
            dpf_output[i] = GroupElement(0, Bin);
        }
        dpf_output[x_tr.value] = GroupElement(1, Bin);
        GroupElement d = inner_product(dpf_output, coefs, 16, scale);
        GroupElement e = inner_product(dpf_output, &(coefs[16]), 16, scale);
        GroupElement f = inner_product(dpf_output, &(coefs[32]), 16, scale);

        x_frac.bitsize = Bin;
        a.bitsize = Bin;
        GroupElement x2 = scale_mult(x_frac, x_frac, scale);
        GroupElement ax2 = scale_mult(d, x2, scale);
        GroupElement bx = scale_mult(e, x_frac, scale);
        GroupElement tmp_res = ax2 + bx + f;
        output = scale_mult(tmp_res, a, scale);
        delete[] coefs;
    }


    delete[] trans_list;
    return output;
}

GroupElement cleartext_tangent(GroupElement input, int scale, bool using_lut){
    int Bin = input.bitsize;
    GroupElement output(0, Bin);
    GroupElement _x_mod = segment(input, scale + 1).second;
    GroupElement one = GroupElement(1, 1 + scale, scale);
    GroupElement x_mod = _x_mod;
    if (_x_mod > one){
        x_mod = _x_mod - one;
    }
    GroupElement interval[2];
    for (int i = 0; i < 2; i++){
        interval[i] = GroupElement(0, 1 + scale);
    }
    for (int i = 0; i < 2; i++){
        if (x_mod < GroupElement(0.5, 1 + scale, scale)){
            interval[0] = GroupElement(1, 1 + scale, scale);
        }else{
            interval[1] = GroupElement(1, 1 + scale, scale);
        }
    }
    GroupElement* trans_list = new GroupElement[6];
    // We start with aaaa
    create_approx_spline(2000, 1 + scale, scale, trans_list);
    GroupElement a = inner_product(interval, trans_list, 2, scale);
    GroupElement b = inner_product(interval, &(trans_list[2]), 2, scale);
    GroupElement c = inner_product(interval, &(trans_list[4]), 2, scale);

    GroupElement _x_frac = scale_mult(b, x_mod, scale, false) + c;
    GroupElement x_frac = segment(_x_frac, scale - 1).second;

    if (using_lut){
        GroupElement* tan_lut[1];
        tan_lut[0] = new GroupElement[1 << (scale - 1)];

        create_sub_lut(2, (scale - 1), Bin, scale, 1, tan_lut);

        // fetch value
        GroupElement dpf_x[1 << ((scale - 1))];

        for (int i = 0; i < (1 << ((scale - 1))); i++){
            dpf_x[i] = GroupElement(0, Bin);
        }

        dpf_x[x_frac.value] = GroupElement(1, Bin, scale);

        GroupElement tan_x = inner_product(dpf_x, tan_lut[0],  1 << ((scale - 1)), scale);

        // TODO: Add check for isSigned instead of hard coding.
        output = scale_mult(tan_x, a, scale, false);

        delete[] tan_lut[0];
    }else{
        GroupElement x_tr = segment(x_frac, scale - 5).first;
        GroupElement* coefs = new GroupElement[48];
        // Changed, scale - 1 to ell
        create_approx_spline(2216, Bin, scale, coefs);
        // ax2+bx+c -> ax2+(b-2ar)x+c+r2 ,def
        int r = 0;
        GroupElement mask = GroupElement(r, Bin, scale);
        mod(mask);
        for (int i = 0; i < 16; i++){
            coefs[16 + i] = coefs[16 + i] - scale_mult(coefs[i], mask, scale) - scale_mult(coefs[i], mask, scale);
            coefs[32 + i] = coefs[32 + i] + scale_mult(mask, mask, scale);
        }
        // fecth coef
        GroupElement dpf_output[16];

        // Note: We modify here as 1 cannot be represented in Fixed-pt Arithmetic thus cause 0 output.
        // This modification do not affect the correctness of protocol as the implementation is priLUT with l_out bitlength.
        for (int i = 0; i < 16; i++){
            dpf_output[i] = GroupElement(0, Bin);
        }
        dpf_output[x_tr.value] = GroupElement(1, Bin);
        GroupElement d = inner_product(dpf_output, coefs, 16, scale);
        GroupElement e = inner_product(dpf_output, &(coefs[16]), 16, scale);
        GroupElement f = inner_product(dpf_output, &(coefs[32]), 16, scale);

        x_frac.bitsize = Bin;
        a.bitsize = Bin;
        GroupElement x2 = scale_mult(x_frac, x_frac, scale);
        GroupElement ax2 = scale_mult(d, x2, scale);
        GroupElement bx = scale_mult(e, x_frac, scale);
        GroupElement tmp_res = ax2 + bx + f;
        output = scale_mult(tmp_res, a, scale);
        delete[] coefs;
    }


    delete[] trans_list;
    return output;
}

int cleartext_proximity(GroupElement xA, GroupElement yA, GroupElement xB, GroupElement yB, int scale, bool using_lut){
    // delta = sin^2 pi [(xA-xB)/2] + cos pi xA * cos pi xB * sin^2 pi [(yA-yB)/2]
    // MPC calculation
    if (xB.value > xA.value){
        int tmp = xB.value;
        xB.value = xA.value;
        xA.value = tmp;
    }
    if (yB.value > yA.value){
        int tmp = yB.value;
        yB.value = yA.value;
        yA.value = tmp;
    }

    GroupElement front_input = scale_mult((xA - xB), GroupElement(0.5, xA.bitsize, scale), scale);
    GroupElement back_input = scale_mult((yA - yB), GroupElement(0.5, xA.bitsize, scale), scale);
    GroupElement _front_output = cleartext_sin(front_input, scale, using_lut);
    GroupElement front_output = scale_mult(_front_output, _front_output, scale);
    GroupElement _back_output_0 = cleartext_cosine(xA, scale, using_lut);
    GroupElement _back_output_1 = cleartext_cosine(xB, scale, using_lut);
    GroupElement _back_output_2 = cleartext_sin(back_input, scale, using_lut);
    GroupElement back_output_0 = scale_mult(_back_output_0, _back_output_1, scale);
    GroupElement back_output_1 = scale_mult(_back_output_2, _back_output_2, scale);
    GroupElement back_output = scale_mult(back_output_0, back_output_1, scale);
    GroupElement output = front_output + back_output;

    // Lib calculation
    float real_xA = decode_from_ge_binary(xA, xA.bitsize, scale);
    float real_xB = decode_from_ge_binary(xB, xB.bitsize, scale);
    float real_yA = decode_from_ge_binary(yA, yA.bitsize, scale);
    float real_yB = decode_from_ge_binary(yB, yB.bitsize, scale);
    float _lib_output = sin(M_PI * (real_xA - real_xB) / 2) * sin(M_PI * (real_xA - real_xB) / 2)
            + cos(M_PI * real_xA) * cos(M_PI * real_xB) * sin(M_PI * (real_yA - real_yB) / 2)
            * sin(M_PI * (real_yA - real_yB) / 2);
    GroupElement lib_output = encode_to_ge_binary(_lib_output, xA.bitsize, scale);

    return get_ulp(output, lib_output);
}

int cleartext_biometric(GroupElement xA, GroupElement yA, GroupElement xB, GroupElement yB,
                        int scale, bool using_lut) {
    GroupElement z0 = cleartext_tangent(xA, scale, using_lut);
    GroupElement z1 = cleartext_tangent(xB, scale, using_lut);
    GroupElement z2 = cleartext_tangent(yA, scale, using_lut);
    GroupElement z3 = cleartext_tangent(yB, scale, using_lut);

    float real_xA = decode_from_ge_binary(xA, xA.bitsize, scale);
    float real_xB = decode_from_ge_binary(xB, xB.bitsize, scale);
    float real_yA = decode_from_ge_binary(yA, yA.bitsize, scale);
    float real_yB = decode_from_ge_binary(yB, yB.bitsize, scale);

    float _lib_output_0 = tan(M_PI * real_xA);
    float _lib_output_1 = tan(M_PI * real_xB);
    float _lib_output_2 = tan(M_PI * real_yA);
    float _lib_output_3 = tan(M_PI * real_yB);

    GroupElement lib_output_0 = encode_to_ge_binary(_lib_output_0, xA.bitsize, scale);
    GroupElement lib_output_1 = encode_to_ge_binary(_lib_output_1, xB.bitsize, scale);
    GroupElement lib_output_2 = encode_to_ge_binary(_lib_output_2, yA.bitsize, scale);
    GroupElement lib_output_3 = encode_to_ge_binary(_lib_output_3, yB.bitsize, scale);

    return get_ulp(z0, lib_output_0) + get_ulp(z1, lib_output_1) + get_ulp(z2, lib_output_2) + get_ulp(z3, lib_output_3);

}