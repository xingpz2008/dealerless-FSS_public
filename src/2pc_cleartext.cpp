//
// Created by root on 4/28/24.
//
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
    // std::cout << "Claer sin." << std::endl;
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
        sin_lut[0] = new GroupElement[1 << (Bin / 2)];
        sin_lut[1] = new GroupElement[1 << (Bin / 2)];
        cos_lut[0] = new GroupElement[1 << (Bin / 2)];
        cos_lut[1] = new GroupElement[1 << (Bin / 2)];

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