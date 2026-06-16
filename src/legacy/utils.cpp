/*
Original Authors: Deepak Kumaraswamy, Kanav Gupta
Modified by: Pengzhi Xing
Copyright:
Original Copyright (c) 2022 Microsoft Research
Copyright (c) 2024 Pengzhi Xing
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include "legacy/utils.h"
#include <assert.h>
#include <cstdlib>
#include <iostream>
#include <math.h>

int64_t getSignedValue(GroupElement x) {
    if (x.bitsize == 64) {
        return static_cast<int64_t>(x.value);
    }
    int msb = x[0];
    x.value = x.value % ((uint64_t)1 << x.bitsize);
    int64_t val = x.value;
    if (msb == 1) {
        val = val - ((uint64_t)1 << x.bitsize);
    }
    return val;
}

int fixed_point_approx_eval_bits(int output_bits, int scale) {
    int eval_bits = output_bits + scale + 3;
    const int max_product_safe_bits = 63;
    if (eval_bits + scale > max_product_safe_bits) {
        eval_bits = max_product_safe_bits - scale;
    }
    if (eval_bits < output_bits) {
        eval_bits = output_bits;
    }
    return eval_bits;
}

void create_approx_spline(int uuid, int bitsize, int scale, GroupElement* coefficientList){
    // uuid encoding: f+d+s<2>
    // (f)unction : 0->sin, 1->cos, 2->tan
    // (d)egree : 1 / 2
    // (s)egNum: 02, 04, 08, 16, 32, 64
    // Example: 0216 = 2 deg poly-approx to sine with 16 segs

    // parse uuid
    int deg = (uuid % 1000) / 100;
    int seg = uuid % 100;
    int list_size = (1 + deg) * seg;
    switch (uuid) {
        case 216:{
            // 0216 = 2 deg poly-approx to sine with 16 segs
            // list size = 3 * 16 = 48
            float list[] = {-2.4207849687076878e-1,-7.2390414238067667e-1,-1.1987581953565418,-1.6620675517525636,-2.1093702892801631,-2.5363586381721683,-2.9389204673831886,-3.3131788867008045,-3.6555295833987529,-3.9626755339118653,-4.2316587563840384,-4.45988879875165,-4.6451676897725758,-4.7857111218260835,-4.8801657387902724,-4.9276246922600206,
                            3.1444284283908551,3.1745197788901646,3.2338312499498127,3.3206343716408515,3.4323712252858902,3.5656956610169006,3.7165273849992784,3.8801181849002004,4.0511293964863269,4.2237195597007684,4.3916410711697527,4.5483445137737446,4.6870892350940041,4.8010586618294626,4.8834788340360662,4.9277408790262802,
                            -4.9216377766292095e-6,-4.8453936502295579e-4,-0.0023462618160401219,-0.0064214190445875076,-0.013408514536218837,-0.023824618470484598,-0.037961186931876514,-0.055845433416165845,-0.077208278279919537,-0.10145978194275898,-0.1276728305540428,-0.15457569066602336,-0.1805538848120348,-0.20366166671457289,-0.22164321030738637,-0.23196402094954596};
            list_size = 48;
            for (int i = 0; i < list_size; i++){
                coefficientList[i] = GroupElement(list[i], bitsize, scale);
            }
            break;
        }
        case 1216:{
            // 1216 = 2 deg poly-approx to cosine with 16 segs
            float list[] = {-4.9276246922600206,-4.8801657387902724,-4.7857111218260835,-4.6451676897725758,-4.45988879875165,-4.2316587563840384,-3.9626755339118653,-3.6555295833987529,-3.3131788867008045,-2.9389204673831886,-2.5363586381721683,-2.1093702892801631,-1.6620675517525636,-1.1987581953565418,-0.72390414238067669,-0.24207849687076877,
            -0.00011618676625937336,-0.0033130952457940651,-0.015347540003379066,-0.041921545321428007,-0.08845571502209483,-0.15998231478571429,-0.26104402578890284,-0.39559981308757364,-0.56693929819939581,-0.77760691761608991,-1.0293370228447323,-1.3230009360057271,-1.6585668198882877,-2.0350730545932709,-2.4506156365094878,-2.9023499315200865,
            1.0000002454985888,1.0000547720130788,1.0004398837436375,1.0016988102918232,1.0046243665329366,1.0102330159348241,1.0197311144296588,1.0344740241135555,1.0559189373587332,1.0855723887219655,1.1249335524949235,1.1754345257866854,1.2383788788376973,1.3148798143197307,1.4057993144848902,1.5116896683399588};
            list_size = 48;
            for (int i = 0; i < list_size; i++){
                coefficientList[i] = GroupElement(list[i], bitsize, scale);
            }
            break;
        }
        case 2216:{
            // 2216 = 2 deg poly-approx to tangent with 16 segs
            float list[] = {0.48701374577046591,1.4993396293593293,2.6331046790580102,3.9930612744307088,5.727533021861543,8.0657232441668754,11.387727658031523,16.36684213431899,24.283227032572555,37.783785658961115,62.955072427217779,115.94339473086562,249.38759738458177,702.29009201353563,3579.042395751057,39202901.287069559,
            3.1358680224925539,3.0722195532111329,2.9296776017986392,2.6732710640520372,2.2373604272511565,1.5029804468557266,0.25113883681812615,-1.9376795077568865,-5.9149016192455708,-13.546426405361103,-29.36045794344906,-65.997934147236762,-166.73909481493817,-537.72670144321341,-3084.2781502574317,-37937843.714861609,
            9.9641465839886146e-06,0.0010310966696487204,0.0055344194800547031,0.017647676599386677,0.04507101276318537,0.10278129553495,0.22078095702582534,0.46142972868838267,0.96112606022883695,2.0398603326948912,4.5241456475705242,10.858107358510376,29.873431720898107,105.85139536517849,669.42290866433098,9173938.800715385};
            for (int i = 0; i < list_size; i++){
                coefficientList[i] = GroupElement(list[i], bitsize, scale);
            }
            break;
        }
        case 0000:{
            // This is the special case for generating coefficient for input transformation
            // target function: sin(pi*x)
            float list[] = { 1, 1, 1, -1,
                             1, -1, 1, -1,
                             0 ,1, -1, 2};
            list_size = 12;
            for (int i = 0; i < list_size; i++){
                coefficientList[i] = GroupElement(list[i], bitsize, scale);
            }
            break;
        }
        case 1000:{
            // This is the special transformation for cosine input
            float list[] = {1, -1, -1, 1,
                            1, -1, 1, -1,
                            0, 1, -1, 2};
            list_size = 12;
            for (int i = 0; i < list_size; i++){
                coefficientList[i] = GroupElement(list[i], bitsize, scale);
            }
            break;
        }
        case 2000:{
            // This is the special transformation for tangent input
            float list[] = {1, -1,
                            1, -1,
                            0, 1};
            list_size = 6;
            for (int i = 0; i < list_size; i++){
                coefficientList[i] = GroupElement(list[i], bitsize, scale);
            }
            break;
        }
        default:{
            return;
        }
    }
}

void create_sub_lut(int function, int Bin, int Bout, int scale, int segNum, GroupElement** lut){
    // The lut list num is identical to segNum
    // sine 0 cosine 1 tangent 2
    int lut_len = 1 << (Bin / segNum);
    for (int i = 0; i < segNum; i++){
        std::cout << "===========" << std::endl;
        for (int j = 0; j < lut_len; j++){
            switch (function) {
                case 0:{
                    // lut 0 is low bit result
                    float interval = 0.25 / (segNum * lut_len);
                    float idx = (j << (i * Bin / segNum)) / (float)(1 << scale);
                    lut[i][j] = GroupElement(sin((j << (i * Bin / segNum)) / (float)(1 << scale) * (M_PI)),
                                             Bout, scale);
                    // std::cout << "i = " << i << ", j = " << j << ", Generating sin(" << idx << " * Pi)" << std::endl;
                    break;
                }
                case 1:{
                    float interval = 0.25 / (segNum * lut_len);
                    lut[i][j] = GroupElement(cos((j << (i * Bin / segNum)) / (float)(1 << scale) * (M_PI)),
                                             Bout, scale);
                    break;
                }
                case 2:{
                    float interval = 0.25 / (segNum * lut_len);
                    float idx = (j << (i * Bin / segNum)) / (float)(1 << scale);
                    lut[i][j] = GroupElement(tan((j << (i * Bin / segNum)) / (float)(1 << scale) * (M_PI)),
                                             Bout, scale);
                    // std::cout << "i = " << i << ", j = " << j << ", Generating tan(" << idx << " * Pi)" << std::endl;
                    break;
                }
                default:{
                    std::cout << "[ERROR] Invalid function!" << std::endl;
                    exit(0);
                }
            }
        }
    }
}

int randint_range(int n,int m){//产生n~m间的随机数（包括m和n）
    assert(n <= m);
    auto rng = secure_prng();
    const uint64_t range = static_cast<uint64_t>(m) - static_cast<uint64_t>(n) + 1;
    const uint64_t limit = ~uint64_t(0) - (~uint64_t(0) % range);
    uint64_t draw = 0;
    do {
        draw = rng.get<uint64_t>();
    } while (draw >= limit);
    return n + static_cast<int>(draw % range);
}

float decode_from_ge_binary(GroupElement x, int bitlen, int scale){
    return ((float)x.value) / (1 << scale);
}

uint64_t encode_to_ge_binary(float x, int bitlen, int scale){
    return GroupElement(x, bitlen, scale).value;
}

int get_ulp(GroupElement x, GroupElement y){
    return abs((int)x.value - (int)y.value);
}
