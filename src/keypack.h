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

Note: Part of freeKey functions are to be completed.
*/
#pragma once

#include <cryptoTools/Common/Defines.h>
#include "group_element.h"

using namespace osuCrypto;

struct MultKey{
    int Bin, Bout;
    GroupElement a, b, c;
};

struct DCFKeyPack{
    /*
     * Explanation on CryptFLow-style Key pack:
     * k - CW
     * g - CW_n+1
     * v - V_list
     * Group size was set by default to 1, maybe used in multiprocess?
     *
    */
    int Bin, Bout, groupSize;
    block *k;   // size Bin+1
    GroupElement *g;    // bitsize Bout, size groupSize
    GroupElement *v;   // bitsize Bout, size Bin x groupSize
    DCFKeyPack(int Bin, int Bout, int groupSize,
                block *k,
                GroupElement *g,
                GroupElement *v) : Bin(Bin), Bout(Bout), groupSize(groupSize), k(k), g(g), v(v){}
    DCFKeyPack() {}
};

struct DPFKeyPack{
    int Bin, Bout, groupSize;
    block* k;
    GroupElement* g;
    u8* v;
    GroupElement* random_mask;
    DPFKeyPack(int Bin, int Bout, int groupSize,
               block* k, GroupElement* g, u8* v, GroupElement* random_mask): Bin(Bin), Bout(Bout), groupSize(groupSize), k(k), g(g), v(v), random_mask(random_mask){}
    DPFKeyPack() {}
};

struct iDCFKeyPack{
    int Bin, Bout, groupSize;
    block* k;
    u8* v;
    GroupElement* beta_0;
    GroupElement* g;
    GroupElement* random_mask;
    GroupElement* a;
    GroupElement* b;
    GroupElement* c;
    iDCFKeyPack(int Bin, int Bout, int groupSize,
                block* k, GroupElement* g, u8* v, GroupElement* beta_0, GroupElement* random_mask, GroupElement* a, GroupElement* b, GroupElement* c): Bin(Bin), Bout(Bout), groupSize(groupSize),
                k(k), g(g), v(v), beta_0(beta_0), random_mask(random_mask), a(a), b(b), c(c) {}
    iDCFKeyPack() {}
};

struct newDCFKeyPack{
    int Bin, Bout;
    block* k;
    GroupElement* g;
    u8* v;
    newDCFKeyPack(int Bin, int Bout, block* k, GroupElement* g, u8* v): Bin(Bin), Bout(Bout), k(k), g(g), v(v) {}
    newDCFKeyPack() {}
};

inline void freeNewDCFKeyPack(newDCFKeyPack key){
    delete[] key.k;
    delete[] key.g;
    delete[] key.v;
}

struct ComparisonKeyPack{
    int Bin, Bout;
    GroupElement mask;
    GroupElement correction;
    newDCFKeyPack* DCFKeyList;
    // first is key with r
    // second is key with r+alpha
};

inline void freeComparisonKeyPack(ComparisonKeyPack key){
    freeNewDCFKeyPack(key.DCFKeyList[0]);
    freeNewDCFKeyPack(key.DCFKeyList[1]);
}

inline void freeDCFKeyPack(DCFKeyPack &key){
    delete[] key.k;
    delete[] key.g;
    delete[] key.v;
}

inline void freeDCFKeyPackPair(std::pair<DCFKeyPack, DCFKeyPack> &keys){
    delete[] keys.first.k;
    delete[] keys.second.k;
    delete[] keys.first.g;
    delete[] keys.first.v;
}

struct DualDCFKeyPack{  
    int Bin, Bout, groupSize;
    DCFKeyPack dcfKey;
    GroupElement *sb;   // size: groupSize
    DualDCFKeyPack() {}
};

inline void freeDualDCFKeyPack(DualDCFKeyPack &key){
    freeDCFKeyPack(key.dcfKey);
    delete[] key.sb;
}

inline void freeDualDCFKeyPackPair(std::pair<DualDCFKeyPack, DualDCFKeyPack> &keys){
    delete[] keys.first.dcfKey.k;
    delete[] keys.second.dcfKey.k;
    delete[] keys.first.dcfKey.g;
    delete[] keys.first.dcfKey.v;
    delete[] keys.first.sb;
    delete[] keys.second.sb;
}

struct AddKey{
    int Bin, Bout;
    GroupElement rb;
};


struct MatMulKey{
    int Bin, Bout;
    int s1, s2, s3;
    GroupElement *a, *b, *c;    
};

inline void freeMatMulKey(MatMulKey &key){
    delete[] key.a;
    delete[] key.b;
    delete[] key.c;
}

inline void freeMatMulKeyPair(std::pair<MatMulKey, MatMulKey> &keys){
    delete[] keys.first.a;
    delete[] keys.first.b;
    delete[] keys.first.c;
    delete[] keys.second.a;
    delete[] keys.second.b;
    delete[] keys.second.c;
}

struct MultKeyNew {
    GroupElement a, b, c;
    DCFKeyPack k1, k2, k3, k4;
};

struct Conv2DKey{
    int Bin, Bout;
    int N, H, W, CI, FH, FW, CO,
        zPadHLeft, zPadHRight, 
        zPadWLeft, zPadWRight,
        strideH, strideW;
    GroupElement *a, *b, *c;    
};

inline void freeConv2dKey(Conv2DKey &key){
    delete[] key.a;
    delete[] key.b;
    delete[] key.c;
}

struct ScmpKeyPack
{
    int Bin, Bout;
    DualDCFKeyPack dualDcfKey;
    GroupElement rb;
};

struct PublicICKeyPack
{
    int Bin, Bout;
    DCFKeyPack dcfKey;
    GroupElement zb;
};

struct PublicDivKeyPack
{
    int Bin, Bout;
    DualDCFKeyPack dualDcfKey;
    ScmpKeyPack scmpKey;
    GroupElement zb;
};

struct SignedPublicDivKeyPack
{
    int Bin, Bout;
    GroupElement d;     // divisor
    DCFKeyPack dcfKey;
    PublicICKeyPack publicICkey;
    ScmpKeyPack scmpKey;
    GroupElement A_share, corr_share, B_share, rdiv_share;
    GroupElement rout_temp_share, rout_share;
};

struct ReluKeyPack
{
    int Bin, Bout;
    block *k;
    GroupElement *g, *v;
    GroupElement e_b0, e_b1;		 // size: degree+1 (same as beta)
    GroupElement beta_b0, beta_b1;	 // size: degree+1 (shares of beta, which is set of poly coeffs) (beta: highest to lowest power left to right)
    GroupElement r_b;
};


inline void freeReluKeyPack(ReluKeyPack &key)
{
    delete[] key.k;
    delete[] key.g;
    delete[] key.v;
}

inline void freeReluKeyPackPair(std::pair<ReluKeyPack,ReluKeyPack> &keys)
{
    delete[] keys.first.k;
    delete[] keys.second.k;
    delete[] keys.first.g;
    delete[] keys.first.v;
    // other key shares g and v, dont delete again
}

struct MaxpoolKeyPack
{
    int Bin, Bout;
    ReluKeyPack reluKey;
    GroupElement rb;
};

inline void freeMaxpoolKeyPack(MaxpoolKeyPack &key)
{
    freeReluKeyPack(key.reluKey);
}

inline void freeMaxpoolKeyPackPair(std::pair<MaxpoolKeyPack,MaxpoolKeyPack> &keys)
{
    delete[] keys.first.reluKey.k;
    delete[] keys.second.reluKey.k;
    delete[] keys.first.reluKey.g;
    delete[] keys.first.reluKey.v;
}

struct ARSKeyPack
{
    // arithmetic right shift
    int Bin, Bout, shift;
    DCFKeyPack dcfKey;
    DualDCFKeyPack dualDcfKey;      // groupSize = 2 for payload
    GroupElement rb;
    ARSKeyPack() {}
};

inline void freeARSKeyPack(ARSKeyPack &key)
{
    delete[] key.dcfKey.k;
    delete[] key.dcfKey.g;
    delete[] key.dcfKey.v;
    if (key.Bout > key.Bin - key.shift) {
        delete[] key.dualDcfKey.sb;
        delete[] key.dualDcfKey.dcfKey.k;
        delete[] key.dualDcfKey.dcfKey.g;
        delete[] key.dualDcfKey.dcfKey.v;
    }
}
inline void freeARSKeyPackPair(std::pair<ARSKeyPack, ARSKeyPack> &keys)
{
    delete[] keys.first.dcfKey.k;
    delete[] keys.second.dcfKey.k;
    delete[] keys.first.dcfKey.g;
    delete[] keys.first.dcfKey.v;
    if (keys.first.Bout > keys.first.Bin - keys.first.shift) {
        delete[] keys.first.dualDcfKey.sb;
        delete[] keys.second.dualDcfKey.sb;
        delete[] keys.first.dualDcfKey.dcfKey.k;
        delete[] keys.second.dualDcfKey.dcfKey.k;
        delete[] keys.first.dualDcfKey.dcfKey.g;
        delete[] keys.first.dualDcfKey.dcfKey.v;
    }
}
/*
struct SplineOneKeyPack
{
    int Bin, Bout;
    int degree; // degree of poly in payload beta
    DCFKeyPack dcfKey;
    std::vector<GroupElement> e_b;		 // size: degree+1 (same as beta)
    std::vector<GroupElement> beta_b;	 // size: degree+1 (shares of beta, which is set of poly coeffs) (beta: highest to lowest power left to right)
    GroupElement r_b;
};
*/
struct SplineKeyPack
{
    int Bin, Bout;
    int numPoly, degree;
    DCFKeyPack dcfKey;
    std::vector<GroupElement> p;        // spline breakpoints, size: numPoly + 1; p[0] = 0 and p[numPoly] = N-1
    std::vector<std::vector<GroupElement>> e_b; // 2d array dim: numPoly x (degree+1) (size is same as beta)
    std::vector<GroupElement> beta_b;           // 1d array size: numPoly * (degree+1) (shares of beta, which is set of poly coeffs) (beta: highest to lowest power left to right)
    GroupElement r_b;
};


inline void freeSplineKey(SplineKeyPack &key)
{
    freeDCFKeyPack(key.dcfKey);
    key.p.clear();
    key.e_b.clear();
    key.beta_b.clear();
}

inline void freeSplineKeyPair(std::pair<SplineKeyPack, SplineKeyPack> &keys)
{
    delete[] keys.first.dcfKey.k;
    delete[] keys.second.dcfKey.k;
    delete[] keys.first.dcfKey.g;
    delete[] keys.first.dcfKey.v;
    keys.first.p.clear();
    keys.second.p.clear();
    keys.first.e_b.clear();
    keys.second.e_b.clear();
    keys.first.beta_b.clear();
    keys.second.beta_b.clear();
}

struct ModularKeyPack{
    // Remove int N component as N is shared
    int Bin, Bout;
    ComparisonKeyPack ComparisonKey;
};

inline void freeModularKeyPack(ModularKeyPack key){
    freeComparisonKeyPack(key.ComparisonKey);
}

struct TRKeyPack{
    int Bin, Bout;
    int s;
    ComparisonKeyPack ComparisonKey;
};

inline void freeTRKeyPack(TRKeyPack key){
    freeComparisonKeyPack(key.ComparisonKey);
}

struct ContainmentKeyPack{
    int Bin, Bout;
    int CtnNum;
    GroupElement* AList;
    GroupElement* BList;
    GroupElement* CList;
    ComparisonKeyPack* ComparisonKeyList;
};

inline void freeContainmentKeyPack(ContainmentKeyPack key){
    delete[] key.AList;
    delete[] key.BList;
    delete[] key.CList;
    for (int i = 0; i < key.CtnNum; i++){
        freeComparisonKeyPack(key.ComparisonKeyList[i]);
    }
}

struct DigDecKeyPack{
    int Bin, Bout;
    int SegNum;
    int NewBitSize;
    ComparisonKeyPack* ComparisonKeyList;
    DPFKeyPack* DPFKeyList;
    GroupElement* AList;
    GroupElement* BList;
    GroupElement* CList;
};

inline void freeDigDecKeyPack(DigDecKeyPack key){
    delete[] key.AList;
    delete[] key.BList;
    delete[] key.CList;
    for (int i = 0; i < key.SegNum - 1; i++){
        freeComparisonKeyPack(key.ComparisonKeyList[i]);
        delete[] key.DPFKeyList[i].k;
        delete[] key.DPFKeyList[i].g;
        delete[] key.DPFKeyList[i].v;
        delete[] key.DPFKeyList[i].random_mask;
    }
}

struct PrivateLutKey{
    int entryNum, lut_bitlen;
    GroupElement random_mask;
    DPFKeyPack* DPFKeyList;
};

inline void freePrivateLutKey(struct PrivateLutKey key){
    for (int i = 0; i < key.entryNum; i++){
        delete[] key.DPFKeyList[i].k;
        delete[] key.DPFKeyList[i].g;
        delete[] key.DPFKeyList[i].v;
        delete[] key.DPFKeyList[i].random_mask;
    }
}

struct SplinePolyApproxKeyPack{
    int Bin, Bout;
    int degNum, segNum;
    GroupElement* coefficientList;
    GroupElement random_mask;
    TRKeyPack TRKey;
    PrivateLutKey* PriLUTKeyList;
};

inline void freeSplinePolyApproxKeyPack(SplinePolyApproxKeyPack key){
    delete[] key.coefficientList;
    for (int i = 0; i < key.degNum + 1; i++){
        freePrivateLutKey(key.PriLUTKeyList[i]);
    }
}

struct SineKeyPack{
    int Bin, scale, Bout;
    bool using_lut;
    int digdec_new_bitsize, approx_segNum, approx_deg;
    ModularKeyPack ModKey;
    ContainmentKeyPack CtnKey;
    DigDecKeyPack DigDecKey;
    DPFKeyPack* EvalAllKeyList;
    // This public LUT seems no need to be contained in the key?
    // GroupElement* LUT;
    SplinePolyApproxKeyPack SplineApproxKey; // TRKey included
    // Maybe Multiplication MTs?
    int MTList_len;
    GroupElement* AList;
    GroupElement* BList;
    GroupElement* CList;
};

inline void freeSineKeyPack(SineKeyPack Key){
    freeModularKeyPack(Key.ModKey);
    //freeContainmentKeyPack(Key.CtnKey);
    //freeDigDecKeyPack(Key.DigDecKey);
    delete[] Key.EvalAllKeyList;
    //freeSplinePolyApproxKeyPack(Key.SplineApproxKey);
    delete[] Key.AList;
    delete[] Key.BList;
    delete[] Key.CList;
}

typedef SineKeyPack CosineKeyPack;

inline void freeCosineKeyPack(CosineKeyPack Key){
    freeSineKeyPack(Key);
}

typedef SineKeyPack TangentKeyPack;

inline void freeTangentKeyPack(TangentKeyPack Key){
    freeModularKeyPack(Key.ModKey);
    //freeContainmentKeyPack(Key.CtnKey);
    delete[] Key.EvalAllKeyList;
    //freeSplinePolyApproxKeyPack(Key.SplineApproxKey);
    delete[] Key.AList;
    delete[] Key.BList;
    delete[] Key.CList;
}

struct TestKeyPack{
    ModularKeyPack key1;
    TRKeyPack key2;
    ContainmentKeyPack key3;
    DigDecKeyPack key4;
    DPFKeyPack key5;
    PrivateLutKey key6;
    SplinePolyApproxKeyPack key7;
};

struct ProximityKeyPack{
    int Bin, Bout, scale;
    SineKeyPack* SineKeyList;
    CosineKeyPack* CosineKeyList;
    GroupElement* Alist;
    GroupElement* Blist;
    GroupElement* Clist;
    // MT triples = 4
    // SineKey = 2
    // Cosine Key = 2
};

inline void freeProximityKeyPack(ProximityKeyPack key){
    // TODO: Implement this.
};

struct BiometricKeyPack{
    int Bin, Bout, scale;
    bool using_lut;
    TangentKeyPack* TangentKeyList;
};

inline void freeBiometricKeyPack(BiometricKeyPack key){
    // TODO: Implement this.
}