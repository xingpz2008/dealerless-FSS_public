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

Note: Key packs use shared array ownership for protocol key material. This
preserves the historical cheap-copy behavior while avoiding public owning raw
pointers and double-free-prone manual ownership.
*/
#pragma once

#include <array>
#include <cstddef>
#include <cryptoTools/Common/Defines.h>
#include <memory>
#include "group_element.h"

using namespace osuCrypto;

template <typename T>
class KeyArray {
public:
    KeyArray() = default;
    explicit KeyArray(T* ptr) : ptr_(ptr, std::default_delete<T[]>()) {}

    KeyArray& operator=(T* ptr) {
        reset(ptr);
        return *this;
    }

    void reset(T* ptr = nullptr) {
        if (ptr == nullptr) {
            ptr_.reset();
        } else {
            ptr_.reset(ptr, std::default_delete<T[]>());
        }
    }

    T* data() noexcept {
        return ptr_.get();
    }

    const T* data() const noexcept {
        return ptr_.get();
    }

    T* get() noexcept {
        return data();
    }

    const T* get() const noexcept {
        return data();
    }

    T& operator[](std::size_t index) {
        return ptr_.get()[index];
    }

    const T& operator[](std::size_t index) const {
        return ptr_.get()[index];
    }

    explicit operator bool() const noexcept {
        return static_cast<bool>(ptr_);
    }

    operator T*() const noexcept {
        return ptr_.get();
    }

    bool operator==(std::nullptr_t) const noexcept {
        return ptr_ == nullptr;
    }

    bool operator!=(std::nullptr_t) const noexcept {
        return ptr_ != nullptr;
    }

private:
    std::shared_ptr<T[]> ptr_;
};

template <typename T>
inline void resetKeyArray(KeyArray<T>& array) {
    array.reset();
}

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
    int Bin = 0, Bout = 0, groupSize = 0;
    KeyArray<block> k;   // size Bin+1
    KeyArray<GroupElement> g;    // bitsize Bout, size groupSize
    KeyArray<GroupElement> v;   // bitsize Bout, size Bin x groupSize
    DCFKeyPack(int Bin, int Bout, int groupSize,
                block *k,
                GroupElement *g,
                GroupElement *v) : Bin(Bin), Bout(Bout), groupSize(groupSize), k(k), g(g), v(v){}
    DCFKeyPack() = default;
};

struct DPFKeyPack{
    int Bin = 0, Bout = 0, groupSize = 0;
    KeyArray<block> k;
    KeyArray<GroupElement> g;
    KeyArray<u8> v;
    std::shared_ptr<GroupElement> random_mask;
    DPFKeyPack(int Bin, int Bout, int groupSize,
               block* k, GroupElement* g, u8* v, GroupElement* random_mask): Bin(Bin), Bout(Bout), groupSize(groupSize), k(k), g(g), v(v), random_mask(random_mask){}
    DPFKeyPack() = default;
};

inline void resetDPFKeyPack(DPFKeyPack &key){
    key.k.reset();
    key.g.reset();
    key.v.reset();
    key.random_mask.reset();
    key = DPFKeyPack();
}

inline void freeDPFKeyPack(DPFKeyPack &key){
    resetDPFKeyPack(key);
}

struct iDCFKeyPack{
    int Bin = 0, Bout = 0, groupSize = 0;
    KeyArray<block> k;
    KeyArray<u8> v;
    KeyArray<GroupElement> beta_0;
    KeyArray<GroupElement> g;
    std::shared_ptr<GroupElement> random_mask;
    KeyArray<GroupElement> a;
    KeyArray<GroupElement> b;
    KeyArray<GroupElement> c;
    iDCFKeyPack(int Bin, int Bout, int groupSize,
                block* k, GroupElement* g, u8* v, GroupElement* beta_0, GroupElement* random_mask, GroupElement* a, GroupElement* b, GroupElement* c): Bin(Bin), Bout(Bout), groupSize(groupSize),
                k(k), g(g), v(v), beta_0(beta_0), random_mask(random_mask), a(a), b(b), c(c) {}
    iDCFKeyPack() = default;
};

struct newDCFKeyPack{
    int Bin = 0, Bout = 0;
    KeyArray<block> k;
    KeyArray<GroupElement> g;
    KeyArray<u8> v;
    newDCFKeyPack(int Bin, int Bout, block* k, GroupElement* g, u8* v): Bin(Bin), Bout(Bout), k(k), g(g), v(v) {}
    newDCFKeyPack() = default;
};

inline void resetNewDCFKeyPack(newDCFKeyPack &key){
    key.k.reset();
    key.g.reset();
    key.v.reset();
    key = newDCFKeyPack();
}

inline void freeNewDCFKeyPack(newDCFKeyPack &key){
    resetNewDCFKeyPack(key);
}

struct ComparisonKeyPack{
    int Bin = 0, Bout = 0;
    GroupElement mask;
    GroupElement correction;
    std::array<newDCFKeyPack, 2> DCFKeyList;
    // first is key with r
    // second is key with r+alpha
};

inline void resetComparisonKeyPack(ComparisonKeyPack &key){
    resetNewDCFKeyPack(key.DCFKeyList[0]);
    resetNewDCFKeyPack(key.DCFKeyList[1]);
    key = ComparisonKeyPack();
}

inline void freeComparisonKeyPack(ComparisonKeyPack &key){
    resetComparisonKeyPack(key);
}

inline void freeDCFKeyPack(DCFKeyPack &key){
    key.k.reset();
    key.g.reset();
    key.v.reset();
    key = DCFKeyPack();
}

inline void freeDCFKeyPackPair(std::pair<DCFKeyPack, DCFKeyPack> &keys){
    freeDCFKeyPack(keys.first);
    freeDCFKeyPack(keys.second);
}

struct DualDCFKeyPack{  
    int Bin, Bout, groupSize;
    DCFKeyPack dcfKey;
    KeyArray<GroupElement> sb;   // size: groupSize
    DualDCFKeyPack() {}
};

inline void freeDualDCFKeyPack(DualDCFKeyPack &key){
    freeDCFKeyPack(key.dcfKey);
    key.sb.reset();
}

inline void freeDualDCFKeyPackPair(std::pair<DualDCFKeyPack, DualDCFKeyPack> &keys){
    freeDualDCFKeyPack(keys.first);
    freeDualDCFKeyPack(keys.second);
}

struct AddKey{
    int Bin, Bout;
    GroupElement rb;
};


struct MatMulKey{
    int Bin, Bout;
    int s1, s2, s3;
    KeyArray<GroupElement> a, b, c;
};

inline void freeMatMulKey(MatMulKey &key){
    key.a.reset();
    key.b.reset();
    key.c.reset();
}

inline void freeMatMulKeyPair(std::pair<MatMulKey, MatMulKey> &keys){
    freeMatMulKey(keys.first);
    freeMatMulKey(keys.second);
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
    KeyArray<GroupElement> a, b, c;
};

inline void freeConv2dKey(Conv2DKey &key){
    key.a.reset();
    key.b.reset();
    key.c.reset();
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
    KeyArray<block> k;
    KeyArray<GroupElement> g, v;
    GroupElement e_b0, e_b1;		 // size: degree+1 (same as beta)
    GroupElement beta_b0, beta_b1;	 // size: degree+1 (shares of beta, which is set of poly coeffs) (beta: highest to lowest power left to right)
    GroupElement r_b;
};


inline void freeReluKeyPack(ReluKeyPack &key)
{
    key.k.reset();
    key.g.reset();
    key.v.reset();
}

inline void freeReluKeyPackPair(std::pair<ReluKeyPack,ReluKeyPack> &keys)
{
    freeReluKeyPack(keys.first);
    freeReluKeyPack(keys.second);
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
    freeMaxpoolKeyPack(keys.first);
    freeMaxpoolKeyPack(keys.second);
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
    freeDCFKeyPack(key.dcfKey);
    if (key.Bout > key.Bin - key.shift) {
        freeDualDCFKeyPack(key.dualDcfKey);
    }
}
inline void freeARSKeyPackPair(std::pair<ARSKeyPack, ARSKeyPack> &keys)
{
    freeARSKeyPack(keys.first);
    freeARSKeyPack(keys.second);
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
    freeDCFKeyPack(keys.first.dcfKey);
    freeDCFKeyPack(keys.second.dcfKey);
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

inline void freeModularKeyPack(ModularKeyPack& key){
    freeComparisonKeyPack(key.ComparisonKey);
}

struct TRKeyPack{
    int Bin, Bout;
    int s;
    ComparisonKeyPack ComparisonKey;
};

inline void freeTRKeyPack(TRKeyPack& key){
    freeComparisonKeyPack(key.ComparisonKey);
}

struct ContainmentKeyPack{
    int Bin, Bout;
    int CtnNum;
    KeyArray<GroupElement> AList;
    KeyArray<GroupElement> BList;
    KeyArray<GroupElement> CList;
    KeyArray<ComparisonKeyPack> ComparisonKeyList;
};

inline void freeContainmentKeyPack(ContainmentKeyPack& key){
    key.AList.reset();
    key.BList.reset();
    key.CList.reset();
    for (int i = 0; i < key.CtnNum; i++){
        freeComparisonKeyPack(key.ComparisonKeyList[i]);
    }
    key.ComparisonKeyList.reset();
}

struct DigDecKeyPack{
    int Bin, Bout;
    int SegNum;
    int NewBitSize;
    KeyArray<ComparisonKeyPack> ComparisonKeyList;
    KeyArray<DPFKeyPack> DPFKeyList;
    KeyArray<GroupElement> AList;
    KeyArray<GroupElement> BList;
    KeyArray<GroupElement> CList;
};

inline void freeDigDecKeyPack(DigDecKeyPack& key){
    key.AList.reset();
    key.BList.reset();
    key.CList.reset();
    for (int i = 0; i < key.SegNum - 1; i++){
        freeComparisonKeyPack(key.ComparisonKeyList[i]);
        freeDPFKeyPack(key.DPFKeyList[i]);
    }
    key.ComparisonKeyList.reset();
    key.DPFKeyList.reset();
}

struct PrivateLutKey{
    int entryNum, lut_bitlen;
    GroupElement random_mask;
    KeyArray<DPFKeyPack> DPFKeyList;
};

inline void freePrivateLutKey(struct PrivateLutKey& key){
    for (int i = 0; i < key.entryNum; i++){
        freeDPFKeyPack(key.DPFKeyList[i]);
    }
    key.DPFKeyList.reset();
}

struct SplinePolyApproxKeyPack{
    int Bin, Bout;
    int degNum, segNum;
    int fixed_scale;
    KeyArray<GroupElement> coefficientList;
    GroupElement random_mask;
    TRKeyPack TRKey;
    KeyArray<ComparisonKeyPack> EvalSignKeyList;
    KeyArray<ComparisonKeyPack> EvalExtendKeyList;
    KeyArray<TRKeyPack> EvalScaleTRKeyList;
    KeyArray<GroupElement> EvalAList;
    KeyArray<GroupElement> EvalBList;
    KeyArray<GroupElement> EvalCList;
    KeyArray<PrivateLutKey> PriLUTKeyList;
};

inline void freeSplinePolyApproxKeyPack(SplinePolyApproxKeyPack& key){
    key.coefficientList.reset();
    if (key.EvalExtendKeyList != nullptr) {
        key.EvalExtendKeyList.reset();
    }
    if (key.fixed_scale > 0) {
        if (key.EvalSignKeyList != nullptr) {
            for (int i = 0; i < key.degNum; i++) {
                freeComparisonKeyPack(key.EvalSignKeyList[i]);
            }
            key.EvalSignKeyList.reset();
        }
        key.EvalScaleTRKeyList.reset();
        key.EvalAList.reset();
        key.EvalBList.reset();
        key.EvalCList.reset();
    }
    for (int i = 0; i < key.degNum + 1; i++){
        freePrivateLutKey(key.PriLUTKeyList[i]);
    }
    key.PriLUTKeyList.reset();
}

struct SineKeyPack{
    int Bin, scale, Bout;
    bool using_lut;
    int digdec_new_bitsize, approx_segNum, approx_deg;
    ModularKeyPack ModKey;
    ComparisonKeyPack ModExtendKey;
    ContainmentKeyPack CtnKey;
    DigDecKeyPack DigDecKey;
    KeyArray<DPFKeyPack> EvalAllKeyList;
    KeyArray<TRKeyPack> LUTProductTRKeyList;
    // This public LUT seems no need to be contained in the key?
    // GroupElement* LUT;
    SplinePolyApproxKeyPack SplineApproxKey; // TRKey included
    // Maybe Multiplication MTs?
    int MTList_len;
    KeyArray<GroupElement> AList;
    KeyArray<GroupElement> BList;
    KeyArray<GroupElement> CList;
};

inline void freeSineKeyPack(SineKeyPack& Key){
    freeModularKeyPack(Key.ModKey);
    freeComparisonKeyPack(Key.ModExtendKey);
    freeContainmentKeyPack(Key.CtnKey);
    if (Key.using_lut) {
        freeDigDecKeyPack(Key.DigDecKey);
        const int digdec_segNum =
            (Key.scale - 1) / Key.digdec_new_bitsize +
            (((Key.scale - 1) % Key.digdec_new_bitsize == 0) ? 0 : 1);
        for (int i = 0; i < digdec_segNum; i++) {
            freeDPFKeyPack(Key.EvalAllKeyList[i]);
        }
        Key.EvalAllKeyList.reset();
        for (int i = 0; i < 2; i++) {
            freeTRKeyPack(Key.LUTProductTRKeyList[i]);
        }
        Key.LUTProductTRKeyList.reset();
    } else {
        freeSplinePolyApproxKeyPack(Key.SplineApproxKey);
    }
    Key.AList.reset();
    Key.BList.reset();
    Key.CList.reset();
}

typedef SineKeyPack CosineKeyPack;

inline void freeCosineKeyPack(CosineKeyPack& Key){
    freeSineKeyPack(Key);
}

typedef SineKeyPack TangentKeyPack;

inline void freeTangentKeyPack(TangentKeyPack& Key){
    freeModularKeyPack(Key.ModKey);
    freeComparisonKeyPack(Key.ModExtendKey);
    freeContainmentKeyPack(Key.CtnKey);
    if (Key.using_lut) {
        freeDPFKeyPack(Key.EvalAllKeyList[0]);
        Key.EvalAllKeyList.reset();
    } else {
        freeSplinePolyApproxKeyPack(Key.SplineApproxKey);
    }
    Key.AList.reset();
    Key.BList.reset();
    Key.CList.reset();
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
    KeyArray<SineKeyPack> SineKeyList;
    KeyArray<CosineKeyPack> CosineKeyList;
    KeyArray<GroupElement> Alist;
    KeyArray<GroupElement> Blist;
    KeyArray<GroupElement> Clist;
    KeyArray<TRKeyPack> ProductTRKeyList;
    KeyArray<ComparisonKeyPack> ProductExtendKeyList;
    // MT triples = 4
    // SineKey = 2
    // Cosine Key = 2
};

inline void freeProximityKeyPack(ProximityKeyPack& key){
    for (int i = 0; i < 2; i++) {
        freeSineKeyPack(key.SineKeyList[i]);
        freeCosineKeyPack(key.CosineKeyList[i]);
    }
    key.SineKeyList.reset();
    key.CosineKeyList.reset();
    key.Alist.reset();
    key.Blist.reset();
    key.Clist.reset();
    for (int i = 0; i < 4; i++) {
        freeTRKeyPack(key.ProductTRKeyList[i]);
    }
    key.ProductTRKeyList.reset();
    for (int i = 0; i < 6; i++) {
        freeComparisonKeyPack(key.ProductExtendKeyList[i]);
    }
    key.ProductExtendKeyList.reset();
};

struct BiometricKeyPack{
    int Bin, Bout, scale;
    bool using_lut;
    KeyArray<TangentKeyPack> TangentKeyList;
};

inline void freeBiometricKeyPack(BiometricKeyPack& key){
    for (int i = 0; i < 4; i++) {
        freeTangentKeyPack(key.TangentKeyList[i]);
    }
    key.TangentKeyList.reset();
}
