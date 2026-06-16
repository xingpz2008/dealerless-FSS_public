#pragma once

#include <array>
#include <utility>
#include <vector>

#include "commons/keypack.h"

// Key material retained for NDSS-compatible baselines and old EzPC-style
// experiments. New dFSS code should not include this header.

struct DCFKeyPack{
    int Bin = 0, Bout = 0, groupSize = 0;
    KeyArray<block> k;   // size Bin+1
    KeyArray<GroupElement> g;
    KeyArray<GroupElement> v;
    DCFKeyPack(int Bin, int Bout, int groupSize,
                block *k,
                GroupElement *g,
                GroupElement *v) : Bin(Bin), Bout(Bout), groupSize(groupSize), k(k), g(g), v(v){}
    DCFKeyPack() = default;
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

struct LegacyComparisonKeyPack{
    int Bin = 0, Bout = 0;
    GroupElement mask;
    GroupElement correction;
    std::array<newDCFKeyPack, 2> DCFKeyList;
};

inline void resetLegacyComparisonKeyPack(LegacyComparisonKeyPack &key){
    resetNewDCFKeyPack(key.DCFKeyList[0]);
    resetNewDCFKeyPack(key.DCFKeyList[1]);
    key = LegacyComparisonKeyPack();
}

inline void freeLegacyComparisonKeyPack(LegacyComparisonKeyPack &key){
    resetLegacyComparisonKeyPack(key);
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
    KeyArray<GroupElement> sb;
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

struct MultKeyNew {
    GroupElement a, b, c;
    DCFKeyPack k1, k2, k3, k4;
};

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
    GroupElement d;
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
    GroupElement e_b0, e_b1;
    GroupElement beta_b0, beta_b1;
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
    int Bin, Bout, shift;
    DCFKeyPack dcfKey;
    DualDCFKeyPack dualDcfKey;
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

struct SplineKeyPack
{
    int Bin, Bout;
    int numPoly, degree;
    DCFKeyPack dcfKey;
    std::vector<GroupElement> p;
    std::vector<std::vector<GroupElement>> e_b;
    std::vector<GroupElement> beta_b;
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
    freeSplineKey(keys.first);
    freeSplineKey(keys.second);
}

struct ContainmentKeyPack{
    int Bin, Bout;
    int CtnNum;
    KeyArray<GroupElement> AList;
    KeyArray<GroupElement> BList;
    KeyArray<GroupElement> CList;
    KeyArray<LegacyComparisonKeyPack> ComparisonKeyList;
};

inline void freeContainmentKeyPack(ContainmentKeyPack& key){
    key.AList.reset();
    key.BList.reset();
    key.CList.reset();
    for (int i = 0; i < key.CtnNum; i++){
        freeLegacyComparisonKeyPack(key.ComparisonKeyList[i]);
    }
    key.ComparisonKeyList.reset();
}

using LegacyPublicLutKeyPack = DPFKeyPack;

inline void freeLegacyPublicLutKeyPack(LegacyPublicLutKeyPack& key){
    freeDPFKeyPack(key);
}

struct LegacyModularKeyPack{
    int Bin = 0, Bout = 0;
    LegacyComparisonKeyPack ComparisonKey;
};

inline void freeLegacyModularKeyPack(LegacyModularKeyPack& key){
    freeLegacyComparisonKeyPack(key.ComparisonKey);
}

struct LegacyTRKeyPack{
    int Bin = 0, Bout = 0;
    int s = 0;
    LegacyComparisonKeyPack ComparisonKey;
};

inline void freeLegacyTRKeyPack(LegacyTRKeyPack& key){
    freeLegacyComparisonKeyPack(key.ComparisonKey);
}

struct LegacyDigDecKeyPack{
    int Bin = 0, Bout = 0;
    int SegNum = 0;
    int NewBitSize = 0;
    KeyArray<LegacyComparisonKeyPack> ComparisonKeyList;
    KeyArray<DPFKeyPack> DPFKeyList;
    KeyArray<GroupElement> AList;
    KeyArray<GroupElement> BList;
    KeyArray<GroupElement> CList;
};

inline void freeLegacyDigDecKeyPack(LegacyDigDecKeyPack& key){
    key.AList.reset();
    key.BList.reset();
    key.CList.reset();
    for (int i = 0; i < key.SegNum - 1; i++){
        freeLegacyComparisonKeyPack(key.ComparisonKeyList[i]);
        freeDPFKeyPack(key.DPFKeyList[i]);
    }
    key.ComparisonKeyList.reset();
    key.DPFKeyList.reset();
}

struct LegacyPrivateLutKey{
    int entryNum = 0, lut_bitlen = 0;
    GroupElement random_mask;
    KeyArray<DPFKeyPack> DPFKeyList;
};

inline void freeLegacyPrivateLutKey(LegacyPrivateLutKey& key){
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
    LegacyTRKeyPack TRKey;
    KeyArray<LegacyComparisonKeyPack> EvalSignKeyList;
    KeyArray<LegacyComparisonKeyPack> EvalExtendKeyList;
    KeyArray<LegacyTRKeyPack> EvalScaleTRKeyList;
    KeyArray<GroupElement> EvalAList;
    KeyArray<GroupElement> EvalBList;
    KeyArray<GroupElement> EvalCList;
    KeyArray<LegacyPrivateLutKey> PriLUTKeyList;
};

inline void freeSplinePolyApproxKeyPack(SplinePolyApproxKeyPack& key){
    key.coefficientList.reset();
    if (key.EvalExtendKeyList != nullptr) {
        key.EvalExtendKeyList.reset();
    }
    if (key.fixed_scale > 0) {
        if (key.EvalSignKeyList != nullptr) {
            for (int i = 0; i < key.degNum; i++) {
                freeLegacyComparisonKeyPack(key.EvalSignKeyList[i]);
            }
            key.EvalSignKeyList.reset();
        }
        key.EvalScaleTRKeyList.reset();
        key.EvalAList.reset();
        key.EvalBList.reset();
        key.EvalCList.reset();
    }
    for (int i = 0; i < key.degNum + 1; i++){
        freeLegacyPrivateLutKey(key.PriLUTKeyList[i]);
    }
    key.PriLUTKeyList.reset();
}

struct SineKeyPack{
    int Bin, scale, Bout;
    bool using_lut;
    int digdec_new_bitsize, approx_segNum, approx_deg;
    LegacyModularKeyPack ModKey;
    LegacyComparisonKeyPack ModExtendKey;
    ContainmentKeyPack CtnKey;
    LegacyDigDecKeyPack DigDecKey;
    KeyArray<DPFKeyPack> EvalAllKeyList;
    KeyArray<LegacyTRKeyPack> LUTProductTRKeyList;
    SplinePolyApproxKeyPack SplineApproxKey;
    int MTList_len;
    KeyArray<GroupElement> AList;
    KeyArray<GroupElement> BList;
    KeyArray<GroupElement> CList;
};

inline void freeSineKeyPack(SineKeyPack& Key){
    freeLegacyModularKeyPack(Key.ModKey);
    freeLegacyComparisonKeyPack(Key.ModExtendKey);
    freeContainmentKeyPack(Key.CtnKey);
    if (Key.using_lut) {
        freeLegacyDigDecKeyPack(Key.DigDecKey);
        const int digdec_segNum =
            (Key.scale - 1) / Key.digdec_new_bitsize +
            (((Key.scale - 1) % Key.digdec_new_bitsize == 0) ? 0 : 1);
        for (int i = 0; i < digdec_segNum; i++) {
            freeDPFKeyPack(Key.EvalAllKeyList[i]);
        }
        Key.EvalAllKeyList.reset();
        for (int i = 0; i < 2; i++) {
            freeLegacyTRKeyPack(Key.LUTProductTRKeyList[i]);
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
    freeLegacyModularKeyPack(Key.ModKey);
    freeLegacyComparisonKeyPack(Key.ModExtendKey);
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
    LegacyModularKeyPack key1;
    LegacyTRKeyPack key2;
    ContainmentKeyPack key3;
    LegacyDigDecKeyPack key4;
    DPFKeyPack key5;
    LegacyPrivateLutKey key6;
    SplinePolyApproxKeyPack key7;
};

struct ProximityKeyPack{
    int Bin, Bout, scale;
    KeyArray<SineKeyPack> SineKeyList;
    KeyArray<CosineKeyPack> CosineKeyList;
    KeyArray<GroupElement> Alist;
    KeyArray<GroupElement> Blist;
    KeyArray<GroupElement> Clist;
    KeyArray<LegacyTRKeyPack> ProductTRKeyList;
    KeyArray<LegacyComparisonKeyPack> ProductExtendKeyList;
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
        freeLegacyTRKeyPack(key.ProductTRKeyList[i]);
    }
    key.ProductTRKeyList.reset();
    for (int i = 0; i < 6; i++) {
        freeLegacyComparisonKeyPack(key.ProductExtendKeyList[i]);
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
