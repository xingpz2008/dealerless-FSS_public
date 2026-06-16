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
#include "commons/group_element.h"

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

template <typename T>
inline KeyArray<T> makeKeyArray(std::size_t size) {
    KeyArray<T> array;
    if (size > 0) {
        array.reset(new T[size]);
    }
    return array;
}

struct DPFKeyPack{
    int Bin = 0, Bout = 0, groupSize = 0;
    int prefixBits = 0, suffixBits = -1, vectorSize = 0;
    KeyArray<block> k;
    KeyArray<GroupElement> g;
    KeyArray<u8> v;
    std::shared_ptr<GroupElement> random_mask;
    KeyArray<u8> boolean_mask;
    DPFKeyPack(int Bin, int Bout, int groupSize,
               block* k, GroupElement* g, u8* v, GroupElement* random_mask): Bin(Bin), Bout(Bout), groupSize(groupSize), k(k), g(g), v(v), random_mask(random_mask){}
    DPFKeyPack() = default;
};

struct BooleanDPFKeyPack{
    int Bin = 0, groupSize = 0;
    KeyArray<block> k;
    KeyArray<block> g;
    KeyArray<u8> v;
    std::shared_ptr<GroupElement> random_mask;
    KeyArray<u8> boolean_mask;
};

using EqualityKey = DPFKeyPack;
using EqualityBlockKey = BooleanDPFKeyPack;

struct PublicLutKeyPack{
    int idx_bitlen = 0, output_bitlen = 0, table_size = 0, suffixBits = 0;
    bool earlyTermination = true;
    GroupElement random_mask;
    DPFKeyPack DPFKey;
};

inline void resetDPFKeyPack(DPFKeyPack &key){
    key.k.reset();
    key.g.reset();
    key.v.reset();
    key.random_mask.reset();
    key.boolean_mask.reset();
    key = DPFKeyPack();
}

inline void freeDPFKeyPack(DPFKeyPack &key){
    resetDPFKeyPack(key);
}

inline void freeBooleanDPFKeyPack(BooleanDPFKeyPack& key){
    key.k.reset();
    key.g.reset();
    key.v.reset();
    key.random_mask.reset();
    key.boolean_mask.reset();
    key = BooleanDPFKeyPack();
}

inline void freeEqualityKey(EqualityKey& key){
    freeDPFKeyPack(key);
}

inline void freeEqualityBlockKey(EqualityBlockKey& key){
    freeBooleanDPFKeyPack(key);
}

inline void freePublicLutKeyPack(PublicLutKeyPack& key){
    freeDPFKeyPack(key.DPFKey);
    key = PublicLutKeyPack();
}

using DPFETKeyPack = DPFKeyPack;

inline void freeDPFETKeyPack(DPFETKeyPack &key){
    freeDPFKeyPack(key);
}

// MIC family key packs for the dFSS extension building blocks.
struct PublicInterval {
    uint64_t left;
    uint64_t right;
};

struct MICKeyPack{
    int Bin, Bout;
    GroupElement rho_share;
    GroupElement payload_share;
    GroupElement root_payload_cw;
    DPFKeyPack iDPFKey;
};

inline void freeMICKeyPack(MICKeyPack& key){
    freeDPFKeyPack(key.iDPFKey);
}

struct ComparisonKeyPack{
    int Bin, Bout;
    uint64_t threshold = 0;
    MICKeyPack MICKey;
};

inline void freeComparisonKeyPack(ComparisonKeyPack& key){
    freeMICKeyPack(key.MICKey);
}

struct MICBooleanKeyPack{
    int Bin;
    GroupElement rho_share;
    DPFKeyPack iDPFKey;
};

inline void freeMICBooleanKeyPack(MICBooleanKeyPack& key){
    freeDPFKeyPack(key.iDPFKey);
    key = MICBooleanKeyPack();
}

struct ComparisonBitKeyPack{
    int Bin;
    uint64_t threshold = 0;
    MICBooleanKeyPack MICKey;
};

inline void freeComparisonBitKeyPack(
    ComparisonBitKeyPack& key){
    freeMICBooleanKeyPack(key.MICKey);
    key = ComparisonBitKeyPack();
}

// Public building-block key packs.
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

struct SignedRingExtensionKeyPack{
    int input_bits, output_bits;
    ComparisonKeyPack CarryKey;
    ComparisonKeyPack SignKey;
};

inline void freeSignedRingExtensionKeyPack(SignedRingExtensionKeyPack& key){
    freeComparisonKeyPack(key.CarryKey);
    freeComparisonKeyPack(key.SignKey);
}

struct SignedTruncateKeyPack{
    int Bin, Bout;
    int s;
    ComparisonKeyPack CarryKey;
};

inline void freeSignedTruncateKeyPack(SignedTruncateKeyPack& key){
    freeComparisonKeyPack(key.CarryKey);
}

struct MICPolyEvalKeyPack{
    int Bin = 0, Bout = 0, wide_bits = 0, scale = 0, degree = 0;
    int segment_count = 0;
    MICKeyPack MICKey;
    SignedRingExtensionKeyPack ExtKey;
    SignedTruncateKeyPack TruncKey;
    KeyArray<GroupElement> r_powers;
    KeyArray<GroupElement> MulAList;
    KeyArray<GroupElement> MulBList;
    KeyArray<GroupElement> MulCList;
};

inline void freeMICPolyEvalKeyPack(MICPolyEvalKeyPack& key){
    freeMICKeyPack(key.MICKey);
    freeSignedRingExtensionKeyPack(key.ExtKey);
    if (key.degree * key.scale > 0) {
        freeSignedTruncateKeyPack(key.TruncKey);
    }
    key.r_powers.reset();
    key.MulAList.reset();
    key.MulBList.reset();
    key.MulCList.reset();
    key = MICPolyEvalKeyPack();
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

// Lookup-table key packs.
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
