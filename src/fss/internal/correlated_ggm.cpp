#include "fss/internal/correlated_ggm.h"

#include <stdexcept>
#include <string>

#include "mpc/api.h"
#include "fss/internal/ggm.h"
#include "fss/internal/payload_conversion.h"
#include "mpc/secure_ops.h"

namespace dfss::internal {

namespace {

BooleanElement blockLsb(const osuCrypto::block& input) {
    return _mm_cvtsi128_si64x(input) & 1;
}

template <typename KeyT>
osuCrypto::block evalLeaf(const BooleanElement* opened_bits, const KeyT& key,
                          BooleanElement* controlBitOut) {
    osuCrypto::block levelNode = key.k[0];
    BooleanElement controlBit = blockLsb(levelNode);
    for (int i = 0; i < key.Bin - 1; i++) {
        const BooleanElement direction =
            static_cast<BooleanElement>(opened_bits[i] & 1);
        const osuCrypto::block current = levelNode;
        const osuCrypto::block hashed = ccrHash(current);
        levelNode = hashed ^
                    (direction ? current : osuCrypto::ZeroBlock) ^
                    (controlBit ? key.k[i + 1] : osuCrypto::ZeroBlock);
        controlBit = blockLsb(levelNode);
    }

    const BooleanElement finalDirection =
        static_cast<BooleanElement>(opened_bits[key.Bin - 1] & 1);
    const osuCrypto::block q =
        ccrHash(levelNode ^
                (finalDirection ? osuCrypto::OneBlock
                                : osuCrypto::ZeroBlock));
    const osuCrypto::block finalCw =
        setBlockLsb(key.k[key.Bin],
                    key.v[2 * (key.Bin - 1) + finalDirection]);
    levelNode = q ^ (controlBit ? finalCw : osuCrypto::ZeroBlock);
    controlBit = blockLsb(levelNode);
    if (controlBitOut != nullptr) {
        *controlBitOut = controlBit;
    }
    return levelNode;
}

}  // namespace

namespace {

constexpr int kMaxFullTreeBits = 24;

void ensureSupportedFullTreeBits(const int bits, const char* caller) {
    if (bits < 0 || bits > kMaxFullTreeBits) {
        throw std::invalid_argument(
            std::string(caller) + " requires 0 <= bit length <= " +
            std::to_string(kMaxFullTreeBits) +
            " in the current full-tree implementation");
    }
}

}  // namespace

CorrelatedTreeMaterial generateCorrelatedTree(
    int party_id, int Bin, int Bout, const BooleanElement* bits,
    const char* caller, bool computeArithmeticSums) {
    ensureSupportedFullTreeBits(Bin, caller);
    if (Bin <= 0) {
        throw std::invalid_argument(std::string(caller) + " requires Bin > 0");
    }
    if (bits == nullptr) {
        throw std::invalid_argument(std::string(caller) +
                                    " requires target bits");
    }

    const int party_bit = party_id - SERVER;
    auto rng = secure_prng();

    osuCrypto::block root = rng.get<osuCrypto::block>();
    root = setBlockLsb(root, static_cast<osuCrypto::u8>(party_bit));
    const osuCrypto::block delta_share = root;

    const size_t leafCapacity = size_t(1) << Bin;
    const size_t halfCapacity = (leafCapacity > 1) ? (leafCapacity / 2) : 1;
    auto largeLevelNodes =
        std::make_unique<osuCrypto::block[]>(leafCapacity);
    auto smallLevelNodes =
        std::make_unique<osuCrypto::block[]>(halfCapacity);
    osuCrypto::block* levelNodes =
        (Bin % 2 == 0) ? largeLevelNodes.get() : smallLevelNodes.get();
    osuCrypto::block* nextLevelNodes =
        (Bin % 2 == 0) ? smallLevelNodes.get() : largeLevelNodes.get();
    levelNodes[0] = root;

    auto tau = makeKeyArray<BooleanElement>(Bin * 2);
    auto scw = makeKeyArray<osuCrypto::block>(Bin + 1);
    scw[0] = root;
    for (int i = 0; i < Bin * 2; i++) {
        tau[i] = 0;
    }

    std::vector<BooleanElement> real_idx(Bin);
    for (int i = 0; i < Bin; i++) {
        real_idx[i] = static_cast<BooleanElement>(bits[i] & 1);
    }

    const bool useDpfBitBlockMulMaterial = !computeArithmeticSums;
    DpfBitBlockMulMaterial bitBlockMulMaterial;
    if (useDpfBitBlockMulMaterial) {
        bitBlockMulMaterial =
            prepareDpfBitBlockMulMaterial(party_id, Bin, peer);
    }

    std::vector<osuCrypto::block> delta_selected(Bin > 1 ? Bin - 1 : 0);
    if (Bin > 1) {
        std::vector<BooleanElement> alpha_bar_shares(Bin - 1);
        std::vector<osuCrypto::block> delta_choices(Bin - 1, delta_share);
        for (int i = 0; i < Bin - 1; i++) {
            alpha_bar_shares[i] =
                real_idx[i] ^ static_cast<BooleanElement>(1 - party_bit);
        }
        if (useDpfBitBlockMulMaterial) {
            consumeDpfBitBlockMulMaterial(party_id, bitBlockMulMaterial,
                                          alpha_bar_shares.data(),
                                          delta_choices.data(),
                                          delta_selected.data(), Bin - 1,
                                          peer);
        } else {
            bitBlockMultiply(party_id, alpha_bar_shares.data(),
                             delta_choices.data(), delta_selected.data(),
                             Bin - 1, peer);
        }
    }

    for (int i = 0; i < Bin - 1; i++) {
        const size_t levelSize = size_t(1) << i;

        osuCrypto::block levelHashXor = osuCrypto::ZeroBlock;
        for (size_t j = 0; j < levelSize; j++) {
            levelHashXor = levelHashXor ^ ccrHash(levelNodes[j]);
        }

        osuCrypto::block layer_cw = levelHashXor ^ delta_selected[i];
        reconstruct(&layer_cw);
        scw[i + 1] = layer_cw;

        for (size_t j = 0; j < levelSize; j++) {
            const osuCrypto::block current = levelNodes[j];
            const BooleanElement controlBit = blockLsb(current);
            const osuCrypto::block hashed = ccrHash(current);
            const osuCrypto::block correction =
                controlBit ? layer_cw : osuCrypto::ZeroBlock;
            nextLevelNodes[2 * j] = hashed ^ correction;
            nextLevelNodes[2 * j + 1] = hashed ^ current ^ correction;
        }
        std::swap(levelNodes, nextLevelNodes);
    }

    const size_t penultimateSize = size_t(1) << (Bin - 1);
    const BooleanElement alpha_bar_last =
        real_idx[Bin - 1] ^ static_cast<BooleanElement>(1 - party_bit);
    osuCrypto::block high0 = osuCrypto::ZeroBlock;
    osuCrypto::block high1 = osuCrypto::ZeroBlock;
    BooleanElement low0 = 0;
    BooleanElement low1 = 0;
    for (size_t j = 0; j < penultimateSize; j++) {
        const osuCrypto::block q0 = ccrHash(levelNodes[j]);
        const osuCrypto::block q1 =
            ccrHash(levelNodes[j] ^ osuCrypto::OneBlock);
        high0 = high0 ^ clearBlockLsb(q0);
        high1 = high1 ^ clearBlockLsb(q1);
        low0 ^= blockLsb(q0);
        low1 ^= blockLsb(q1);
    }

    const osuCrypto::block high_diff = high0 ^ high1;
    osuCrypto::block high_selected = osuCrypto::ZeroBlock;
    if (useDpfBitBlockMulMaterial) {
        consumeDpfBitBlockMulMaterial(party_id, bitBlockMulMaterial,
                                      &alpha_bar_last, &high_diff,
                                      &high_selected, 1, peer);
    } else {
        bitBlockMultiply(party_id, &alpha_bar_last, &high_diff,
                         &high_selected, 1, peer);
    }
    osuCrypto::block hcw = high0 ^ high_selected;
    BooleanElement lcw0 =
        low0 ^ real_idx[Bin - 1] ^ static_cast<BooleanElement>(party_bit);
    BooleanElement lcw1 = low1 ^ real_idx[Bin - 1];
    BooleanElement lcw_bits[2] = {lcw0, lcw1};
    reconstruct(&hcw, lcw_bits, 2);
    lcw0 = lcw_bits[0];
    lcw1 = lcw_bits[1];
    hcw = clearBlockLsb(hcw);
    scw[Bin] = hcw;
    tau[2 * (Bin - 1)] = lcw0;
    tau[2 * (Bin - 1) + 1] = lcw1;

    const osuCrypto::block leafCw0 = setBlockLsb(hcw, lcw0);
    const osuCrypto::block leafCw1 = setBlockLsb(hcw, lcw1);
    for (size_t j = 0; j < penultimateSize; j++) {
        const osuCrypto::block current = levelNodes[j];
        const BooleanElement controlBit = blockLsb(current);
        const osuCrypto::block q0 = ccrHash(current);
        const osuCrypto::block q1 =
            ccrHash(current ^ osuCrypto::OneBlock);
        nextLevelNodes[2 * j] =
            q0 ^ (controlBit ? leafCw0 : osuCrypto::ZeroBlock);
        nextLevelNodes[2 * j + 1] =
            q1 ^ (controlBit ? leafCw1 : osuCrypto::ZeroBlock);
    }
    std::swap(levelNodes, nextLevelNodes);

    osuCrypto::block leafXor = osuCrypto::ZeroBlock;
    GroupElement convertedSum(0, Bout);
    uint64_t controlBitSum = 0;
    for (size_t i = 0; i < leafCapacity; i++) {
        leafXor = leafXor ^ levelNodes[i];
        if (computeArithmeticSums) {
            convertedSum =
                convertedSum + convertBlockToGroup(Bout, levelNodes[i]);
        }
        controlBitSum += static_cast<uint64_t>(blockLsb(levelNodes[i]));
    }

    CorrelatedTreeMaterial material;
    material.Bin = Bin;
    material.Bout = Bout;
    material.scw = scw;
    material.tau = tau;
    material.leaf_xor = leafXor;
    material.converted_sum = convertedSum;
    material.control_bit_sum = controlBitSum;
    return material;
}

osuCrypto::block evalCorrelatedDPFLeaf(const BooleanElement* opened_bits,
                                       const DPFKeyPack& key,
                                       BooleanElement* controlBitOut) {
    return evalLeaf(opened_bits, key, controlBitOut);
}

osuCrypto::block evalCorrelatedDPFLeaf(
    const BooleanElement* opened_bits, const BooleanDPFKeyPack& key,
    BooleanElement* controlBitOut) {
    return evalLeaf(opened_bits, key, controlBitOut);
}

}  // namespace dfss::internal
