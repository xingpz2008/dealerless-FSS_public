#include "fss/dpf.h"

#include <cassert>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "mpc/secure_ops.h"
#include "mpc/api.h"
#include "fss/internal/correlated_ggm.h"
#include "fss/internal/ggm.h"
#include "fss/internal/payload_conversion.h"

namespace {

constexpr int kMaxFullTreeBits = 24;

int ceilDivPositive(int numerator, int denominator) {
    return (numerator + denominator - 1) / denominator;
}

int ceilLog2AtLeastOne(int value) {
    int output = 0;
    int capacity = 1;
    while (capacity < value) {
        capacity <<= 1;
        output++;
    }
    return output;
}

void ensureSupportedFullTreeBits(const int bits, const char* caller) {
    if (bits < 0 || bits > kMaxFullTreeBits) {
        throw std::invalid_argument(
            std::string(caller) + " requires 0 <= bit length <= " +
            std::to_string(kMaxFullTreeBits) +
            " in the current full-tree implementation");
    }
}

void validateETKeyShape(const DPFKeyPack& key, const char* caller) {
    ensureSupportedFullTreeBits(key.Bin, caller);
    if (key.prefixBits <= 0 || key.suffixBits < 0 ||
        key.prefixBits + key.suffixBits != key.Bin ||
        key.vectorSize != (1 << key.suffixBits)) {
        throw std::invalid_argument(std::string(caller) +
                                    " received an invalid key");
    }
}

std::vector<BooleanElement> bitsFromGroup(GroupElement input) {
    std::vector<BooleanElement> bits(input.bitsize);
    for (int i = 0; i < input.bitsize; i++) {
        bits[i] = input[i];
    }
    return bits;
}

BooleanElement blockLsb(const osuCrypto::block& input) {
    return _mm_cvtsi128_si64x(input) & 1;
}

}  // namespace

namespace dfss {

DPFKeyPack keyGenDPF(int party_id, int Bin, int Bout,
                     const BooleanElement* alpha_bits, GroupElement beta) {
    ensureSupportedFullTreeBits(Bin, "dfss::keyGenDPF");
    if (alpha_bits == nullptr) {
        throw std::invalid_argument("dfss::keyGenDPF requires target bits");
    }

    auto rng = secure_prng();
    const osuCrypto::block root = rng.get<osuCrypto::block>();
    const size_t leafCapacity = size_t(1) << Bin;
    const size_t halfCapacity = (leafCapacity > 1) ? (leafCapacity / 2) : 1;
    auto largeLevelNodes =
        std::make_unique<osuCrypto::block[]>(leafCapacity);
    auto smallLevelNodes =
        std::make_unique<osuCrypto::block[]>(halfCapacity);
    auto largeControlBits =
        std::make_unique<BooleanElement[]>(leafCapacity);
    auto smallControlBits =
        std::make_unique<BooleanElement[]>(halfCapacity);
    osuCrypto::block* levelNodes =
        (Bin % 2 == 0) ? largeLevelNodes.get()
                       : smallLevelNodes.get();
    osuCrypto::block* nextLevelNodes =
        (Bin % 2 == 0) ? smallLevelNodes.get()
                       : largeLevelNodes.get();
    BooleanElement* levelControlBits =
        (Bin % 2 == 0) ? largeControlBits.get()
                       : smallControlBits.get();
    BooleanElement* nextLevelControlBits =
        (Bin % 2 == 0) ? smallControlBits.get()
                       : largeControlBits.get();

    levelNodes[0] = root;
    levelControlBits[0] = static_cast<BooleanElement>(party_id - SERVER);

    auto tau = makeKeyArray<BooleanElement>(Bin * 2);
    auto scw = makeKeyArray<osuCrypto::block>(Bin + 1);
    scw[0] = root;

    for (int i = 0; i < Bin; i++) {
        osuCrypto::block leftChildren = osuCrypto::ZeroBlock;
        osuCrypto::block rightChildren = osuCrypto::ZeroBlock;
        const size_t expandNum = size_t(1) << i;
        internal::expandDpfPrgLevel(levelNodes, nextLevelNodes, expandNum,
                                    leftChildren, rightChildren);

        const BooleanElement directionShare =
            static_cast<BooleanElement>(alpha_bits[i] & 1);
        const BooleanElement muxInput =
            directionShare ^ static_cast<BooleanElement>(party_id - SERVER);
        osuCrypto::block sigma =
            multiplexer2(party_id, muxInput, leftChildren, rightChildren,
                         peer);
        BooleanElement tau0 =
            blockLsb(leftChildren) ^ directionShare ^
            static_cast<BooleanElement>(party_id - SERVER);
        BooleanElement tau1 = blockLsb(rightChildren) ^ directionShare;

        BooleanElement tau_bits[2] = {tau0, tau1};
        reconstruct(&sigma, tau_bits, 2);
        tau0 = tau_bits[0];
        tau1 = tau_bits[1];

        tau[i * 2] = tau0;
        tau[i * 2 + 1] = tau1;
        scw[i + 1] = sigma;

        // Apply the opened seed/control correction to every node controlled by
        // this party's current control bit.
        for (size_t j = 0; j < expandNum; j++) {
            nextLevelControlBits[2 * j] = blockLsb(nextLevelNodes[2 * j]);
            nextLevelControlBits[2 * j + 1] =
                blockLsb(nextLevelNodes[2 * j + 1]);
            if (levelControlBits[j] == static_cast<BooleanElement>(1)) {
                nextLevelNodes[2 * j] =
                    nextLevelNodes[2 * j] ^ scw[i + 1];
                nextLevelNodes[2 * j + 1] =
                    nextLevelNodes[2 * j + 1] ^ scw[i + 1];
                nextLevelControlBits[2 * j] ^= tau0;
                nextLevelControlBits[2 * j + 1] ^= tau1;
            }
        }
        std::swap(levelNodes, nextLevelNodes);
        std::swap(levelControlBits, nextLevelControlBits);
    }

    uint64_t controlBitSum = 0;
    uint64_t convertedSum = 0;
    for (size_t i = 0; i < leafCapacity; i++) {
        uint64_t converted = 0;
        internal::convertBlockToWords(Bout, 1, levelNodes[i], &converted);
        convertedSum += converted;
        controlBitSum += static_cast<uint64_t>(levelControlBits[i]);
    }

    // Arithmetic payload conversion uses the same second-LSB choice as the
    // correlated-DPF path; only the tree generation is ordinary GGM here.
    const BooleanElement payloadChoice =
        internal::dpfPayloadChoiceBit(party_id, controlBitSum, 1);
    GroupElement sign(((party_id - SERVER) == 1) ? 1 : -1, Bout);
    GroupElement W_CW_0 = beta + convertedSum * sign;
    GroupElement W_CW_1 = -beta + convertedSum * (-sign);
    auto W_CW = makeKeyArray<GroupElement>(1);
    W_CW[0] = multiplexer2(party_id, payloadChoice, W_CW_0, W_CW_1, peer);
    reconstruct(W_CW.data());

    DPFKeyPack key;
    key.Bin = Bin;
    key.Bout = Bout;
    key.groupSize = 1;
    key.k = scw;
    key.g = W_CW;
    key.v = tau;
    return key;
}

DPFKeyPack keyGenCorrelatedDPF(int party_id, int Bin, int Bout,
                               const BooleanElement* alpha_bits,
                               GroupElement beta) {
    const internal::CorrelatedTreeMaterial material =
        internal::generateCorrelatedTree(
            party_id, Bin, Bout, alpha_bits, "dfss::keyGenCorrelatedDPF", true);
    const int party_bit = party_id - SERVER;
    const BooleanElement payload_choice =
        internal::dpfPayloadChoiceBit(party_id, material.control_bit_sum, 1);
    GroupElement sign(party_bit == 1 ? 1 : -1, Bout);
    GroupElement W_CW_0 = beta + material.converted_sum * sign;
    GroupElement W_CW_1 = -beta + material.converted_sum * (-sign);
    auto W_CW = makeKeyArray<GroupElement>(1);
    W_CW[0] = multiplexer2(party_id, payload_choice, W_CW_0, W_CW_1, peer);
    reconstruct(W_CW.data());

    DPFKeyPack key;
    key.Bin = material.Bin;
    key.Bout = material.Bout;
    key.groupSize = 1;
    key.prefixBits = material.Bin;
    key.suffixBits = 0;
    key.vectorSize = 1;
    key.k = material.scw;
    key.g = W_CW;
    key.v = material.tau;
    return key;
}

DPFKeyPack keyGenCorrelatedDPFBit(int party_id, int Bin,
                                  const BooleanElement* alpha_bits) {
    const internal::CorrelatedTreeMaterial material =
        internal::generateCorrelatedTree(
            party_id, Bin, 1, alpha_bits, "dfss::keyGenCorrelatedDPFBit", false);

    DPFKeyPack key;
    key.Bin = material.Bin;
    key.Bout = 1;
    key.groupSize = 1;
    key.prefixBits = material.Bin;
    key.suffixBits = 0;
    key.vectorSize = 1;
    key.k = material.scw;
    key.v = material.tau;
    return key;
}

BooleanDPFKeyPack keyGenBooleanCorrelatedDPF(
    int party_id, int Bin, const BooleanElement* alpha_bits,
    osuCrypto::block beta) {
    const internal::CorrelatedTreeMaterial material =
        internal::generateCorrelatedTree(
            party_id, Bin, 1, alpha_bits, "dfss::keyGenBooleanCorrelatedDPF",
            false);

    auto W_CW = makeKeyArray<osuCrypto::block>(1);
    W_CW[0] = material.leaf_xor ^ beta;
    reconstruct(W_CW.data());

    BooleanDPFKeyPack key;
    key.Bin = material.Bin;
    key.groupSize = 1;
    key.k = material.scw;
    key.g = W_CW;
    key.v = material.tau;
    return key;
}

GroupElement evalDPF(int party_id, GroupElement public_x,
                     const DPFKeyPack& key) {
    if (public_x.bitsize != key.Bin) {
        throw std::invalid_argument("dfss::evalDPF point bit length mismatch");
    }

    osuCrypto::AES aes;
    osuCrypto::block node = key.k[0];
    BooleanElement controlBit =
        static_cast<BooleanElement>(party_id - SERVER);
    const static osuCrypto::block pt[2] = {osuCrypto::ZeroBlock,
                                           osuCrypto::OneBlock};
    osuCrypto::block ct[2];

    for (int i = 0; i < key.Bin; i++) {
        const int direction = static_cast<int>(public_x[i]);
        aes.setKey(node);
        aes.ecbEncTwoBlocks(pt, ct);
        const osuCrypto::block levelCW = key.k[i + 1];
        const BooleanElement levelTau = key.v[2 * i + direction];
        if (controlBit == static_cast<BooleanElement>(1)) {
            node = ct[direction] ^ levelCW;
            controlBit = blockLsb(ct[direction]) ^ levelTau;
        } else {
            node = ct[direction];
            controlBit = blockLsb(ct[direction]);
        }
    }

    const int sign = (party_id - SERVER) ? -1 : 1;
    GroupElement converted = internal::convertRawBlockToGroup(key.Bout, node);
    return (key.g[0] * static_cast<uint64_t>(controlBit) + converted) * sign;
}

GroupElement evalCorrelatedDPF(int party_id, GroupElement public_x,
                               const DPFKeyPack& key) {
    const std::vector<BooleanElement> bits = bitsFromGroup(public_x);
    BooleanElement controlBit = 0;
    const osuCrypto::block leaf =
        internal::evalCorrelatedDPFLeaf(bits.data(), key, &controlBit);

    const int sign = (party_id - SERVER) ? -1 : 1;
    GroupElement converted = internal::convertBlockToGroup(key.Bout, leaf);
    return (key.g[0] * static_cast<uint64_t>(controlBit) + converted) * sign;
}

BooleanElement evalCorrelatedDPFBit(int party_id, GroupElement public_x,
                                    const DPFKeyPack& key) {
    const std::vector<BooleanElement> bits = bitsFromGroup(public_x);
    BooleanElement controlBit = 0;
    internal::evalCorrelatedDPFLeaf(bits.data(), key, &controlBit);
    return controlBit;
}

osuCrypto::block evalBooleanCorrelatedDPF(
    int party_id, GroupElement public_x, const BooleanDPFKeyPack& key) {
    const std::vector<BooleanElement> bits = bitsFromGroup(public_x);
    BooleanElement controlBit = 0;
    const osuCrypto::block leaf =
        internal::evalCorrelatedDPFLeaf(bits.data(), key, &controlBit);
    return leaf ^ (controlBit ? key.g[0] : osuCrypto::ZeroBlock);
}

void evalAllCorrelatedDPF(int party_id, GroupElement* output,
                          const DPFKeyPack& key, int length) {
    assert(length == key.Bin);
    if (length <= 0) {
        throw std::invalid_argument("evalAllCorrelatedDPF requires length > 0");
    }

    std::vector<osuCrypto::block> level_nodes(1, key.k[0]);
    for (int level = 0; level < length - 1; level++) {
        std::vector<osuCrypto::block> next_nodes(size_t(1) << (level + 1));
#pragma omp parallel for if(next_nodes.size() >= 1024)
        for (long long node_ll = 0;
             node_ll < static_cast<long long>(level_nodes.size());
             node_ll++) {
            const size_t node = static_cast<size_t>(node_ll);
            const osuCrypto::block current = level_nodes[node];
            const BooleanElement controlBit = blockLsb(current);
            const osuCrypto::block hashed = internal::ccrHash(current);
            const osuCrypto::block correction =
                controlBit ? key.k[level + 1] : osuCrypto::ZeroBlock;
            next_nodes[2 * node] = hashed ^ correction;
            next_nodes[2 * node + 1] = hashed ^ current ^ correction;
        }
        level_nodes.swap(next_nodes);
    }

    const size_t penultimate_size = level_nodes.size();
    const osuCrypto::block leafCw0 =
        internal::setBlockLsb(key.k[length], key.v[2 * (length - 1)]);
    const osuCrypto::block leafCw1 = internal::setBlockLsb(
        key.k[length], key.v[2 * (length - 1) + 1]);
    const int sign = (party_id - SERVER) ? -1 : 1;
#pragma omp parallel for if(penultimate_size >= 1024)
    for (long long node_ll = 0;
         node_ll < static_cast<long long>(penultimate_size); node_ll++) {
        const size_t node = static_cast<size_t>(node_ll);
        const osuCrypto::block current = level_nodes[node];
        const BooleanElement controlBit = blockLsb(current);
        const osuCrypto::block q0 = internal::ccrHash(current);
        const osuCrypto::block q1 =
            internal::ccrHash(current ^ osuCrypto::OneBlock);
        const osuCrypto::block leaf0 =
            q0 ^ (controlBit ? leafCw0 : osuCrypto::ZeroBlock);
        const osuCrypto::block leaf1 =
            q1 ^ (controlBit ? leafCw1 : osuCrypto::ZeroBlock);
        const BooleanElement leafControl0 = blockLsb(leaf0);
        const BooleanElement leafControl1 = blockLsb(leaf1);
        output[2 * node] =
            (key.g[0] * static_cast<uint64_t>(leafControl0) +
             internal::convertBlockToGroup(key.Bout, leaf0)) *
            sign;
        output[2 * node + 1] =
            (key.g[0] * static_cast<uint64_t>(leafControl1) +
             internal::convertBlockToGroup(key.Bout, leaf1)) *
            sign;
    }
}

int defaultETSuffixBits(int Bin, int Bout, int lambdaBits) {
    if (Bin <= 0) {
        throw std::invalid_argument("defaultETSuffixBits requires Bin > 0");
    }
    if (Bout <= 0) {
        throw std::invalid_argument("defaultETSuffixBits requires Bout > 0");
    }
    if (lambdaBits <= 0) {
        throw std::invalid_argument(
            "defaultETSuffixBits requires lambdaBits > 0");
    }

    const int lambda_over_output = ceilDivPositive(lambdaBits, Bout);
    int suffixBits = ceilLog2AtLeastOne(lambda_over_output);
    if (suffixBits >= Bin) {
        suffixBits = Bin - 1;
    }
    return suffixBits;
}

DPFKeyPack keyGenET(int party_id, int Bin, int Bout,
                    const BooleanElement* alpha_bits, GroupElement beta,
                    int lambdaBits) {
    return keyGenET(party_id, Bin, Bout,
                    defaultETSuffixBits(Bin, Bout, lambdaBits), alpha_bits,
                    beta);
}

DPFKeyPack keyGenET(int party_id, int Bin, int Bout, int suffixBits,
                    const BooleanElement* alpha_bits, GroupElement beta) {
    ensureSupportedFullTreeBits(Bin, "dfss::keyGenET");
    if (Bin <= 0) {
        throw std::invalid_argument("dfss::keyGenET requires Bin > 0");
    }
    if (alpha_bits == nullptr) {
        throw std::invalid_argument("dfss::keyGenET requires target bits");
    }
    if (suffixBits < 0 || suffixBits >= Bin) {
        throw std::invalid_argument(
            "dfss::keyGenET requires 0 <= suffixBits < Bin");
    }
    if (suffixBits == 0) {
        return keyGenCorrelatedDPF(party_id, Bin, Bout, alpha_bits, beta);
    }

    const int defaultSuffixBits = defaultETSuffixBits(Bin, Bout);
    if (suffixBits > defaultSuffixBits && party_id == SERVER) {
        std::cerr << "Warning: dfss::keyGenET suffixBits=" << suffixBits
                  << " exceeds default ceil(log2(ceil(lambdaBits / Bout)))="
                  << defaultSuffixBits << " for lambdaBits=128, Bout=" << Bout
                  << ". This may increase OHG and DPF-ET cost.\n";
    }

    const int prefixBits = Bin - suffixBits;
    const int vectorSize = 1 << suffixBits;
    const int party_bit = party_id - SERVER;
    auto rng = secure_prng();

    // Use the same local cGGM root setup as full DPF, but expand only to the
    // prefix depth h = Bin - suffixBits.
    osuCrypto::block root = rng.get<osuCrypto::block>();
    root = internal::setBlockLsb(root, static_cast<osuCrypto::u8>(party_bit));
    const osuCrypto::block delta_share = root;

    std::vector<BooleanElement> real_idx(Bin);
    for (int i = 0; i < Bin; i++) {
        real_idx[i] = static_cast<BooleanElement>(alpha_bits[i] & 1);
    }

    std::vector<BooleanElement> suffix_one_hot(vectorSize, 0);
    booleanOneHotFromBits(party_id, real_idx.data() + prefixBits, suffixBits,
                          suffix_one_hot.data(), peer);

    // OHG gives Boolean shares of e_eta; arithmetic MUXes lift those bits to
    // the vector payload B, selecting between 0 and beta.
    std::vector<GroupElement> payload_vector(vectorSize);
    std::vector<GroupElement> suffix_payload(vectorSize);
    for (int i = 0; i < vectorSize; i++) {
        payload_vector[i] = beta;
        payload_vector[i].bitsize = Bout;
        suffix_payload[i] = GroupElement(0, Bout);
    }
    multiplexer(party_id, suffix_one_hot, payload_vector.data(),
                suffix_payload.data(), vectorSize, peer);

    const size_t leafCapacity = size_t(1) << prefixBits;
    const size_t halfCapacity = (leafCapacity > 1) ? (leafCapacity / 2) : 1;
    auto largeLevelNodes =
        std::make_unique<osuCrypto::block[]>(leafCapacity);
    auto smallLevelNodes =
        std::make_unique<osuCrypto::block[]>(halfCapacity);
    osuCrypto::block* levelNodes =
        (prefixBits % 2 == 0) ? largeLevelNodes.get()
                              : smallLevelNodes.get();
    osuCrypto::block* nextLevelNodes =
        (prefixBits % 2 == 0) ? smallLevelNodes.get()
                              : largeLevelNodes.get();
    levelNodes[0] = root;

    auto tau = makeKeyArray<BooleanElement>(prefixBits * 2);
    auto scw = makeKeyArray<osuCrypto::block>(prefixBits + 1);
    scw[0] = root;
    for (int i = 0; i < prefixBits * 2; i++) {
        tau[i] = 0;
    }

    std::vector<osuCrypto::block> delta_selected(prefixBits > 1 ? prefixBits - 1
                                                                : 0);
    if (prefixBits > 1) {
        std::vector<BooleanElement> alpha_bar_shares(prefixBits - 1);
        std::vector<osuCrypto::block> delta_choices(prefixBits - 1,
                                                    delta_share);
        for (int i = 0; i < prefixBits - 1; i++) {
            alpha_bar_shares[i] =
                real_idx[i] ^ static_cast<BooleanElement>(1 - party_bit);
        }
        bitBlockMultiply(party_id, alpha_bar_shares.data(),
                         delta_choices.data(), delta_selected.data(),
                         prefixBits - 1, peer);
    }

    // Generate cGGM layer correction words for the retained prefix tree.
    for (int i = 0; i < prefixBits - 1; i++) {
        const size_t levelSize = size_t(1) << i;

        osuCrypto::block levelHashXor = osuCrypto::ZeroBlock;
        for (size_t j = 0; j < levelSize; j++) {
            levelHashXor = levelHashXor ^ internal::ccrHash(levelNodes[j]);
        }

        osuCrypto::block layer_cw = levelHashXor ^ delta_selected[i];
        reconstruct(&layer_cw);
        scw[i + 1] = layer_cw;

        for (size_t j = 0; j < levelSize; j++) {
            const osuCrypto::block current = levelNodes[j];
            const BooleanElement controlBit = blockLsb(current);
            const osuCrypto::block hashed = internal::ccrHash(current);
            const osuCrypto::block correction =
                controlBit ? layer_cw : osuCrypto::ZeroBlock;
            nextLevelNodes[2 * j] = hashed ^ correction;
            nextLevelNodes[2 * j + 1] = hashed ^ current ^ correction;
        }
        std::swap(levelNodes, nextLevelNodes);
    }

    // Generate the leaf correction at the termination level h.
    const size_t penultimateSize = size_t(1) << (prefixBits - 1);
    const BooleanElement alpha_bar_last =
        real_idx[prefixBits - 1] ^ static_cast<BooleanElement>(1 - party_bit);
    osuCrypto::block high0 = osuCrypto::ZeroBlock;
    osuCrypto::block high1 = osuCrypto::ZeroBlock;
    BooleanElement low0 = 0;
    BooleanElement low1 = 0;
    for (size_t j = 0; j < penultimateSize; j++) {
        const osuCrypto::block q0 = internal::ccrHash(levelNodes[j]);
        const osuCrypto::block q1 =
            internal::ccrHash(levelNodes[j] ^ osuCrypto::OneBlock);
        high0 = high0 ^ internal::clearBlockLsb(q0);
        high1 = high1 ^ internal::clearBlockLsb(q1);
        low0 ^= blockLsb(q0);
        low1 ^= blockLsb(q1);
    }

    const osuCrypto::block high_diff = high0 ^ high1;
    osuCrypto::block high_selected = osuCrypto::ZeroBlock;
    bitBlockMultiply(party_id, &alpha_bar_last, &high_diff, &high_selected, 1,
                     peer);
    osuCrypto::block hcw = high0 ^ high_selected;
    BooleanElement lcw0 =
        low0 ^ real_idx[prefixBits - 1] ^ static_cast<BooleanElement>(party_bit);
    BooleanElement lcw1 = low1 ^ real_idx[prefixBits - 1];
    BooleanElement lcw_bits[2] = {lcw0, lcw1};
    reconstruct(&hcw, lcw_bits, 2);
    lcw0 = lcw_bits[0];
    lcw1 = lcw_bits[1];
    hcw = internal::clearBlockLsb(hcw);
    scw[prefixBits] = hcw;
    tau[2 * (prefixBits - 1)] = lcw0;
    tau[2 * (prefixBits - 1) + 1] = lcw1;

    const osuCrypto::block leafCw0 = internal::setBlockLsb(hcw, lcw0);
    const osuCrypto::block leafCw1 = internal::setBlockLsb(hcw, lcw1);
    for (size_t j = 0; j < penultimateSize; j++) {
        const osuCrypto::block current = levelNodes[j];
        const BooleanElement controlBit = blockLsb(current);
        const osuCrypto::block q0 = internal::ccrHash(current);
        const osuCrypto::block q1 =
            internal::ccrHash(current ^ osuCrypto::OneBlock);
        nextLevelNodes[2 * j] =
            q0 ^ (controlBit ? leafCw0 : osuCrypto::ZeroBlock);
        nextLevelNodes[2 * j + 1] =
            q1 ^ (controlBit ? leafCw1 : osuCrypto::ZeroBlock);
    }
    std::swap(levelNodes, nextLevelNodes);

    std::vector<GroupElement> convertedSum(vectorSize, GroupElement(0, Bout));
    std::vector<uint64_t> convertedScratch(vectorSize, 0);
    uint64_t controlBitSum = 0;
    for (size_t node = 0; node < leafCapacity; node++) {
        // Parse the terminated label as s_h || t_h, hash the seed part s_h,
        // then ConvertL expands that vector seed into L ring values.
        const osuCrypto::block vectorSeed =
            internal::ccrHash(internal::clearBlockLsb(levelNodes[node]));
        internal::addConvertedBlockVectorToSums(
            Bout, vectorSize, vectorSeed, convertedScratch, convertedSum);
        controlBitSum += static_cast<uint64_t>(blockLsb(levelNodes[node]));
    }

    // One MUX choice derived from the second LSB is shared across all vector
    // coordinates, then the vector payload correction word is opened.
    const BooleanElement payload_choice =
        internal::dpfPayloadChoiceBit(party_id, controlBitSum, 1);
    GroupElement sign(party_bit == 1 ? 1 : -1, Bout);
    std::vector<GroupElement> W_CW_0(vectorSize);
    std::vector<GroupElement> W_CW_1(vectorSize);
    auto W_CW = makeKeyArray<GroupElement>(vectorSize);
    for (int suffix = 0; suffix < vectorSize; suffix++) {
        W_CW_0[suffix] = suffix_payload[suffix] + convertedSum[suffix] * sign;
        W_CW_1[suffix] =
            -suffix_payload[suffix] + convertedSum[suffix] * (-sign);
        W_CW[suffix] = GroupElement(0, Bout);
    }
    std::vector<BooleanElement> payload_choices(vectorSize, payload_choice);
    multiplexer2(party_id, payload_choices.data(), W_CW_0.data(),
                 W_CW_1.data(), W_CW.data(), vectorSize, peer);
    reconstruct(vectorSize, W_CW.data(), Bout);

    DPFKeyPack key;
    key.Bin = Bin;
    key.Bout = Bout;
    key.groupSize = vectorSize;
    key.prefixBits = prefixBits;
    key.suffixBits = suffixBits;
    key.vectorSize = vectorSize;
    key.k = scw;
    key.g = W_CW;
    key.v = tau;
    return key;
}

void evalET(int party_id, GroupElement* output, uint64_t public_x,
            const DPFKeyPack& key) {
    *output = evalET(party_id, public_x, key);
}

GroupElement evalET(int party_id, uint64_t public_x, const DPFKeyPack& key) {
    validateETKeyShape(key, "dfss::evalET");
    const uint64_t domain = uint64_t(1) << key.Bin;
    if (public_x >= domain) {
        throw std::invalid_argument("dfss::evalET point outside domain");
    }
    if (key.suffixBits == 0) {
        return evalCorrelatedDPF(party_id, GroupElement(public_x, key.Bin),
                                 key);
    }

    osuCrypto::block node = key.k[0];
    for (int level = 0; level < key.prefixBits - 1; level++) {
        const int direction =
            static_cast<int>((public_x >> (key.Bin - 1 - level)) & 1);
        const BooleanElement controlBit = blockLsb(node);
        const osuCrypto::block hashed = internal::ccrHash(node);
        const osuCrypto::block correction =
            controlBit ? key.k[level + 1] : osuCrypto::ZeroBlock;
        node = direction == 0 ? (hashed ^ correction)
                              : (hashed ^ node ^ correction);
    }

    const int finalDirection =
        static_cast<int>((public_x >> key.suffixBits) & 1);
    const BooleanElement controlBit = blockLsb(node);
    const osuCrypto::block leafCw = internal::setBlockLsb(
        key.k[key.prefixBits],
        key.v[2 * (key.prefixBits - 1) + finalDirection]);
    const osuCrypto::block q =
        internal::ccrHash(node ^ (finalDirection ? osuCrypto::OneBlock
                                                 : osuCrypto::ZeroBlock));
    const osuCrypto::block leaf =
        q ^ (controlBit ? leafCw : osuCrypto::ZeroBlock);
    const BooleanElement leafControl = blockLsb(leaf);

    const osuCrypto::block vectorSeed =
        internal::ccrHash(internal::clearBlockLsb(leaf));
    std::vector<uint64_t> converted(key.vectorSize, 0);
    internal::convertBlockToWords(key.Bout, key.vectorSize, vectorSeed,
                                  converted.data());
    const int suffix =
        static_cast<int>(public_x & ((uint64_t(1) << key.suffixBits) - 1));
    const int sign = (party_id - SERVER) ? -1 : 1;
    return (key.g[suffix] * static_cast<uint64_t>(leafControl) +
            GroupElement(converted[suffix], key.Bout)) *
           sign;
}

void evalAllET(int party_id, GroupElement* output, const DPFKeyPack& key) {
    validateETKeyShape(key, "dfss::evalAllET");
    if (key.suffixBits == 0) {
        evalAllCorrelatedDPF(party_id, output, key, key.Bin);
        return;
    }

    // Expand only the retained prefix tree and apply the ET leaf correction at
    // level h.
    std::vector<osuCrypto::block> level_nodes(1, key.k[0]);
    for (int level = 0; level < key.prefixBits - 1; level++) {
        std::vector<osuCrypto::block> next_nodes(size_t(1) << (level + 1));
#pragma omp parallel for if(next_nodes.size() >= 1024)
        for (long long node_ll = 0;
             node_ll < static_cast<long long>(level_nodes.size());
             node_ll++) {
            const size_t node = static_cast<size_t>(node_ll);
            const osuCrypto::block current = level_nodes[node];
            const BooleanElement controlBit = blockLsb(current);
            const osuCrypto::block hashed = internal::ccrHash(current);
            const osuCrypto::block correction =
                controlBit ? key.k[level + 1] : osuCrypto::ZeroBlock;
            next_nodes[2 * node] = hashed ^ correction;
            next_nodes[2 * node + 1] = hashed ^ current ^ correction;
        }
        level_nodes.swap(next_nodes);
    }

    const size_t penultimate_size = level_nodes.size();
    const size_t prefix_leaf_size = size_t(1) << key.prefixBits;
    std::vector<osuCrypto::block> prefix_leaves(prefix_leaf_size);
    const osuCrypto::block leafCw0 = internal::setBlockLsb(
        key.k[key.prefixBits], key.v[2 * (key.prefixBits - 1)]);
    const osuCrypto::block leafCw1 = internal::setBlockLsb(
        key.k[key.prefixBits], key.v[2 * (key.prefixBits - 1) + 1]);

#pragma omp parallel for if(penultimate_size >= 1024)
    for (long long node_ll = 0;
         node_ll < static_cast<long long>(penultimate_size); node_ll++) {
        const size_t node = static_cast<size_t>(node_ll);
        const osuCrypto::block current = level_nodes[node];
        const BooleanElement controlBit = blockLsb(current);
        const osuCrypto::block q0 = internal::ccrHash(current);
        const osuCrypto::block q1 =
            internal::ccrHash(current ^ osuCrypto::OneBlock);
        prefix_leaves[2 * node] =
            q0 ^ (controlBit ? leafCw0 : osuCrypto::ZeroBlock);
        prefix_leaves[2 * node + 1] =
            q1 ^ (controlBit ? leafCw1 : osuCrypto::ZeroBlock);
    }

    const int sign = (party_id - SERVER) ? -1 : 1;
#pragma omp parallel if(prefix_leaf_size >= 1024)
    {
        // Keep conversion scratch per thread; allocating it per prefix leaf is
        // visible in full-domain ET evaluation for large domains.
        std::vector<uint64_t> converted(key.vectorSize, 0);
#pragma omp for
        for (long long node_ll = 0;
             node_ll < static_cast<long long>(prefix_leaf_size); node_ll++) {
            const size_t node = static_cast<size_t>(node_ll);
            const osuCrypto::block leaf = prefix_leaves[node];
            const BooleanElement controlBit = blockLsb(leaf);
            // ConvertL(H_S(s_h)) supplies the whole suffix vector for this
            // terminated prefix; the vector CW injects B only when the prefix
            // node is on-path.
            const osuCrypto::block vectorSeed =
                internal::ccrHash(internal::clearBlockLsb(leaf));
            internal::convertBlockToWords(key.Bout, key.vectorSize,
                                          vectorSeed, converted.data());
            for (int suffix = 0; suffix < key.vectorSize; suffix++) {
                output[node * key.vectorSize + suffix] =
                    (key.g[suffix] * static_cast<uint64_t>(controlBit) +
                     GroupElement(converted[suffix], key.Bout)) *
                    sign;
            }
        }
    }
}

void evalAllDPF(int party_id, GroupElement* output, const DPFKeyPack& key) {
    if (key.suffixBits < 0) {
        throw std::invalid_argument(
            "dfss::evalAllDPF requires a cGGM/ET key; ordinary GGM is point-eval only");
    }
    evalAllET(party_id, output, key);
}

}  // namespace dfss
