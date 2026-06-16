/*
 * Description: Refer to README.md
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

#include "legacy/dcf.h"

#include <memory>
#include <stdexcept>
#include <string>

using namespace osuCrypto;

inline int bytesize(const int bitsize) {
    return (bitsize % 8) == 0 ? bitsize / 8 : (bitsize / 8)  + 1;
}

namespace {

constexpr size_t kParallelDcfPrgExpansionThreshold = 4096;
constexpr int kMaxFullTreeBits = 24;

void ensureSupportedFullTreeBits(const int bits, const char* caller) {
    if (bits < 0 || bits > kMaxFullTreeBits) {
        throw std::invalid_argument(
            std::string(caller) + " requires 0 <= bit length <= " +
            std::to_string(kMaxFullTreeBits) +
            " in the current full-tree implementation");
    }
}

void expandDcfPrgLevel(const block* levelNodes, block* nextLevelNodes,
                       block* thisLevelV, size_t expandNum,
                       block& leftChildren, block& rightChildren) {
    static const block notThreeBlock = osuCrypto::toBlock(~0, ~3);
    static const block ThreeBlock = osuCrypto::toBlock(~0, 3);
    const static block pt[4] = {ZeroBlock, OneBlock, notThreeBlock, ThreeBlock};

    leftChildren = ZeroBlock;
    rightChildren = ZeroBlock;

#ifdef _OPENMP
    const int threadCount = omp_get_max_threads();
    if (expandNum >= kParallelDcfPrgExpansionThreshold && threadCount > 1) {
        std::vector<block> leftPartials(threadCount, ZeroBlock);
        std::vector<block> rightPartials(threadCount, ZeroBlock);

#pragma omp parallel
        {
            const int tid = omp_get_thread_num();
            AES aes;
            block ct[4];
            block localLeft = ZeroBlock;
            block localRight = ZeroBlock;

#pragma omp for
            for (long long jj = 0; jj < static_cast<long long>(expandNum); jj++) {
                const size_t j = static_cast<size_t>(jj);
                aes.setKey(levelNodes[j]);
                aes.ecbEncFourBlocks(pt, ct);
                localLeft = localLeft ^ ct[0];
                localRight = localRight ^ ct[1];
                nextLevelNodes[2 * j] = ct[0];
                nextLevelNodes[2 * j + 1] = ct[1];
                thisLevelV[2 * j] = ct[2];
                thisLevelV[2 * j + 1] = ct[3];
            }

            leftPartials[tid] = localLeft;
            rightPartials[tid] = localRight;
        }

        for (int tid = 0; tid < threadCount; tid++) {
            leftChildren = leftChildren ^ leftPartials[tid];
            rightChildren = rightChildren ^ rightPartials[tid];
        }
        return;
    }
#endif

    AES aes;
    block ct[4];
    for (size_t j = 0; j < expandNum; j++) {
        aes.setKey(levelNodes[j]);
        aes.ecbEncFourBlocks(pt, ct);
        leftChildren = leftChildren ^ ct[0];
        rightChildren = rightChildren ^ ct[1];
        nextLevelNodes[2 * j] = ct[0];
        nextLevelNodes[2 * j + 1] = ct[1];
        thisLevelV[2 * j] = ct[2];
        thisLevelV[2 * j + 1] = ct[3];
    }
}

}

newDCFKeyPack keyGenNewDCF(int party_id, int Bin, int Bout, GroupElement idx, GroupElement payload){
    ensureSupportedFullTreeBits(Bin, "keyGenNewDCF");
    auto rng = secure_prng();
    auto s = rng.get<std::array<block, 1>>();

    // One full leaf-level buffer plus one half-level buffer is enough for
    // nodes/control bits. The DCF V buffer still needs one full next layer.
    const size_t leafCapacity = size_t(1) << Bin;
    const size_t halfCapacity = (leafCapacity > 1) ? (leafCapacity / 2) : 1;
    auto largeLevelNodes = std::make_unique<block[]>(leafCapacity);
    auto smallLevelNodes = std::make_unique<block[]>(halfCapacity);
    auto thisLevelV = std::make_unique<block[]>(leafCapacity);
    auto largeControlBits = std::make_unique<u8[]>(leafCapacity);
    auto smallControlBits = std::make_unique<u8[]>(halfCapacity);
    block* levelNodes = (Bin % 2 == 0) ? largeLevelNodes.get() : smallLevelNodes.get();
    block* nextLevelNodes = (Bin % 2 == 0) ? smallLevelNodes.get() : largeLevelNodes.get();
    u8* levelControlBits = (Bin % 2 == 0) ? largeControlBits.get() : smallControlBits.get();
    u8* nextLevelControlBits = (Bin % 2 == 0) ? smallControlBits.get() : largeControlBits.get();
    uint64_t convert_val = 0;
    block null_block;

    levelNodes[0] = s[0];
    levelControlBits[0] = (u8)(party_id-2);
    GroupElement v_alpha(0, Bout);

    // The format of the final key is: s|CW_i|W_CW -> s|(s|V_CW|t|t)...|W_CW
    // lambda| n lambda | n GE |2n u8|GE
    auto tau = makeKeyArray<u8>(Bin * 2);
    auto scw = makeKeyArray<block>(Bin + 1);
    auto vcw = makeKeyArray<GroupElement>(Bin + 1);
    scw[0] = s[0];
    block sigma;

    // Get bits value
    std::vector<u8> real_idx(Bin);
    u8 level_and_res = 0;
    for (int i = 0; i < Bin; i++) {
        real_idx[Bin - i - 1] = idx[Bin - i - 1] ^ level_and_res;
        level_and_res = check_bit_overflow(party_id, idx[Bin - i - 1], level_and_res, peer);
    }

    // Body iteration
    for (int i = 0; i < Bin; i++){
        block leftChildren = ZeroBlock;
        block rightChildren = ZeroBlock;
        const size_t expandNum = size_t(1) << i;
        GroupElement v0(0, Bout);
        GroupElement v1(0, Bout);
        expandDcfPrgLevel(levelNodes, nextLevelNodes, thisLevelV.get(), expandNum,
                          leftChildren, rightChildren);

        uint8_t mux_input = real_idx[i] ^ (party_id - 2);
        sigma = multiplexer2(party_id, mux_input, leftChildren, rightChildren, peer);
        u8 tau_0 = lsb(leftChildren) ^ real_idx[i] ^ (u8)(party_id - 2);
        u8 tau_1 = lsb(rightChildren) ^ real_idx[i];

        block recL = leftChildren;
        block recR = rightChildren;
        reconstruct(&recL);
        reconstruct(&recR);

        reconstruct(&sigma);
        reconstruct(&tau_0);
        reconstruct(&tau_1);

        // Now we parse CW
        tau[i * 2] = tau_0;
        tau[i * 2 + 1] = tau_1;
        scw[i + 1] = sigma;

        uint64_t thisControlBitSum = 0;

        for (size_t j = 0; j < expandNum; j++) {
            nextLevelControlBits[2 * j] = lsb(nextLevelNodes[2 * j]);
            nextLevelControlBits[2 * j + 1] = lsb(nextLevelNodes[2 * j + 1]);
            if (levelControlBits[j] == (u8)1) {
                // Here the sigma does not contain the info of CW control bit, i.e. simply add scw
                // cannot update control bit to hold on-path attribute
                nextLevelNodes[2 * j] = nextLevelNodes[2 * j] ^ scw[i + 1];
                nextLevelNodes[2 * j + 1] = nextLevelNodes[2 * j + 1] ^ scw[i + 1];
                nextLevelControlBits[2 * j] = nextLevelControlBits[2 * j] ^ tau_0;
                nextLevelControlBits[2 * j + 1] = nextLevelControlBits[2 * j + 1] ^ tau_1;
            }

            // Compute CW now (Convert)
            two_pc_convert(Bout, thisLevelV[2 * j], &convert_val, &null_block);
            v0 = v0 + GroupElement(convert_val, Bout);
            two_pc_convert(Bout, thisLevelV[2 * j + 1], &convert_val, &null_block);
            v1 = v1 + GroupElement(convert_val, Bout);

            // Get control bit sum (prev level)
            thisControlBitSum += (uint64_t)levelControlBits[j];
        }

        u8 cmp_tau_0_ = (u8)(thisControlBitSum & 1);
        u8 cmp_tau_1_ = (u8)((thisControlBitSum >> 1) & 1);
        u8 g = cmp_2bit_opt(party_id, cmp_tau_1_, cmp_tau_0_, peer);

        // We reuse mux_input here, get phi
        GroupElement phi_input_A = v0;
        GroupElement phi_input_B = v1;
        if ((party_id - 2) == 0){
            phi_input_A = phi_input_A * (-1);
            phi_input_B = phi_input_B * (-1);
        }
        GroupElement phi_output = multiplexer2(party_id, mux_input, phi_input_A, phi_input_B, peer);
        GroupElement theta(0, Bout);
        theta = phi_output + (v0 + v1) * (((party_id - 2) == 0) ? 1 : (-1));

        // Get eta
        GroupElement zero(0 ,Bout);
        GroupElement eta_output = multiplexer2(party_id, real_idx[i], zero, payload, peer);

        // Set Vcw
        GroupElement v_alpha_share = v_alpha * static_cast<uint64_t>(party_id == SERVER);
        GroupElement vcw_0 = phi_output - v_alpha_share + eta_output;
        GroupElement vcw_1 = -phi_output + v_alpha_share - eta_output;
        GroupElement vcw_output = multiplexer2(party_id, g, vcw_0, vcw_1, peer);

        reconstruct(&vcw_output);
        vcw[i] = vcw_output;

        GroupElement g_a = B2A(party_id, g, Bout, peer);
        // Inject public constants into one additive share before reconstruction.
        GroupElement public_share(static_cast<uint64_t>(party_id == SERVER), Bout);
        GroupElement v_alpha_update_share = v_alpha * public_share.value;
        GroupElement sign_share = g_a * (-2) + public_share;
        GroupElement v_alpha_hat = v_alpha_update_share + theta + sign_share * vcw_output;
        reconstruct(&v_alpha_hat);
        v_alpha = v_alpha_hat;

        std::swap(levelNodes, nextLevelNodes);
        std::swap(levelControlBits, nextLevelControlBits);
    }
    // Evaluate the last CW
    // To begin with, we add all control bits together
    uint64_t controlBitSum = 0;
    // We also need to add all Converted elements
    uint64_t lastLevelSum = 0;
    for (size_t i = 0; i < leafCapacity; i++){
        uint64_t converted = 0;
        two_pc_convert(Bout, levelNodes[i], &converted, &null_block);
        lastLevelSum = lastLevelSum + converted;
        controlBitSum = controlBitSum + (uint64_t)levelControlBits[i];
    }
    u8 cmp_tau_0 = (u8)(controlBitSum & 1);
    u8 cmp_tau_1 = (u8)((controlBitSum >> 1) & 1);
    u8 t = cmp_2bit_opt(party_id, cmp_tau_1, cmp_tau_0, peer);
    GroupElement sign(((party_id-2) == 1) ? 1 : -1, Bout);
    GroupElement v_alpha_share = v_alpha * static_cast<uint64_t>(party_id == SERVER);
    GroupElement W_CW_0 = -v_alpha_share + lastLevelSum * sign;
    GroupElement W_CW_1 = v_alpha_share + lastLevelSum * (-sign);
    GroupElement W_CW = multiplexer2(party_id, t, W_CW_0, W_CW_1, peer);
    reconstruct(&W_CW);

    vcw[Bin] = W_CW;

    newDCFKeyPack key;
    key.Bin = Bin;
    key.Bout = Bout;
    key.k = scw;
    key.g = vcw;
    key.v = tau;
    return key;
}

void evalNewDCF(int party, GroupElement* res, const GroupElement* idx, const newDCFKeyPack* keyList, int size, int max_bitsize){
    // Assume uniform bitsize = max_bitsize
    std::vector<int> Bin(size);
    std::vector<int> Bout(size);
    std::vector<const GroupElement*> g_list(size);
    std::vector<const u8*> t_list(size);
    std::vector<const block*> s_list(size);
    std::vector<u8> controlBit(size);
    std::vector<GroupElement> V(size);
    std::vector<block> levelNodes(size);
    std::vector<uint64_t> converted_val(size);
    std::vector<block> null_block(size);

    static const block notOneBlock = osuCrypto::toBlock(~0, ~1);
    static const block notThreeBlock = osuCrypto::toBlock(~0, ~3);
    static const block ThreeBlock = osuCrypto::toBlock(~0, 3);
    const static block pt[4] = {ZeroBlock, OneBlock, notThreeBlock, ThreeBlock};
    std::vector<block> ct(4 * size);

    // Init all variables
    for (int i = 0; i < size; i++){
       // Parse key first
       Bin[i] = keyList[i].Bin;
       Bout[i] = keyList[i].Bout;
       controlBit[i] = (u8)(party - 2);
       V[i].value = 0;
       V[i].bitsize = Bout[i];
       g_list[i] = keyList[i].g;
       t_list[i] = keyList[i].v;
       s_list[i] = keyList[i].k;
       levelNodes[i] = s_list[i][0];
    }

    // Body iteration
    for (int i = 0; i < max_bitsize; i++) {

        osuCrypto::AES AESInstance;
        for (int j = 0; j < size; j++) {
            AESInstance.setKey(levelNodes[j]);
            AESInstance.ecbEncFourBlocks(pt, &(ct[4 * j]));
            if (idx[j][i] == (u8) 0) {
                two_pc_convert(Bout[j], ct[j * 4 + 2], &(converted_val[j]), &(null_block[j]));
            } else {
                two_pc_convert(Bout[j], ct[j * 4 + 3], &(converted_val[j]), &(null_block[j]));
            }
            V[j] = V[j] +
                   (converted_val[j] + (uint64_t) controlBit[j] * g_list[j][i]) * (((party - 2) == 0) ? 1 : (-1));
            if (controlBit[j] == (u8) 1) {
                // Apply correction words
                levelNodes[j] = ct[4 * j + (int) (idx[j][i])] ^ s_list[j][i + 1];
                controlBit[j] = lsb(ct[4 * j + (int) (idx[j][i])]) ^ t_list[j][2 * i + (int) (idx[j][i])];
            } else {
                levelNodes[j] = ct[4 * j + (int) (idx[j][i])];
                controlBit[j] = lsb(ct[4 * j + (int) (idx[j][i])]);
            }
        }
    }

    // Final V calculation
    for (int i = 0; i < size; i++){
        two_pc_convert(Bout[i], levelNodes[i], &(converted_val[i]), &(null_block[i]));
        GroupElement final_term =
            (((party - 2) == 0) ? 1 : (-1)) *
            (converted_val[i] + g_list[i][Bin[i]] * (uint64_t)controlBit[i]);
        res[i] = V[i] + final_term;
    }

}
