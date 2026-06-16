#include "fss/idpf.h"

#include <memory>
#include <stdexcept>
#include <vector>

#include "mpc/secure_ops.h"
#include "mpc/api.h"
#include "fss/internal/ggm.h"
#include "fss/internal/payload_conversion.h"

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

BooleanElement blockLsb(const osuCrypto::block& input) {
    return _mm_cvtsi128_si64x(input) & 1;
}

}  // namespace

namespace dfss {

DPFKeyPack keyGeniDPF(int party_id, int Bin, int Bout,
                      const BooleanElement* alpha_bits,
                      const GroupElement* beta_per_level) {
    ensureSupportedFullTreeBits(Bin, "dfss::keyGeniDPF");

    auto rng = secure_prng();
    auto s = rng.get<osuCrypto::block>();
    const size_t leafCapacity = size_t(1) << Bin;
    const size_t halfCapacity = (leafCapacity > 1) ? (leafCapacity / 2) : 1;
    auto largeLevelNodes =
        std::make_unique<osuCrypto::block[]>(leafCapacity);
    auto smallLevelNodes =
        std::make_unique<osuCrypto::block[]>(halfCapacity);
    auto largeControlBits = std::make_unique<BooleanElement[]>(leafCapacity);
    auto smallControlBits = std::make_unique<BooleanElement[]>(halfCapacity);
    osuCrypto::block* levelNodes =
        (Bin % 2 == 0) ? largeLevelNodes.get() : smallLevelNodes.get();
    osuCrypto::block* nextLevelNodes =
        (Bin % 2 == 0) ? smallLevelNodes.get() : largeLevelNodes.get();
    BooleanElement* levelControlBits =
        (Bin % 2 == 0) ? largeControlBits.get() : smallControlBits.get();
    BooleanElement* nextLevelControlBits =
        (Bin % 2 == 0) ? smallControlBits.get() : largeControlBits.get();

    levelNodes[0] = s;
    levelControlBits[0] = static_cast<BooleanElement>(party_id - 2);

    auto tau = makeKeyArray<BooleanElement>(Bin * 2);
    auto scw = makeKeyArray<osuCrypto::block>(Bin + 1);
    auto W_CW = makeKeyArray<GroupElement>(Bin);
    std::vector<BooleanElement> payload_choices(Bin);
    std::vector<GroupElement> W_CW_0(Bin, GroupElement(0, Bout));
    std::vector<GroupElement> W_CW_1(Bin, GroupElement(0, Bout));
    scw[0] = s;
    for (int i = 0; i < Bin; i++) {
        W_CW[i].bitsize = Bout;
    }

    for (int i = 0; i < Bin; i++) {
        osuCrypto::block leftChildren = osuCrypto::ZeroBlock;
        osuCrypto::block rightChildren = osuCrypto::ZeroBlock;
        const size_t expandNum = size_t(1) << i;
        internal::expandDpfPrgLevel(levelNodes, nextLevelNodes, expandNum,
                                    leftChildren, rightChildren);

        const uint8_t mux_input =
            alpha_bits[i] ^ static_cast<BooleanElement>(party_id - 2);
        osuCrypto::block sigma =
            multiplexer2(party_id, mux_input, leftChildren, rightChildren,
                         peer);
        BooleanElement tau_0 =
            blockLsb(leftChildren) ^ alpha_bits[i] ^
            static_cast<BooleanElement>(party_id - 2);
        BooleanElement tau_1 = blockLsb(rightChildren) ^ alpha_bits[i];

        BooleanElement tau_bits[2] = {tau_0, tau_1};
        reconstruct(&sigma, tau_bits, 2);
        tau_0 = tau_bits[0];
        tau_1 = tau_bits[1];

        tau[i * 2] = tau_0;
        tau[i * 2 + 1] = tau_1;
        scw[i + 1] = sigma;

        for (size_t j = 0; j < expandNum; j++) {
            nextLevelControlBits[2 * j] = blockLsb(nextLevelNodes[2 * j]);
            nextLevelControlBits[2 * j + 1] =
                blockLsb(nextLevelNodes[2 * j + 1]);
            if (levelControlBits[j] == static_cast<BooleanElement>(1)) {
                nextLevelNodes[2 * j] =
                    nextLevelNodes[2 * j] ^ scw[i + 1];
                nextLevelNodes[2 * j + 1] =
                    nextLevelNodes[2 * j + 1] ^ scw[i + 1];
                nextLevelControlBits[2 * j] =
                    nextLevelControlBits[2 * j] ^ tau_0;
                nextLevelControlBits[2 * j + 1] =
                    nextLevelControlBits[2 * j + 1] ^ tau_1;
            }
        }

        std::swap(levelNodes, nextLevelNodes);
        std::swap(levelControlBits, nextLevelControlBits);

        uint64_t controlBitSum = 0;
        uint64_t levelSum = 0;
        for (size_t j = 0; j < 2 * expandNum; j++) {
            const osuCrypto::block label = internal::setBlockLsb(
                levelNodes[j],
                static_cast<osuCrypto::u8>(levelControlBits[j]));
            const uint64_t converted =
                internal::convertPayload_iDPF(Bout, label);
            levelSum += converted;
            controlBitSum += static_cast<uint64_t>(levelControlBits[j]);
        }

        const BooleanElement t =
            internal::dpfPayloadChoiceBit(party_id, controlBitSum, 1);
        GroupElement sign(((party_id - 2) == 1) ? 1 : -1, Bout);
        payload_choices[i] = t;
        W_CW_0[i] = beta_per_level[i] + levelSum * sign;
        W_CW_1[i] = -beta_per_level[i] + levelSum * (-sign);
    }
    multiplexer2(party_id, payload_choices.data(), W_CW_0.data(),
                 W_CW_1.data(), W_CW.data(), Bin, peer);
    reconstruct(Bin, W_CW.data(), Bout);

    DPFKeyPack key;
    key.Bin = Bin;
    key.Bout = Bout;
    key.groupSize = 1;
    key.k = scw;
    key.g = W_CW;
    key.v = tau;
    return key;
}

DPFKeyPack keyGeniDPFBit(int party_id, int Bin,
                         const BooleanElement* alpha_bits) {
    ensureSupportedFullTreeBits(Bin, "dfss::keyGeniDPFBit");

    auto rng = secure_prng();
    auto s = rng.get<osuCrypto::block>();
    const size_t leafCapacity = size_t(1) << Bin;
    const size_t halfCapacity = (leafCapacity > 1) ? (leafCapacity / 2) : 1;
    auto largeLevelNodes =
        std::make_unique<osuCrypto::block[]>(leafCapacity);
    auto smallLevelNodes =
        std::make_unique<osuCrypto::block[]>(halfCapacity);
    auto largeControlBits = std::make_unique<BooleanElement[]>(leafCapacity);
    auto smallControlBits = std::make_unique<BooleanElement[]>(halfCapacity);
    osuCrypto::block* levelNodes =
        (Bin % 2 == 0) ? largeLevelNodes.get() : smallLevelNodes.get();
    osuCrypto::block* nextLevelNodes =
        (Bin % 2 == 0) ? smallLevelNodes.get() : largeLevelNodes.get();
    BooleanElement* levelControlBits =
        (Bin % 2 == 0) ? largeControlBits.get() : smallControlBits.get();
    BooleanElement* nextLevelControlBits =
        (Bin % 2 == 0) ? smallControlBits.get() : largeControlBits.get();

    levelNodes[0] = s;
    levelControlBits[0] = static_cast<BooleanElement>(party_id - 2);

    auto tau = makeKeyArray<BooleanElement>(Bin * 2);
    auto scw = makeKeyArray<osuCrypto::block>(Bin + 1);
    scw[0] = s;

    for (int i = 0; i < Bin; i++) {
        osuCrypto::block leftChildren = osuCrypto::ZeroBlock;
        osuCrypto::block rightChildren = osuCrypto::ZeroBlock;
        const size_t expandNum = size_t(1) << i;
        internal::expandDpfPrgLevel(levelNodes, nextLevelNodes, expandNum,
                                    leftChildren, rightChildren);

        const uint8_t mux_input =
            alpha_bits[i] ^ static_cast<BooleanElement>(party_id - 2);
        osuCrypto::block sigma =
            multiplexer2(party_id, mux_input, leftChildren, rightChildren,
                         peer);
        BooleanElement tau_0 =
            blockLsb(leftChildren) ^ alpha_bits[i] ^
            static_cast<BooleanElement>(party_id - 2);
        BooleanElement tau_1 = blockLsb(rightChildren) ^ alpha_bits[i];

        BooleanElement tau_bits[2] = {tau_0, tau_1};
        reconstruct(&sigma, tau_bits, 2);
        tau_0 = tau_bits[0];
        tau_1 = tau_bits[1];

        tau[i * 2] = tau_0;
        tau[i * 2 + 1] = tau_1;
        scw[i + 1] = sigma;

        for (size_t j = 0; j < expandNum; j++) {
            nextLevelControlBits[2 * j] = blockLsb(nextLevelNodes[2 * j]);
            nextLevelControlBits[2 * j + 1] =
                blockLsb(nextLevelNodes[2 * j + 1]);
            if (levelControlBits[j] == static_cast<BooleanElement>(1)) {
                nextLevelNodes[2 * j] =
                    nextLevelNodes[2 * j] ^ scw[i + 1];
                nextLevelNodes[2 * j + 1] =
                    nextLevelNodes[2 * j + 1] ^ scw[i + 1];
                nextLevelControlBits[2 * j] =
                    nextLevelControlBits[2 * j] ^ tau_0;
                nextLevelControlBits[2 * j + 1] =
                    nextLevelControlBits[2 * j + 1] ^ tau_1;
            }
        }

        std::swap(levelNodes, nextLevelNodes);
        std::swap(levelControlBits, nextLevelControlBits);
    }

    DPFKeyPack key;
    key.Bin = Bin;
    key.Bout = 1;
    key.groupSize = 1;
    key.k = scw;
    key.v = tau;
    return key;
}

std::vector<GroupElement> evaliDPF(int party_id, GroupElement public_x,
                                   const DPFKeyPack& key) {
    osuCrypto::AES aes;
    const int Bin = key.Bin;
    const int Bout = key.Bout;
    std::vector<GroupElement> result(Bin);
    const osuCrypto::block* scw = key.k;
    const GroupElement* wcw = key.g;
    const BooleanElement* tau = key.v;

    osuCrypto::block node = scw[0];
    BooleanElement controlBit = static_cast<BooleanElement>(party_id - 2);
    BooleanElement level_tau = controlBit;
    const static osuCrypto::block pt[2] = {osuCrypto::ZeroBlock,
                                           osuCrypto::OneBlock};
    osuCrypto::block ct[2];

    for (int i = 0; i < Bin; i++) {
        aes.setKey(node);
        aes.ecbEncTwoBlocks(pt, ct);
        const osuCrypto::block levelCW = scw[i + 1];
        level_tau = tau[2 * i + static_cast<int>(public_x[i])];
        if (controlBit == static_cast<BooleanElement>(1)) {
            node = ct[static_cast<int>(public_x[i])] ^ levelCW;
            controlBit =
                blockLsb(ct[static_cast<int>(public_x[i])]) ^ level_tau;
        } else {
            node = ct[static_cast<int>(public_x[i])];
            controlBit = blockLsb(ct[static_cast<int>(public_x[i])]);
        }

        const int sign = (party_id - 2) ? -1 : 1;
        const osuCrypto::block label =
            internal::setBlockLsb(node, static_cast<osuCrypto::u8>(controlBit));
        const uint64_t converted =
            internal::convertPayload_iDPF(Bout, label);
        result[i] =
            (wcw[i] * static_cast<uint64_t>(controlBit) + converted) * sign;
    }
    return result;
}

}  // namespace dfss
