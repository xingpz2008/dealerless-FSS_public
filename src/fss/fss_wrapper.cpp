#include "fss/fss_wrapper.h"

#include <memory>
#include <stdexcept>
#include <vector>

#include "mpc/secure_ops.h"
#include "fss/dpf.h"
#include "fss/idpf.h"

namespace {

std::vector<BooleanElement> decomposeInput(int party_id, GroupElement& input,
                                           bool masked,
                                           std::shared_ptr<GroupElement>& mask) {
    mask = std::make_shared<GroupElement>(0, input.bitsize);
    if (masked) {
        auto rng = secure_prng();
        mask->value = rng.get<uint64_t>();
        mod(*mask);
        input = input + *mask;
    }
    return BitDec(party_id, input, input.bitsize, peer);
}

KeyArray<BooleanElement> maskBooleanTarget(int Bin,
                                           const BooleanElement* input_bits,
                                           bool masked,
                                           std::vector<BooleanElement>& shifted) {
    if (input_bits == nullptr) {
        throw std::invalid_argument("Boolean FSS wrapper requires input bits");
    }
    shifted.resize(Bin);
    KeyArray<BooleanElement> mask;
    if (masked) {
        mask = makeKeyArray<BooleanElement>(Bin);
        auto rng = secure_prng();
        for (int i = 0; i < Bin; i++) {
            mask[i] = static_cast<BooleanElement>(rng.get<uint8_t>() & 1);
            shifted[i] =
                static_cast<BooleanElement>((input_bits[i] & 1) ^ mask[i]);
        }
    } else {
        for (int i = 0; i < Bin; i++) {
            shifted[i] = static_cast<BooleanElement>(input_bits[i] & 1);
        }
    }
    return mask;
}

std::vector<BooleanElement> openBooleanInput(const BooleanElement* input_bits,
                                             const KeyArray<BooleanElement>& mask,
                                             int Bin, bool masked) {
    if (input_bits == nullptr) {
        throw std::invalid_argument("Boolean FSS wrapper requires input bits");
    }
    if (masked && !mask) {
        throw std::invalid_argument(
            "Boolean FSS wrapper eval requires a Boolean-mask key");
    }
    std::vector<BooleanElement> opened(Bin);
    for (int i = 0; i < Bin; i++) {
        opened[i] = static_cast<BooleanElement>(
            (input_bits[i] & 1) ^ (masked ? (mask[i] & 1) : 0));
    }
    reconstruct(static_cast<int32_t>(Bin), opened.data());
    return opened;
}

GroupElement groupFromPublicBits(const BooleanElement* bits, int Bin) {
    uint64_t value = 0;
    for (int i = 0; i < Bin; i++) {
        value |= uint64_t(bits[i] & 1) << (Bin - 1 - i);
    }
    return GroupElement(value, Bin);
}

}  // namespace

namespace dfss::wrapper {

DPFKeyPack keyGenDPF(int party_id, GroupElement input, GroupElement beta,
                     DPFOptions options) {
    if (!options.correlated && options.earlyTerminationSuffixBits != -1) {
        throw std::invalid_argument(
            "DPF wrapper does not support early termination for full-GGM DPF");
    }
    std::shared_ptr<GroupElement> mask;
    std::vector<BooleanElement> bits =
        decomposeInput(party_id, input, options.masked, mask);
    if (!options.correlated) {
        DPFKeyPack key =
            ::dfss::keyGenDPF(party_id, input.bitsize, beta.bitsize,
                              bits.data(), beta);
        key.random_mask = mask;
        return key;
    }
    if (options.earlyTerminationSuffixBits == -2) {
        DPFKeyPack key =
            ::dfss::keyGenET(party_id, input.bitsize, beta.bitsize,
                             bits.data(), beta);
        key.random_mask = mask;
        return key;
    }
    if (options.earlyTerminationSuffixBits >= 0) {
        DPFKeyPack key =
            ::dfss::keyGenET(party_id, input.bitsize, beta.bitsize,
                             options.earlyTerminationSuffixBits, bits.data(),
                             beta);
        key.random_mask = mask;
        return key;
    }
    DPFKeyPack key =
        ::dfss::keyGenCorrelatedDPF(party_id, input.bitsize, beta.bitsize,
                                    bits.data(), beta);
    key.random_mask = mask;
    return key;
}

DPFKeyPack keyGenDPF(int party_id, int Bin, const BooleanElement* input_bits,
                     GroupElement beta, DPFOptions options) {
    if (beta.bitsize <= 0) {
        throw std::invalid_argument("DPF wrapper requires a valid payload");
    }
    if (!options.correlated && options.earlyTerminationSuffixBits != -1) {
        throw std::invalid_argument(
            "DPF wrapper does not support early termination for full-GGM DPF");
    }
    std::vector<BooleanElement> shifted_bits;
    KeyArray<BooleanElement> mask =
        maskBooleanTarget(Bin, input_bits, options.masked, shifted_bits);
    DPFKeyPack key;
    if (!options.correlated) {
        key = ::dfss::keyGenDPF(party_id, Bin, beta.bitsize,
                                shifted_bits.data(), beta);
    } else if (options.earlyTerminationSuffixBits == -2) {
        key = ::dfss::keyGenET(party_id, Bin, beta.bitsize,
                               shifted_bits.data(), beta);
    } else if (options.earlyTerminationSuffixBits >= 0) {
        key = ::dfss::keyGenET(party_id, Bin, beta.bitsize,
                               options.earlyTerminationSuffixBits,
                               shifted_bits.data(), beta);
    } else {
        key = ::dfss::keyGenCorrelatedDPF(party_id, Bin, beta.bitsize,
                                          shifted_bits.data(), beta);
    }
    key.boolean_mask = mask;
    return key;
}

DPFKeyPack keyGenDPF(int party_id, GroupElement input, GroupElement beta,
                     bool earlyTermination) {
    DPFOptions options;
    options.earlyTerminationSuffixBits = earlyTermination ? -2 : -1;
    return keyGenDPF(party_id, input, beta, options);
}

DPFKeyPack keyGenDPF(int party_id, GroupElement input, GroupElement beta,
                     int suffixBits) {
    DPFOptions options;
    options.earlyTerminationSuffixBits = suffixBits;
    return keyGenDPF(party_id, input, beta, options);
}

void evalDPF(int party_id, GroupElement* output, GroupElement input,
             const DPFKeyPack& key, DPFOptions options) {
    *output = evalDPF(party_id, input, key, options);
}

GroupElement evalDPF(int party_id, GroupElement input, const DPFKeyPack& key,
                     DPFOptions options) {
    if (key.prefixBits > 0 || key.vectorSize > 0) {
        if (options.masked) {
            if (!key.random_mask) {
                throw std::invalid_argument(
                    "ET DPF wrapper eval requires an arithmetic-mask key");
            }
            input = input + *key.random_mask;
            reconstruct(1, &input, input.bitsize);
        }
        return ::dfss::evalET(party_id, input.value, key);
    }
    if (!options.correlated) {
        if (options.masked) {
            if (!key.random_mask) {
                throw std::invalid_argument(
                    "DPF wrapper eval requires an arithmetic-mask key");
            }
            input = input + *key.random_mask;
            reconstruct(1, &input, input.bitsize);
        }
        return ::dfss::evalDPF(party_id, input, key);
    }
    if (options.masked) {
        if (!key.random_mask) {
            throw std::invalid_argument(
                "correlated DPF wrapper eval requires an arithmetic-mask key");
        }
        input = input + *key.random_mask;
        reconstruct(1, &input, input.bitsize);
    }
    return ::dfss::evalCorrelatedDPF(party_id, input, key);
}

GroupElement evalDPF(int party_id, const BooleanElement* input_bits,
                     const DPFKeyPack& key, DPFOptions options) {
    std::vector<BooleanElement> opened =
        openBooleanInput(input_bits, key.boolean_mask, key.Bin, options.masked);
    DPFOptions public_options = options;
    public_options.masked = false;
    return evalDPF(party_id, groupFromPublicBits(opened.data(), key.Bin), key,
                   public_options);
}

void evalDPF(int party_id, GroupElement* output,
             const BooleanElement* input_bits, const DPFKeyPack& key,
             DPFOptions options) {
    *output = evalDPF(party_id, input_bits, key, options);
}

void evalAllDPF(int party_id, GroupElement* output, const DPFKeyPack& key) {
    ::dfss::evalAllDPF(party_id, output, key);
}

DPFKeyPack keyGenDPF(int party_id, GroupElement input, bool masked) {
    std::shared_ptr<GroupElement> mask;
    std::vector<BooleanElement> bits =
        decomposeInput(party_id, input, masked, mask);
    DPFKeyPack key =
        ::dfss::keyGenCorrelatedDPFBit(party_id, input.bitsize, bits.data());
    key.random_mask = mask;
    return key;
}

DPFKeyPack keyGenDPF(int party_id, int Bin, const BooleanElement* input_bits,
                     bool masked) {
    std::vector<BooleanElement> shifted_bits;
    KeyArray<BooleanElement> mask =
        maskBooleanTarget(Bin, input_bits, masked, shifted_bits);
    DPFKeyPack key =
        ::dfss::keyGenCorrelatedDPFBit(party_id, Bin, shifted_bits.data());
    key.boolean_mask = mask;
    return key;
}

BooleanElement evalDPFBit(int party_id, GroupElement input,
                          const DPFKeyPack& key, bool masked) {
    if (masked) {
        if (!key.random_mask) {
            throw std::invalid_argument(
                "DPF bit wrapper eval requires an arithmetic-mask key");
        }
        input = input + *key.random_mask;
        reconstruct(1, &input, input.bitsize);
    }
    return ::dfss::evalCorrelatedDPFBit(party_id, input, key);
}

BooleanElement evalDPFBit(int party_id, const BooleanElement* input_bits,
                          const DPFKeyPack& key, bool masked) {
    std::vector<BooleanElement> opened =
        openBooleanInput(input_bits, key.boolean_mask, key.Bin, masked);
    return ::dfss::evalCorrelatedDPFBit(
        party_id, groupFromPublicBits(opened.data(), key.Bin), key);
}

BooleanDPFKeyPack keyGenDPF(int party_id, GroupElement input,
                            osuCrypto::block beta, bool masked) {
    std::shared_ptr<GroupElement> mask;
    std::vector<BooleanElement> bits =
        decomposeInput(party_id, input, masked, mask);
    BooleanDPFKeyPack key =
        ::dfss::keyGenBooleanCorrelatedDPF(party_id, input.bitsize,
                                           bits.data(), beta);
    key.random_mask = mask;
    return key;
}

BooleanDPFKeyPack keyGenDPF(int party_id, int Bin,
                            const BooleanElement* input_bits,
                            osuCrypto::block beta, bool masked) {
    std::vector<BooleanElement> shifted_bits;
    KeyArray<BooleanElement> mask =
        maskBooleanTarget(Bin, input_bits, masked, shifted_bits);
    BooleanDPFKeyPack key =
        ::dfss::keyGenBooleanCorrelatedDPF(party_id, Bin, shifted_bits.data(),
                                           beta);
    key.boolean_mask = mask;
    return key;
}

osuCrypto::block evalDPFBlock(int party_id, GroupElement input,
                              const BooleanDPFKeyPack& key, bool masked) {
    if (masked) {
        if (!key.random_mask) {
            throw std::invalid_argument(
                "DPF block wrapper eval requires an arithmetic-mask key");
        }
        input = input + *key.random_mask;
        reconstruct(1, &input, input.bitsize);
    }
    return ::dfss::evalBooleanCorrelatedDPF(party_id, input, key);
}

osuCrypto::block evalDPFBlock(int party_id, const BooleanElement* input_bits,
                              const BooleanDPFKeyPack& key, bool masked) {
    std::vector<BooleanElement> opened =
        openBooleanInput(input_bits, key.boolean_mask, key.Bin, masked);
    return ::dfss::evalBooleanCorrelatedDPF(
        party_id, groupFromPublicBits(opened.data(), key.Bin), key);
}

DPFKeyPack keyGeniDPF(int party_id, GroupElement input,
                      const GroupElement* beta_per_level, bool masked) {
    if (beta_per_level == nullptr) {
        throw std::invalid_argument("keyGeniDPF requires payload shares");
    }
    if (masked) {
        throw std::invalid_argument(
            "iDPF wrapper currently supports unmasked mode only");
    }
    std::shared_ptr<GroupElement> mask;
    std::vector<BooleanElement> bits =
        decomposeInput(party_id, input, false, mask);
    return ::dfss::keyGeniDPF(party_id, input.bitsize,
                              beta_per_level[0].bitsize, bits.data(),
                              beta_per_level);
}

DPFKeyPack keyGeniDPF(int party_id, GroupElement input, bool masked) {
    if (masked) {
        throw std::invalid_argument(
            "Boolean iDPF wrapper currently supports unmasked mode only");
    }
    std::shared_ptr<GroupElement> mask;
    std::vector<BooleanElement> bits =
        decomposeInput(party_id, input, false, mask);
    return ::dfss::keyGeniDPFBit(party_id, input.bitsize, bits.data());
}

DPFKeyPack keyGenRandomDPF(int party_id, int Bin, GroupElement beta,
                           GroupElement* random_target_share,
                           DPFOptions options) {
    if (random_target_share == nullptr) {
        throw std::invalid_argument("keyGenRandomDPF requires output target");
    }
    auto rng = secure_prng();
    *random_target_share = random_ge_from_prng(rng, Bin);
    options.masked = false;
    return keyGenDPF(party_id, *random_target_share, beta, options);
}

DPFKeyPack keyGenRandomiDPF(int party_id, int Bin,
                            const GroupElement* beta_per_level,
                            GroupElement* random_target_share) {
    if (random_target_share == nullptr) {
        throw std::invalid_argument("keyGenRandomiDPF requires output target");
    }
    auto rng = secure_prng();
    *random_target_share = random_ge_from_prng(rng, Bin);
    return keyGeniDPF(party_id, *random_target_share, beta_per_level, false);
}

DPFKeyPack keyGenRandomiDPF(int party_id, int Bin,
                            GroupElement* random_target_share) {
    if (random_target_share == nullptr) {
        throw std::invalid_argument("keyGenRandomiDPF requires output target");
    }
    auto rng = secure_prng();
    *random_target_share = random_ge_from_prng(rng, Bin);
    return keyGeniDPF(party_id, *random_target_share, false);
}

}  // namespace dfss::wrapper

namespace dfss {

DPFKeyPack keyGenArithmeticDPF(int party_id, GroupElement input,
                               GroupElement beta, bool correlated,
                               bool masked) {
    return wrapper::keyGenDPF(party_id, input, beta, {masked, correlated, -1});
}

DPFKeyPack keyGenCorrelatedDPF(int party_id, int Bin, int Bout,
                               GroupElement input, GroupElement beta,
                               bool masked) {
    if (input.bitsize != Bin || beta.bitsize != Bout) {
        throw std::invalid_argument("keyGenCorrelatedDPF wrapper bit mismatch");
    }
    return keyGenArithmeticDPF(party_id, input, beta, true, masked);
}

void evalArithmeticDPF(int party_id, GroupElement* output, GroupElement input,
                       const DPFKeyPack& key, bool correlated, bool masked) {
    wrapper::evalDPF(party_id, output, input, key, {masked, correlated, -1});
}

GroupElement evalArithmeticDPF(int party_id, GroupElement input,
                               const DPFKeyPack& key, bool correlated,
                               bool masked) {
    return wrapper::evalDPF(party_id, input, key, {masked, correlated, -1});
}

void evalCorrelatedDPF(int party_id, GroupElement* output, GroupElement input,
                       const DPFKeyPack& key, bool masked) {
    *output = evalCorrelatedDPF(party_id, input, key, masked);
}

GroupElement evalCorrelatedDPF(int party_id, GroupElement input,
                               const DPFKeyPack& key, bool masked) {
    return evalArithmeticDPF(party_id, input, key, true, masked);
}

DPFKeyPack keyGenCorrelatedDPFBit(int party_id, GroupElement input,
                                  bool masked) {
    return wrapper::keyGenDPF(party_id, input, masked);
}

DPFKeyPack keyGenCorrelatedDPFBit(int party_id, int Bin,
                                  GroupElement input, bool masked) {
    if (input.bitsize != Bin) {
        throw std::invalid_argument(
            "keyGenCorrelatedDPFBit wrapper bit mismatch");
    }
    return keyGenCorrelatedDPFBit(party_id, input, masked);
}

BooleanElement evalCorrelatedDPFBit(int party_id, GroupElement input,
                                    const DPFKeyPack& key, bool masked) {
    if (masked) {
        if (!key.random_mask) {
            throw std::invalid_argument(
                "evalCorrelatedDPFBit wrapper requires an arithmetic-mask key");
        }
        input = input + *key.random_mask;
        reconstruct(1, &input, input.bitsize);
    }
    return ::dfss::evalCorrelatedDPFBit(party_id, input, key);
}

BooleanDPFKeyPack keyGenBooleanCorrelatedDPF(
    int party_id, GroupElement input, osuCrypto::block beta, bool masked) {
    return wrapper::keyGenDPF(party_id, input, beta, masked);
}

BooleanDPFKeyPack keyGenBooleanCorrelatedDPF(
    int party_id, int Bin, GroupElement input, osuCrypto::block beta,
    bool masked) {
    if (input.bitsize != Bin) {
        throw std::invalid_argument(
            "keyGenBooleanCorrelatedDPF wrapper bit mismatch");
    }
    return keyGenBooleanCorrelatedDPF(party_id, input, beta, masked);
}

osuCrypto::block evalBooleanCorrelatedDPF(
    int party_id, GroupElement input, const BooleanDPFKeyPack& key,
    bool masked) {
    if (masked) {
        if (!key.random_mask) {
            throw std::invalid_argument(
                "evalBooleanCorrelatedDPF wrapper requires an arithmetic-mask key");
        }
        input = input + *key.random_mask;
        reconstruct(1, &input, input.bitsize);
    }
    return ::dfss::evalBooleanCorrelatedDPF(party_id, input, key);
}

void evalBooleanCorrelatedDPF(
    int party_id, osuCrypto::block* output, GroupElement input,
    const BooleanDPFKeyPack& key, bool masked) {
    *output = evalBooleanCorrelatedDPF(party_id, input, key, masked);
}

DPFKeyPack keyGeniDPF(int party_id, GroupElement input,
                      const GroupElement* beta_per_level, bool masked) {
    return wrapper::keyGeniDPF(party_id, input, beta_per_level, masked);
}

DPFKeyPack keyGeniDPF(int party_id, int Bin, int Bout, GroupElement input,
                      const GroupElement* beta_per_level, bool call_from_DCF,
                      bool masked) {
    (void)call_from_DCF;
    if (input.bitsize != Bin || beta_per_level == nullptr ||
        beta_per_level[0].bitsize != Bout) {
        throw std::invalid_argument("keyGeniDPF wrapper bit mismatch");
    }
    return wrapper::keyGeniDPF(party_id, input, beta_per_level, masked);
}

std::vector<GroupElement> evaliDPF(int party_id, GroupElement input,
                                   const DPFKeyPack& key, bool masked) {
    if (masked) {
        throw std::invalid_argument(
            "evaliDPF compatibility wrapper supports unmasked mode only");
    }
    return ::dfss::evaliDPF(party_id, input, key);
}

int defaultDPFETSuffixBits(int Bin, int Bout, int lambdaBits) {
    return defaultETSuffixBits(Bin, Bout, lambdaBits);
}

DPFKeyPack keyGenDPFET(int party_id, int Bin, int Bout, GroupElement input,
                       GroupElement beta, int lambdaBits) {
    if (input.bitsize != Bin || beta.bitsize != Bout) {
        throw std::invalid_argument("keyGenDPFET wrapper bit mismatch");
    }
    wrapper::DPFOptions options;
    options.masked = false;
    options.correlated = true;
    options.earlyTerminationSuffixBits =
        lambdaBits == 128 ? -2 : defaultETSuffixBits(Bin, Bout, lambdaBits);
    return wrapper::keyGenDPF(party_id, input, beta, options);
}

DPFKeyPack keyGenDPFET(int party_id, int Bin, int Bout, int suffixBits,
                       GroupElement input, GroupElement beta) {
    if (input.bitsize != Bin || beta.bitsize != Bout) {
        throw std::invalid_argument("keyGenDPFET wrapper bit mismatch");
    }
    wrapper::DPFOptions options;
    options.masked = false;
    options.correlated = true;
    options.earlyTerminationSuffixBits = suffixBits;
    return wrapper::keyGenDPF(party_id, input, beta, options);
}

void evalDPFET(int party_id, GroupElement* output, uint64_t public_x,
               const DPFKeyPack& key) {
    ::dfss::evalET(party_id, output, public_x, key);
}

GroupElement evalDPFET(int party_id, uint64_t public_x,
                       const DPFKeyPack& key) {
    return ::dfss::evalET(party_id, public_x, key);
}

void evalAllDPFET(int party_id, GroupElement* output, const DPFKeyPack& key) {
    ::dfss::evalAllET(party_id, output, key);
}

}  // namespace dfss
