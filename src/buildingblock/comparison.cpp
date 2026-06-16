#include "buildingblock/comparison.h"

#include <cassert>
#include <stdexcept>
#include <string>

#include "buildingblock/mic.h"
#include "mpc/api.h"

namespace {

void validateThreshold(int Bin, uint64_t threshold, const char* caller) {
    if (Bin <= 0 || Bin >= 32) {
        throw std::invalid_argument(std::string(caller) +
                                    " requires 0 < Bin < 32");
    }
    const uint64_t domain = uint64_t(1) << Bin;
    if (threshold > domain) {
        throw std::invalid_argument(std::string(caller) +
                                    " threshold outside domain");
    }
}

uint64_t openPublicThreshold(GroupElement threshold_share) {
    reconstruct(&threshold_share);
    return threshold_share.value;
}

}  // namespace

namespace dfss {

ComparisonKeyPack comparisonOffline(int party_id, int Bin, int Bout,
                                    GroupElement payload) {
    ComparisonKeyPack key;
    key.Bin = Bin;
    key.Bout = Bout;
    key.MICKey = micOffline(party_id, Bin, Bout, payload);
    return key;
}

ComparisonKeyPack comparisonOffline(int party_id, int Bin, int Bout,
                                    GroupElement threshold_share,
                                    GroupElement payload) {
    if (payload.bitsize != Bout || threshold_share.bitsize != Bin) {
        throw std::invalid_argument("comparisonOffline bit length mismatch");
    }
    ComparisonKeyPack key = comparisonOffline(party_id, Bin, Bout, payload);
    key.threshold = openPublicThreshold(threshold_share);
    validateThreshold(Bin, key.threshold, "comparisonOffline");
    return key;
}

ComparisonBitKeyPack comparisonBitOffline(int party_id, int Bin) {
    ComparisonBitKeyPack key;
    key.Bin = Bin;
    key.MICKey = micBooleanOffline(party_id, Bin);
    return key;
}

ComparisonBitKeyPack comparisonBitOffline(int party_id, int Bin,
                                          GroupElement threshold_share) {
    if (threshold_share.bitsize != Bin) {
        throw std::invalid_argument(
            "comparisonBitOffline threshold bit length mismatch");
    }
    ComparisonBitKeyPack key = comparisonBitOffline(party_id, Bin);
    key.threshold = openPublicThreshold(threshold_share);
    validateThreshold(Bin, key.threshold, "comparisonBitOffline");
    return key;
}

GroupElement comparison(int party_id, GroupElement input, uint64_t threshold,
                        const ComparisonKeyPack& key) {
    validateThreshold(key.Bin, threshold, "comparison");
    const uint64_t domain = uint64_t(1) << key.Bin;
    if (threshold == 0) {
        return GroupElement(0, key.Bout);
    }
    if (threshold == domain) {
        return key.MICKey.payload_share;
    }

    const PublicInterval interval[1] = {{0, threshold}};
    GroupElement output(0, key.Bout);
    mic(party_id, input, interval, 1, &output, key.MICKey);
    return output;
}

GroupElement comparison(int party_id, GroupElement input,
                        const ComparisonKeyPack& key) {
    return comparison(party_id, input, key.threshold, key);
}

void comparison(int party_id, GroupElement* output, GroupElement input,
                uint64_t threshold, const ComparisonKeyPack& key) {
    *output = comparison(party_id, input, threshold, key);
}

void comparison(int party_id, GroupElement* output, GroupElement input,
                const ComparisonKeyPack& key) {
    *output = comparison(party_id, input, key);
}

void comparison(int party_id, GroupElement* output, const GroupElement* input,
                const ComparisonKeyPack* key_list, int size,
                int max_bitsize) {
    (void)max_bitsize;
    for (int i = 0; i < size; i++) {
        output[i] = comparison(party_id, input[i], key_list[i]);
    }
}

BooleanElement comparisonBit(int party_id, GroupElement input,
                             uint64_t threshold,
                             const ComparisonBitKeyPack& key) {
    validateThreshold(key.Bin, threshold, "comparisonBit");
    const uint64_t domain = uint64_t(1) << key.Bin;
    if (threshold == 0) {
        return 0;
    }
    if (threshold == domain) {
        return static_cast<BooleanElement>(party_id == SERVER);
    }

    const PublicInterval interval[1] = {{0, threshold}};
    BooleanElement output = 0;
    micBoolean(party_id, input, interval, 1, &output, key.MICKey);
    return output;
}

BooleanElement comparisonBit(int party_id, GroupElement input,
                             const ComparisonBitKeyPack& key) {
    return comparisonBit(party_id, input, key.threshold, key);
}

ComparisonKeyPack ringExtendOffline(int party_id, int input_bits,
                                    int output_bits) {
    assert(output_bits >= input_bits);
    GroupElement one((uint64_t)(party_id - SERVER), output_bits);
    return comparisonOffline(
        party_id, input_bits + 1, output_bits,
        GroupElement(uint64_t(1) << input_bits, input_bits + 1) *
            uint64_t(party_id - SERVER),
        one);
}

GroupElement ringExtend(int party_id, GroupElement input, int output_bits,
                        const ComparisonKeyPack& key) {
    assert(output_bits >= input.bitsize);
    if (output_bits == input.bitsize) {
        return input;
    }

    GroupElement lifted_input(input.value, input.bitsize + 1);
    GroupElement is_below_threshold = comparison(party_id, lifted_input, key);

    GroupElement one((uint64_t)(party_id - SERVER), output_bits);
    GroupElement carry = one - is_below_threshold;
    return GroupElement(input.value, output_bits) -
           carry * (uint64_t(1) << input.bitsize);
}

}  // namespace dfss
