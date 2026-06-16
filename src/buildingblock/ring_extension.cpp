#include "buildingblock/ring_extension.h"

#include <stdexcept>

#include "buildingblock/comparison.h"
#include "buildingblock/mic.h"

namespace dfss {

SignedRingExtensionKeyPack signedRingExtendOffline(int party_id,
                                                   int input_bits,
                                                   int output_bits) {
    if (input_bits <= 0 || output_bits < input_bits || input_bits >= 31) {
        throw std::invalid_argument(
            "signedRingExtendOffline requires 0 < input_bits <= output_bits and input_bits < 31");
    }
    GroupElement one((uint64_t)(party_id - 2), output_bits);
    SignedRingExtensionKeyPack key;
    key.input_bits = input_bits;
    key.output_bits = output_bits;
    key.CarryKey =
        comparisonOffline(party_id, input_bits + 1, output_bits, one);
    key.SignKey = comparisonOffline(party_id, input_bits, output_bits, one);
    return key;
}

GroupElement signedRingExtend(int party_id, GroupElement input,
                                 int output_bits,
                                 const SignedRingExtensionKeyPack& key) {
    if (output_bits != key.output_bits || input.bitsize != key.input_bits) {
        throw std::invalid_argument("signedRingExtend bit length mismatch");
    }
    if (output_bits == input.bitsize) {
        return input;
    }

    GroupElement lifted_input(input.value, input.bitsize + 1);
    // First compensate for additive-share wrap when embedding the unsigned
    // shares into the wider ring, then apply two's-complement sign extension.
    GroupElement is_below_lift_modulus = comparison(
        party_id, lifted_input, uint64_t(1) << input.bitsize, key.CarryKey);
    GroupElement one((uint64_t)(party_id - 2), output_bits);
    GroupElement carry = one - is_below_lift_modulus;
    GroupElement unsigned_extended =
        GroupElement(input.value, output_bits) -
        carry * (uint64_t(1) << input.bitsize);

    GroupElement is_nonnegative = comparison(
        party_id, input, uint64_t(1) << (input.bitsize - 1), key.SignKey);
    GroupElement sign = one - is_nonnegative;
    return unsigned_extended - sign * (uint64_t(1) << input.bitsize);
}

}  // namespace dfss
