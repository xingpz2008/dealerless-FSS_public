#include "buildingblock/truncation.h"

#include <stdexcept>

#include "buildingblock/comparison.h"
#include "buildingblock/mic.h"

namespace dfss {

TRKeyPack truncateOffline(int party_id, int l, int s) {
    TRKeyPack output;
    output.Bin = s;
    output.Bout = l - s;
    output.s = s;
    GroupElement two_power_s((uint64_t)(party_id - 2) * (1ULL << s), s + 1);
    GroupElement one((uint64_t)(party_id - 2), output.Bout);
    output.ComparisonKey =
        comparisonOffline(party_id, output.Bin + 1, output.Bout, two_power_s,
                          one);
    return output;
}

GroupElement truncate(int party_id, GroupElement input, int s,
                      const TRKeyPack& key) {
    if (s != key.s) {
        throw std::invalid_argument("truncate bit length mismatch");
    }
    if (s == 0) {
        return input;
    }
    auto segmented_ge = segment(input, s);
    segmented_ge.second.bitsize = s + 1;
    GroupElement comparison_res =
        comparison(party_id, segmented_ge.second, key.ComparisonKey);
    GroupElement one((uint64_t)(party_id - 2), input.bitsize - s);
    GroupElement carry = one - comparison_res;
    return segmented_ge.first + carry;
}

SignedTruncateKeyPack signedTruncateOffline(int party_id, int l, int s) {
    if (l <= 0 || s <= 0 || s >= l) {
        throw std::invalid_argument(
            "signedTruncateOffline requires 0 < s < l");
    }
    SignedTruncateKeyPack key;
    key.Bin = s;
    key.Bout = l - s;
    key.s = s;
    GroupElement one((uint64_t)(party_id - 2), key.Bout);
    key.CarryKey = comparisonOffline(party_id, s + 1, key.Bout, one);
    return key;
}

GroupElement signedTruncate(int party_id, GroupElement input, int s,
                               const SignedTruncateKeyPack& key) {
    if (s != key.s || input.bitsize != key.Bin + key.Bout) {
        throw std::invalid_argument("signedTruncate bit length mismatch");
    }
    auto segmented_ge = segment(input, s);
    segmented_ge.second.bitsize = s + 1;
    // Signed floor truncation keeps the high bits and adds the carry from the
    // low s-bit additive shares, matching floor(x / 2^s) over two's complement.
    GroupElement low_no_carry = comparison(
        party_id, segmented_ge.second, uint64_t(1) << s, key.CarryKey);
    GroupElement one((uint64_t)(party_id - 2), key.Bout);
    GroupElement carry = one - low_no_carry;
    return segmented_ge.first + carry;
}

}  // namespace dfss
