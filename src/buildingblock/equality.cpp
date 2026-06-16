#include "buildingblock/equality.h"

#include "fss/fss_wrapper.h"

namespace dfss {

EqualityKey equalityOffline(int party_id, GroupElement point,
                            GroupElement payload, bool masked) {
    wrapper::DPFOptions options;
    options.masked = masked;
    options.correlated = true;
    return wrapper::keyGenDPF(party_id, point, payload, options);
}

EqualityKey equalityOffline(int party_id, int Bin,
                            const BooleanElement* point_bits,
                            GroupElement payload, bool masked) {
    wrapper::DPFOptions options;
    options.masked = masked;
    options.correlated = true;
    return wrapper::keyGenDPF(party_id, Bin, point_bits, payload, options);
}

EqualityKey equalityBitOffline(int party_id, GroupElement point, bool masked) {
    return wrapper::keyGenDPF(party_id, point, masked);
}

EqualityKey equalityBitOffline(int party_id, int Bin,
                               const BooleanElement* point_bits,
                               bool masked) {
    return wrapper::keyGenDPF(party_id, Bin, point_bits, masked);
}

EqualityBlockKey equalityBlockOffline(int party_id, GroupElement point,
                                      block payload, bool masked) {
    return wrapper::keyGenDPF(party_id, point, payload, masked);
}

EqualityBlockKey equalityBlockOffline(int party_id, int Bin,
                                      const BooleanElement* point_bits,
                                      block payload, bool masked) {
    return wrapper::keyGenDPF(party_id, Bin, point_bits, payload, masked);
}

GroupElement equality(int party_id, GroupElement input,
                      const EqualityKey& key, bool masked) {
    return wrapper::evalDPF(party_id, input, key, {masked, true, -1});
}

GroupElement equality(int party_id, const BooleanElement* input_bits,
                      const EqualityKey& key, bool masked) {
    return wrapper::evalDPF(party_id, input_bits, key, {masked, true, -1});
}

void equality(int party_id, GroupElement* output, GroupElement input,
              const EqualityKey& key, bool masked) {
    *output = equality(party_id, input, key, masked);
}

void equality(int party_id, GroupElement* output,
              const BooleanElement* input_bits, const EqualityKey& key,
              bool masked) {
    *output = equality(party_id, input_bits, key, masked);
}

BooleanElement equalityBit(int party_id, GroupElement input,
                           const EqualityKey& key, bool masked) {
    return wrapper::evalDPFBit(party_id, input, key, masked);
}

BooleanElement equalityBit(int party_id, const BooleanElement* input_bits,
                           const EqualityKey& key, bool masked) {
    return wrapper::evalDPFBit(party_id, input_bits, key, masked);
}

block equalityBlock(int party_id, GroupElement input,
                    const EqualityBlockKey& key, bool masked) {
    return wrapper::evalDPFBlock(party_id, input, key, masked);
}

block equalityBlock(int party_id, const BooleanElement* input_bits,
                    const EqualityBlockKey& key, bool masked) {
    return wrapper::evalDPFBlock(party_id, input_bits, key, masked);
}

void equalityBlock(int party_id, block* output, GroupElement input,
                   const EqualityBlockKey& key, bool masked) {
    *output = equalityBlock(party_id, input, key, masked);
}

void equalityBlock(int party_id, block* output,
                   const BooleanElement* input_bits,
                   const EqualityBlockKey& key, bool masked) {
    *output = equalityBlock(party_id, input_bits, key, masked);
}

}  // namespace dfss
