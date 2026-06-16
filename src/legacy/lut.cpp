#include "legacy/lut.h"

#include <cmath>
#include <memory>
#include <vector>

#include "legacy/dpf.h"
#include "mpc/api.h"

namespace dfss::legacy {

LegacyPublicLutKeyPack publicLutOffline(int party_id, int idx_bitlen,
                                        int lut_bitlen) {
    auto rng = secure_prng();
    GroupElement lut_index_shared = random_ge_from_prng(rng, idx_bitlen);
    GroupElement one(party_id - SERVER, lut_bitlen);
    LegacyPublicLutKeyPack output =
        keyGenDPF(party_id, idx_bitlen, lut_bitlen, lut_index_shared, one,
                  false);
    output.random_mask = std::make_shared<GroupElement>(lut_index_shared);
    return output;
}

GroupElement publicLut(int party_id, GroupElement input,
                       const GroupElement* table,
                       GroupElement* shifted_full_domain_res, int table_size,
                       int output_bitlen,
                       const LegacyPublicLutKeyPack& key) {
    GroupElement output(0, output_bitlen);

    std::vector<GroupElement> full_domain_res(table_size);
    for (int i = 0; i < table_size; i++) {
        full_domain_res[i].bitsize = table[i].bitsize;
    }
    int full_domain_length = static_cast<int>(log2ceil(table_size));
    evalAll(party_id, full_domain_res.data(), key, full_domain_length);

    GroupElement key_index = *(key.random_mask);
    GroupElement shift_amount = input - key_index;
    reconstruct(&shift_amount);

    std::vector<GroupElement> local_shifted_full_domain_res;
    if (shifted_full_domain_res == nullptr) {
        local_shifted_full_domain_res.resize(table_size);
        shifted_full_domain_res = local_shifted_full_domain_res.data();
    }
    const int shift = shift_amount.value % table_size;
    for (int i = 0; i < table_size; i++) {
        int real_vector_idx = (i + table_size - shift) % table_size;
        shifted_full_domain_res[i] = full_domain_res[real_vector_idx];
        output = output + shifted_full_domain_res[i] * table[i];
    }
    return output;
}

}  // namespace dfss::legacy
