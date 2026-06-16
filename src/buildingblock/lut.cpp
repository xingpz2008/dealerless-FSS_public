#include "buildingblock/lut.h"

#include <cmath>
#include <stdexcept>
#include <vector>

#include "mpc/api.h"
#include "fss/fss_wrapper.h"

namespace dfss {

namespace {

void validatePublicLutShape(int idx_bitlen, int output_bitlen,
                            size_t table_entries) {
    if (idx_bitlen <= 0 || idx_bitlen >= 31 || output_bitlen <= 0 ||
        table_entries != (size_t(1) << idx_bitlen)) {
        throw std::invalid_argument("public LUT parameters do not match table");
    }
}

}  // namespace

PublicLutKeyPack publicLutOffline(int party_id, const PublicLUTData& table,
                                  PublicLutOptions options) {
    validatePublicLutShape(table.Bin, table.Bout, table.values.size());
    return publicLutOffline(party_id, table.Bin, table.Bout, options);
}

PublicLutKeyPack publicLutOffline(int party_id, int idx_bitlen,
                                  int output_bitlen,
                                  PublicLutOptions options) {
    validatePublicLutShape(idx_bitlen, output_bitlen,
                           size_t(1) << idx_bitlen);

    GroupElement one(party_id - SERVER, output_bitlen);

    wrapper::DPFOptions dpf_options;
    dpf_options.masked = false;
    dpf_options.correlated = true;
    dpf_options.earlyTerminationSuffixBits =
        options.early_termination
            ? (options.suffix_bits < 0
                   ? (options.lambda_bits == 128
                          ? -2
                          : defaultDPFETSuffixBits(idx_bitlen, output_bitlen,
                                                   options.lambda_bits))
                   : options.suffix_bits)
            : -1;

    PublicLutKeyPack output;
    output.idx_bitlen = idx_bitlen;
    output.output_bitlen = output_bitlen;
    output.table_size = 1 << idx_bitlen;
    output.earlyTermination = options.early_termination;
    output.DPFKey = wrapper::keyGenRandomDPF(
        party_id, idx_bitlen, one, &output.random_mask, dpf_options);
    output.suffixBits = output.DPFKey.suffixBits;
    return output;
}

GroupElement publicLut(int party_id, GroupElement input,
                       const PublicLUTData& table,
                       const PublicLutKeyPack& key,
                       GroupElement* shifted_full_domain_res) {
    validatePublicLutShape(table.Bin, table.Bout, table.values.size());
    if (table.Bin != key.idx_bitlen || table.Bout != key.output_bitlen ||
        static_cast<int>(table.values.size()) != key.table_size) {
        throw std::invalid_argument("public LUT table does not match key");
    }

    std::vector<GroupElement> full_domain_res(key.table_size);
    for (int i = 0; i < key.table_size; i++) {
        full_domain_res[i] = GroupElement(0, key.output_bitlen);
    }
    wrapper::evalAllDPF(party_id, full_domain_res.data(), key.DPFKey);

    GroupElement shift_amount = input - key.random_mask;
    reconstruct(&shift_amount);

    std::vector<GroupElement> local_shifted_full_domain_res;
    if (shifted_full_domain_res == nullptr) {
        local_shifted_full_domain_res.resize(key.table_size);
        shifted_full_domain_res = local_shifted_full_domain_res.data();
    }

    GroupElement output(0, key.output_bitlen);
    const int shift = shift_amount.value % key.table_size;
    for (int i = 0; i < key.table_size; i++) {
        const int real_vector_idx =
            (i + key.table_size - shift) % key.table_size;
        shifted_full_domain_res[i] = full_domain_res[real_vector_idx];
        output = output + shifted_full_domain_res[i] * table.values[i];
    }
    return output;
}

PrivateLutKey privateLutOffline(int party_id, int idx_bitlen, int lut_bitlen,
                                const GroupElement* private_list) {
    PrivateLutKey output;
    int entry = 1 << idx_bitlen;
    output.entryNum = entry;
    output.lut_bitlen = lut_bitlen;

    auto rng = secure_prng();
    GroupElement random_mask = random_ge_from_prng(rng, idx_bitlen);
    output.DPFKeyList = makeKeyArray<DPFKeyPack>(entry);
    for (int i = 0; i < entry; i++) {
        GroupElement shifted_mask =
            random_mask +
            GroupElement(i * static_cast<uint64_t>(party_id - 2), idx_bitlen);
        wrapper::DPFOptions options;
        options.masked = false;
        options.correlated = true;
        output.DPFKeyList[i] = wrapper::keyGenDPF(
            party_id, shifted_mask, private_list[i], options);
    }
    output.random_mask = random_mask;
    return output;
}

GroupElement privateLut(int party_id, GroupElement idx,
                        const PrivateLutKey& key) {
    GroupElement random_mask = key.random_mask;
    int entry_num = key.entryNum;
    const DPFKeyPack* dpf_key_list = key.DPFKeyList;
    GroupElement output(0, key.lut_bitlen);
    GroupElement real_input = idx + random_mask;
    reconstruct(&real_input);
    for (int i = 0; i < entry_num; i++) {
        output = output + wrapper::evalDPF(
                              party_id, real_input, dpf_key_list[i],
                              {false, true, -1});
    }
    return output;
}

}  // namespace dfss
