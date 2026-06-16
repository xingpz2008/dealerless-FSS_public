#include "math/luteval.h"

#include <stdexcept>

namespace dfss {

LutEvalKeyPack lutEvalOffline(int party_id, const PublicLUTData& table,
                              int suffix_bits, int lambda_bits) {
    if (table.Bin <= 0 || table.Bout <= 0 ||
        static_cast<int>(table.values.size()) != (1 << table.Bin)) {
        throw std::invalid_argument("lutEvalOffline received invalid table");
    }
    PublicLutOptions options;
    options.early_termination = true;
    options.suffix_bits = suffix_bits;
    options.lambda_bits = lambda_bits;
    return publicLutOffline(party_id, table, options);
}

GroupElement lutEval(int party_id, GroupElement input,
                     const PublicLUTData& table,
                     const LutEvalKeyPack& key) {
    return publicLut(party_id, input, table, key);
}

}  // namespace dfss
