#include "buildingblock/mic.h"

#include <algorithm>
#include <stdexcept>
#include <unordered_map>
#include <vector>

#include "mpc/api.h"
#include "fss/fss_wrapper.h"
#include "fss/internal/ggm.h"
#include "fss/internal/payload_conversion.h"

namespace dfss {

namespace {

uint64_t prefixStateKey(int level, uint64_t prefix) {
    return (static_cast<uint64_t>(level) << 32) | prefix;
}

BooleanElement publicBooleanShare(int party_id, BooleanElement value) {
    return party_id == SERVER ? static_cast<BooleanElement>(value & 1) : 0;
}

BooleanElement blockLsb(const osuCrypto::block& input) {
    return _mm_cvtsi128_si64x(input) & 1;
}

GroupElement evalPrefixPayload(int party_id, const DPFKeyPack& key,
                               const GroupElement& root_payload_cw,
                               int prefix_level, osuCrypto::block node,
                               BooleanElement control_bit) {
    const osuCrypto::block label =
        internal::setBlockLsb(node, static_cast<osuCrypto::u8>(control_bit));
    const uint64_t converted_value =
        internal::convertPayload_iDPF(key.Bout, label);
    GroupElement converted(converted_value, key.Bout);
    const GroupElement& cw =
        prefix_level == 0 ? root_payload_cw : key.g[prefix_level - 1];
    GroupElement local_output =
        converted + cw * static_cast<uint64_t>(control_bit);
    return party_id == SERVER ? local_output : -local_output;
}

struct PrefixEvalState {
    osuCrypto::block node = osuCrypto::ZeroBlock;
    BooleanElement control_bit = 0;
    GroupElement prefix_sum;
    int sign_count = 0;
    BooleanElement previous_direction = 0;
};

struct PrefixEvalBitState {
    osuCrypto::block node = osuCrypto::ZeroBlock;
    BooleanElement control_bit = 0;
    BooleanElement prefix_xor = 0;
    BooleanElement previous_direction = 0;
};

std::unordered_map<uint64_t, GroupElement> evalPrefixBoundaries(
    int party_id, const DPFKeyPack& key, const GroupElement& root_payload_cw,
    GroupElement payload_share, const std::vector<uint64_t>& endpoints) {
    if (key.Bin >= 32) {
        throw std::invalid_argument("MIC prefix evaluation supports Bin < 32");
    }
    const int n = key.Bin;
    const uint64_t domain = uint64_t(1) << n;
    std::vector<uint64_t> sorted = endpoints;
    std::sort(sorted.begin(), sorted.end());
    sorted.erase(std::unique(sorted.begin(), sorted.end()), sorted.end());

    std::unordered_map<uint64_t, PrefixEvalState> memo;
    PrefixEvalState root;
    root.node = key.k[0];
    root.control_bit = static_cast<BooleanElement>(party_id - SERVER);
    root.prefix_sum = GroupElement(0, key.Bout);
    memo[prefixStateKey(0, 0)] = root;

    std::unordered_map<uint64_t, GroupElement> result;
    osuCrypto::AES aes;
    const osuCrypto::block pt[2] = {osuCrypto::ZeroBlock,
                                    osuCrypto::OneBlock};
    osuCrypto::block ct[2];

    // Endpoints are prefix boundaries. For endpoint t, traverse to t-1 and
    // aggregate the iDPF prefix outputs encountered by the binary path.
    for (uint64_t endpoint : sorted) {
        if (endpoint == 0) {
            result[endpoint] = GroupElement(0, key.Bout);
            continue;
        }
        if (endpoint == domain) {
            result[endpoint] = payload_share;
            continue;
        }
        if (endpoint > domain) {
            throw std::invalid_argument("MIC endpoint outside domain");
        }

        const uint64_t phi = endpoint - 1;
        int cached_level = 0;
        uint64_t cached_prefix = 0;
        for (int level = n; level >= 0; level--) {
            const uint64_t prefix =
                level == 0 ? 0 : (phi >> (n - level));
            if (memo.find(prefixStateKey(level, prefix)) != memo.end()) {
                cached_level = level;
                cached_prefix = prefix;
                break;
            }
        }

        PrefixEvalState state = memo[prefixStateKey(cached_level,
                                                    cached_prefix)];
        for (int level = cached_level; level < n; level++) {
            const BooleanElement direction =
                static_cast<BooleanElement>((phi >> (n - 1 - level)) & 1);
            if (direction != state.previous_direction) {
                GroupElement prefix_output = evalPrefixPayload(
                    party_id, key, root_payload_cw, level, state.node,
                    state.control_bit);
                state.prefix_sum =
                    (state.sign_count % 2 == 0)
                        ? state.prefix_sum + prefix_output
                        : state.prefix_sum - prefix_output;
                state.sign_count++;
            }

            aes.setKey(state.node);
            aes.ecbEncTwoBlocks(pt, ct);
            const osuCrypto::block level_cw = key.k[level + 1];
            const BooleanElement level_tau = key.v[2 * level + direction];
            if (state.control_bit == static_cast<BooleanElement>(1)) {
                state.node = ct[direction] ^ level_cw;
                state.control_bit = blockLsb(ct[direction]) ^ level_tau;
            } else {
                state.node = ct[direction];
                state.control_bit = blockLsb(ct[direction]);
            }
            state.previous_direction = direction;

            const uint64_t next_prefix =
                level + 1 == 0 ? 0 : (phi >> (n - (level + 1)));
            memo[prefixStateKey(level + 1, next_prefix)] = state;
        }

        if ((phi & 1) == 0) {
            GroupElement leaf_output = evalPrefixPayload(
                party_id, key, root_payload_cw, n, state.node,
                state.control_bit);
            state.prefix_sum =
                (state.sign_count % 2 == 0)
                    ? state.prefix_sum + leaf_output
                    : state.prefix_sum - leaf_output;
        }
        result[endpoint] = state.prefix_sum;
    }
    return result;
}

std::unordered_map<uint64_t, BooleanElement> evalPrefixBoundariesBoolean(
    int party_id, const DPFKeyPack& key,
    const std::vector<uint64_t>& endpoints) {
    if (key.Bin >= 32) {
        throw std::invalid_argument(
            "MIC Boolean prefix evaluation supports Bin < 32");
    }
    const int n = key.Bin;
    const uint64_t domain = uint64_t(1) << n;
    std::vector<uint64_t> sorted = endpoints;
    std::sort(sorted.begin(), sorted.end());
    sorted.erase(std::unique(sorted.begin(), sorted.end()), sorted.end());

    std::unordered_map<uint64_t, PrefixEvalBitState> memo;
    PrefixEvalBitState root;
    root.node = key.k[0];
    root.control_bit = static_cast<BooleanElement>(party_id - SERVER);
    root.prefix_xor = 0;
    memo[prefixStateKey(0, 0)] = root;

    std::unordered_map<uint64_t, BooleanElement> result;
    osuCrypto::AES aes;
    const osuCrypto::block pt[2] = {osuCrypto::ZeroBlock,
                                    osuCrypto::OneBlock};
    osuCrypto::block ct[2];

    for (uint64_t endpoint : sorted) {
        if (endpoint == 0) {
            result[endpoint] = 0;
            continue;
        }
        if (endpoint == domain) {
            result[endpoint] = publicBooleanShare(party_id, 1);
            continue;
        }
        if (endpoint > domain) {
            throw std::invalid_argument("MIC Boolean endpoint outside domain");
        }

        const uint64_t phi = endpoint - 1;
        int cached_level = 0;
        uint64_t cached_prefix = 0;
        for (int level = n; level >= 0; level--) {
            const uint64_t prefix =
                level == 0 ? 0 : (phi >> (n - level));
            if (memo.find(prefixStateKey(level, prefix)) != memo.end()) {
                cached_level = level;
                cached_prefix = prefix;
                break;
            }
        }

        PrefixEvalBitState state =
            memo[prefixStateKey(cached_level, cached_prefix)];
        for (int level = cached_level; level < n; level++) {
            const BooleanElement direction =
                static_cast<BooleanElement>((phi >> (n - 1 - level)) & 1);
            if (direction != state.previous_direction) {
                state.prefix_xor ^= state.control_bit;
            }

            aes.setKey(state.node);
            aes.ecbEncTwoBlocks(pt, ct);
            const osuCrypto::block level_cw = key.k[level + 1];
            const BooleanElement level_tau = key.v[2 * level + direction];
            if (state.control_bit == static_cast<BooleanElement>(1)) {
                state.node = ct[direction] ^ level_cw;
                state.control_bit = blockLsb(ct[direction]) ^ level_tau;
            } else {
                state.node = ct[direction];
                state.control_bit = blockLsb(ct[direction]);
            }
            state.previous_direction = direction;

            const uint64_t next_prefix =
                level + 1 == 0 ? 0 : (phi >> (n - (level + 1)));
            memo[prefixStateKey(level + 1, next_prefix)] = state;
        }

        if ((phi & 1) == 0) {
            state.prefix_xor ^= state.control_bit;
        }
        result[endpoint] = static_cast<BooleanElement>(state.prefix_xor & 1);
    }
    return result;
}

void micWithDeltaValue(int party_id, uint64_t delta_value,
                       const PublicInterval* intervals, int interval_count,
                       GroupElement* output, const MICKeyPack& key) {
    if (key.Bin <= 0 || key.Bin >= 32) {
        throw std::invalid_argument("mic requires 0 < Bin < 32");
    }
    const uint64_t domain = uint64_t(1) << key.Bin;
    delta_value %= domain;

    std::vector<uint64_t> shifted_left(interval_count, 0);
    std::vector<uint64_t> shifted_right(interval_count, 0);
    std::vector<uint64_t> lengths(interval_count, 0);
    std::vector<uint64_t> endpoints;

    for (int i = 0; i < interval_count; i++) {
        if (intervals[i].left > intervals[i].right ||
            intervals[i].right > domain) {
            throw std::invalid_argument(
                "mic interval must satisfy 0 <= left <= right <= 2^Bin");
        }
        const uint64_t length = intervals[i].right - intervals[i].left;
        lengths[i] = length;
        if (length == 0 || length == domain) {
            continue;
        }
        shifted_left[i] = (intervals[i].left + domain - delta_value) % domain;
        shifted_right[i] =
            (intervals[i].right % domain + domain - delta_value) % domain;
        endpoints.push_back(shifted_left[i]);
        endpoints.push_back(shifted_right[i]);
    }

    std::unordered_map<uint64_t, GroupElement> prefix_values =
        evalPrefixBoundaries(party_id, key.iDPFKey, key.root_payload_cw,
                             key.payload_share, endpoints);

    for (int i = 0; i < interval_count; i++) {
        if (lengths[i] == 0) {
            output[i] = GroupElement(0, key.Bout);
        } else if (lengths[i] == domain) {
            output[i] = key.payload_share;
        } else if (shifted_left[i] < shifted_right[i]) {
            output[i] =
                prefix_values[shifted_right[i]] - prefix_values[shifted_left[i]];
        } else {
            output[i] = key.payload_share - prefix_values[shifted_left[i]] +
                        prefix_values[shifted_right[i]];
        }
    }
}

void micBooleanWithDeltaValue(int party_id, uint64_t delta_value,
                              const PublicInterval* intervals,
                              int interval_count, BooleanElement* output,
                              const MICBooleanKeyPack& key) {
    if (key.Bin <= 0 || key.Bin >= 32) {
        throw std::invalid_argument("mic_boolean requires 0 < Bin < 32");
    }
    const uint64_t domain = uint64_t(1) << key.Bin;
    delta_value %= domain;

    std::vector<uint64_t> shifted_left(interval_count, 0);
    std::vector<uint64_t> shifted_right(interval_count, 0);
    std::vector<uint64_t> lengths(interval_count, 0);
    std::vector<uint64_t> endpoints;

    for (int i = 0; i < interval_count; i++) {
        if (intervals[i].left > intervals[i].right ||
            intervals[i].right > domain) {
            throw std::invalid_argument(
                "mic_boolean interval must satisfy 0 <= left <= right <= 2^Bin");
        }
        const uint64_t length = intervals[i].right - intervals[i].left;
        lengths[i] = length;
        if (length == 0 || length == domain) {
            continue;
        }
        shifted_left[i] = (intervals[i].left + domain - delta_value) % domain;
        shifted_right[i] =
            (intervals[i].right % domain + domain - delta_value) % domain;
        endpoints.push_back(shifted_left[i]);
        endpoints.push_back(shifted_right[i]);
    }

    std::unordered_map<uint64_t, BooleanElement> prefix_values =
        evalPrefixBoundariesBoolean(party_id, key.iDPFKey, endpoints);

    for (int i = 0; i < interval_count; i++) {
        if (lengths[i] == 0) {
            output[i] = 0;
        } else if (lengths[i] == domain) {
            output[i] = publicBooleanShare(party_id, 1);
        } else if (shifted_left[i] < shifted_right[i]) {
            output[i] = static_cast<BooleanElement>(
                prefix_values[shifted_right[i]] ^ prefix_values[shifted_left[i]]);
        } else {
            output[i] = static_cast<BooleanElement>(
                publicBooleanShare(party_id, 1) ^
                prefix_values[shifted_left[i]] ^
                prefix_values[shifted_right[i]]);
        }
    }
}

}  // namespace

MICKeyPack micOffline(int party_id, int Bin, int Bout, GroupElement payload) {
    if (Bin <= 0 || Bin >= 32) {
        throw std::invalid_argument("micOffline requires 0 < Bin < 32");
    }
    if (payload.bitsize != Bout) {
        throw std::invalid_argument("micOffline payload bitsize must equal Bout");
    }

    std::vector<GroupElement> level_payloads(Bin);
    for (int i = 0; i < Bin; i++) {
        level_payloads[i] = payload;
    }
    GroupElement rho_share;
    DPFKeyPack idpf_key =
        wrapper::keyGenRandomiDPF(party_id, Bin, level_payloads.data(),
                                  &rho_share);

    const osuCrypto::block root_label = internal::setBlockLsb(
        idpf_key.k[0], static_cast<osuCrypto::u8>(party_id - SERVER));
    const uint64_t root_converted_value =
        internal::convertPayload_iDPF(Bout, root_label);
    GroupElement root_converted(root_converted_value, Bout);
    GroupElement root_cw_share =
        -payload + (party_id == SERVER ? root_converted : -root_converted);
    reconstruct(&root_cw_share);

    MICKeyPack key;
    key.Bin = Bin;
    key.Bout = Bout;
    key.rho_share = rho_share;
    key.payload_share = payload;
    key.root_payload_cw = root_cw_share;
    key.iDPFKey = idpf_key;
    return key;
}

void mic(int party_id, GroupElement input, const PublicInterval* intervals,
         int interval_count, GroupElement* output, const MICKeyPack& key) {
    if (input.bitsize != key.Bin) {
        throw std::invalid_argument("mic input bitsize must match key.Bin");
    }

    GroupElement delta = input - key.rho_share;
    reconstruct(1, &delta, key.Bin);
    micWithDeltaValue(party_id, delta.value, intervals, interval_count, output,
                      key);
}

MICBooleanKeyPack micBooleanOffline(int party_id, int Bin) {
    if (Bin <= 0 || Bin >= 32) {
        throw std::invalid_argument("micBooleanOffline requires 0 < Bin < 32");
    }

    GroupElement rho_share;
    DPFKeyPack idpf_key =
        wrapper::keyGenRandomiDPF(party_id, Bin, &rho_share);

    MICBooleanKeyPack key;
    key.Bin = Bin;
    key.rho_share = rho_share;
    key.iDPFKey = idpf_key;
    return key;
}

void micBoolean(int party_id, GroupElement input,
                const PublicInterval* intervals, int interval_count,
                BooleanElement* output, const MICBooleanKeyPack& key) {
    if (input.bitsize != key.Bin) {
        throw std::invalid_argument(
            "micBoolean input bitsize must match key.Bin");
    }

    GroupElement delta = input - key.rho_share;
    reconstruct(1, &delta, key.Bin);
    micBooleanWithDeltaValue(party_id, delta.value, intervals, interval_count,
                             output, key);
}

}  // namespace dfss
