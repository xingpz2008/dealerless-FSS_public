#include "common.h"

// Shared metric collection, fixed-point helpers, and reconstruction helpers.

#include <algorithm>

uint64_t elapsed_us(Clock::time_point start, Clock::time_point end) {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(end - start)
            .count());
}

CounterSnapshot snapshot() {
    CounterSnapshot snap;
    snap.sent = peer->bytesSent;
    snap.received = peer->bytesReceived;
    snap.peer_rounds = peer->rounds;
    snap.reconstruct_rounds = numRounds;
    return snap;
}

PhaseMetric diff_metric(const CounterSnapshot& before,
                        const CounterSnapshot& after,
                        uint64_t time_us) {
    PhaseMetric metric;
    metric.time_us = time_us;
    metric.sent = after.sent - before.sent;
    metric.received = after.received - before.received;
    metric.peer_rounds = after.peer_rounds - before.peer_rounds;
    metric.reconstruct_rounds =
        after.reconstruct_rounds - before.reconstruct_rounds;
    return metric;
}

void add_metric(PhaseMetric& total, const PhaseMetric& cur) {
    total.time_us += cur.time_us;
    total.sent += cur.sent;
    total.received += cur.received;
    total.peer_rounds += cur.peer_rounds;
    total.reconstruct_rounds += cur.reconstruct_rounds;
}

uint64_t metric_comm(const PhaseMetric& metric) {
    return metric.sent + metric.received;
}

GroupElement split_share(uint64_t value, int bitsize, uint64_t server_share) {
    if (party == SERVER) {
        return GroupElement(server_share, bitsize);
    }
    return GroupElement(value - server_share, bitsize);
}

uint64_t mask_for_bits(int bits) {
    return bits == 64 ? ~uint64_t(0) : ((uint64_t(1) << bits) - 1);
}

int64_t signed_from_twos(uint64_t value, int bits) {
    if (bits == 64) {
        return static_cast<int64_t>(value);
    }
    const uint64_t sign = uint64_t(1) << (bits - 1);
    const uint64_t modulus = uint64_t(1) << bits;
    return (value & sign) ? static_cast<int64_t>(value) -
                                static_cast<int64_t>(modulus)
                          : static_cast<int64_t>(value);
}

uint64_t twos_from_signed(int64_t value, int bits) {
    if (bits == 64) {
        return static_cast<uint64_t>(value);
    }
    return static_cast<uint64_t>(value) & ((uint64_t(1) << bits) - 1);
}

double real_from_fixed(uint64_t value, int bits, int scale) {
    return static_cast<double>(signed_from_twos(value, bits)) /
           static_cast<double>(uint64_t(1) << scale);
}

int config_suffix_bits(const BenchConfig& config) {
    if (!config.et) {
        return -1;
    }
    if (config.suffixBits >= 0) {
        return config.suffixBits;
    }
    return defaultDPFETSuffixBits(config.Bin, config.Bout);
}

void reconstruct_for_check(GroupElement& value) {
    reconstruct(&value);
}

bool check_reconstructed_vector(const std::vector<GroupElement>& output,
                                const std::vector<uint64_t>& expected) {
    if (output.size() != expected.size()) {
        return false;
    }
    for (size_t i = 0; i < output.size(); i++) {
        if (output[i].value != expected[i]) {
            return false;
        }
    }
    return true;
}
