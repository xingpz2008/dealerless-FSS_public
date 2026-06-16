#include "cases.h"

#include "mpc/secure_ops.h"

#include <string>
#include <vector>

void check_constrained_comparison(ResultLog& log) {
    struct AdjacentCountCase {
        uint64_t server;
        uint64_t client;
        u8 expected;
    };
    const AdjacentCountCase cases[] = {
        {0, 1, 1}, {1, 0, 0},
        {1, 2, 1}, {2, 1, 0},
        {2, 3, 1}, {3, 2, 0},
        {3, 4, 1}, {4, 3, 0},
    };

    for (const auto& test : cases) {
        const uint64_t local_value =
            party == SERVER ? test.server : test.client;
        const u8 high_bit = (local_value >> 1) & 1;
        const u8 low_bit = local_value & 1;
        const u8 output = cmp_2bit_opt(party, high_bit, low_bit, peer);
        log.check_bit("constrained comparison " + std::to_string(test.server) +
                          " < " + std::to_string(test.client),
                      output, test.expected);
    }
}

void check_boolean_wrappers(ResultLog& log) {
    struct BitCase {
        u8 real_a;
        u8 real_b;
        u8 server_a;
        u8 server_b;
    };
    const BitCase cases[] = {
        {0, 0, 0, 1}, {0, 1, 1, 0}, {1, 0, 0, 1}, {1, 1, 1, 1},
        {1, 1, 0, 0}, {0, 0, 1, 1}, {1, 0, 1, 0}, {0, 1, 0, 1},
    };
    constexpr int case_count = sizeof(cases) / sizeof(cases[0]);

    std::vector<u8> a(case_count);
    std::vector<u8> b(case_count);
    std::vector<u8> output(case_count);
    for (int i = 0; i < case_count; i++) {
        a[i] = party == SERVER ? cases[i].server_a
                               : static_cast<u8>(cases[i].real_a ^
                                                 cases[i].server_a);
        b[i] = party == SERVER ? cases[i].server_b
                               : static_cast<u8>(cases[i].real_b ^
                                                 cases[i].server_b);
    }

    and_wrapper(party, a.data(), b.data(), output.data(),
                static_cast<int>(output.size()), peer);
    for (size_t i = 0; i < output.size(); i++) {
        log.check_bit("batched AND " + std::to_string(i), output[i],
                      static_cast<u8>(cases[i].real_a & cases[i].real_b));
    }

    for (const auto& test : cases) {
        const u8 local_a = party == SERVER
                               ? test.server_a
                               : static_cast<u8>(test.real_a ^ test.server_a);
        const u8 local_b = party == SERVER
                               ? test.server_b
                               : static_cast<u8>(test.real_b ^ test.server_b);
        const u8 scalar = and_wrapper(party, local_a, local_b, peer);
        log.check_bit("scalar AND", scalar,
                      static_cast<u8>(test.real_a & test.real_b));
    }
}

void check_ohg(ResultLog& log) {
    for (int bits : {0, 1, 2, 3}) {
        const int length = 1 << bits;
        for (uint64_t eta = 0; eta < static_cast<uint64_t>(length); eta++) {
            for (uint64_t server_share : {uint64_t(0), uint64_t(length / 2)}) {
                const uint64_t mask = length - 1;
                const uint64_t local_share =
                    party == SERVER ? (server_share & mask)
                                    : ((eta ^ server_share) & mask);
                std::vector<u8> eta_bits =
                    msb_bits_from_value(local_share, bits);
                std::vector<u8> output(length, 0);
                booleanOneHotFromBits(
                    party, eta_bits.data(), bits, output.data(), peer);
                for (int i = 0; i < length; i++) {
                    log.check_bit("OHG bits " + std::to_string(bits) +
                                      " eta " + std::to_string(eta) +
                                      " index " + std::to_string(i),
                                  output[i], static_cast<u8>(i == eta));
                }
            }
        }
    }

    for (int bits : {4, 7}) {
        const int length = 1 << bits;
        const uint64_t etas[] = {0, 1, uint64_t(length / 2),
                                 uint64_t(length - 1)};
        for (uint64_t eta : etas) {
            for (uint64_t server_share : {uint64_t(0), uint64_t(length / 2)}) {
                const uint64_t mask = length - 1;
                const uint64_t local_share =
                    party == SERVER ? (server_share & mask)
                                    : ((eta ^ server_share) & mask);
                std::vector<u8> eta_bits =
                    msb_bits_from_value(local_share, bits);
                std::vector<u8> output(length, 0);
                booleanOneHotFromBits(
                    party, eta_bits.data(), bits, output.data(), peer);
                for (int i = 0; i < length; i++) {
                    log.check_bit("OHG sampled bits " + std::to_string(bits) +
                                      " eta " + std::to_string(eta) +
                                      " index " + std::to_string(i),
                                  output[i], static_cast<u8>(i == eta));
                }
            }
        }
    }
}
