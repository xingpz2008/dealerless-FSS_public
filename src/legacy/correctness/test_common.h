#pragma once

#include "commons/types.h"
#include "mpc/api.h"
#include "mpc/comms.h"

#include <cmath>
#include <cstring>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

constexpr int kBin = 4;
constexpr int kBout = 8;
constexpr double kPi = 3.141592653589793238462643383279502884;

inline uint64_t reduce_to_bits(uint64_t value, int bitsize) {
    if (bitsize == 64) {
        return value;
    }
    return value & ((uint64_t(1) << bitsize) - 1);
}

inline GroupElement public_share(uint64_t value, int bitsize) {
    return GroupElement(value * static_cast<uint64_t>(party - SERVER), bitsize);
}

inline GroupElement split_share(uint64_t value, int bitsize,
                                uint64_t server_share) {
    if (party == SERVER) {
        return GroupElement(server_share, bitsize);
    }
    return GroupElement(value - server_share, bitsize);
}

inline int64_t signed_from_twos(uint64_t value, int bitsize) {
    const uint64_t sign_bit = uint64_t(1) << (bitsize - 1);
    const uint64_t modulus = uint64_t(1) << bitsize;
    if ((value & sign_bit) == 0) {
        return static_cast<int64_t>(value);
    }
    return static_cast<int64_t>(value) - static_cast<int64_t>(modulus);
}

inline uint64_t twos_from_signed(int64_t value, int bitsize) {
    const uint64_t modulus = uint64_t(1) << bitsize;
    return static_cast<uint64_t>(value) & (modulus - 1);
}

inline int64_t floor_div_pow2(int64_t value, int shift) {
    if (value >= 0) {
        return value >> shift;
    }
    const int64_t divisor = int64_t(1) << shift;
    return -(((-value) + divisor - 1) >> shift);
}

inline int64_t floor_div_pow2_i128(__int128 value, int shift) {
    const __int128 divisor = __int128(1) << shift;
    if (value >= 0) {
        return static_cast<int64_t>(value >> shift);
    }
    return static_cast<int64_t>(-(((-value) + divisor - 1) >> shift));
}

inline std::vector<u8> msb_bits_from_value(uint64_t value, int bits) {
    std::vector<u8> output(bits);
    for (int i = 0; i < bits; i++) {
        output[i] = static_cast<u8>((value >> (bits - 1 - i)) & 1);
    }
    return output;
}

inline std::vector<u8> split_bit_share(uint64_t value, int bits,
                                       uint64_t server_share) {
    const uint64_t local_share =
        party == SERVER ? server_share : (value ^ server_share);
    return msb_bits_from_value(local_share, bits);
}

class ResultLog {
public:
    void check_scalar(const std::string& name, GroupElement actual,
                      uint64_t expected) {
        reconstruct(&actual);
        const bool ok = actual.value == expected;
        print(name, ok, actual.value, expected);
        failures_ += ok ? 0 : 1;
    }

    void check_vector(const std::string& name, GroupElement* actual,
                      const std::vector<uint64_t>& expected, int bitsize) {
        reconstruct(static_cast<int32_t>(expected.size()), actual, bitsize);
        bool ok = true;
        for (size_t i = 0; i < expected.size(); ++i) {
            ok = ok && actual[i].value == expected[i];
        }
        if (party == SERVER) {
            std::cout << (ok ? "[PASS] " : "[FAIL] ") << name << " actual=[";
            for (size_t i = 0; i < expected.size(); ++i) {
                std::cout << actual[i].value
                          << (i + 1 == expected.size() ? "" : ", ");
            }
            std::cout << "] expected=[";
            for (size_t i = 0; i < expected.size(); ++i) {
                std::cout << expected[i]
                          << (i + 1 == expected.size() ? "" : ", ");
            }
            std::cout << "]\n";
        }
        failures_ += ok ? 0 : 1;
    }

    void check_bit(const std::string& name, u8 actual, u8 expected) {
        reconstruct(&actual);
        const bool ok = actual == expected;
        print(name, ok, actual, expected);
        failures_ += ok ? 0 : 1;
    }

    void check_block(const std::string& name, block actual, block expected) {
        reconstruct(&actual);
        const bool ok =
            std::memcmp(&actual, &expected, sizeof(block)) == 0;
        if (party == SERVER) {
            std::cout << (ok ? "[PASS] " : "[FAIL] ") << name << '\n';
        }
        failures_ += ok ? 0 : 1;
    }

    void check_public_scalar_near(const std::string& name, uint64_t actual,
                                  uint64_t expected, int bitsize,
                                  uint64_t tolerance) {
        const uint64_t modulus = uint64_t(1) << bitsize;
        uint64_t delta = (actual + modulus - expected) % modulus;
        if (delta >= (uint64_t(1) << (bitsize - 1))) {
            delta = modulus - delta;
        }
        const bool ok = delta <= tolerance;
        if (party == SERVER) {
            std::cout << (ok ? "[PASS] " : "[FAIL] ") << name
                      << " actual=" << actual << " expected=" << expected
                      << " tolerance=" << tolerance << '\n';
        }
        failures_ += ok ? 0 : 1;
    }

    int failures() const {
        return failures_;
    }

private:
    void print(const std::string& name, bool ok, uint64_t actual,
               uint64_t expected) const {
        if (party == SERVER) {
            std::cout << (ok ? "[PASS] " : "[FAIL] ") << name
                      << " actual=" << actual << " expected=" << expected
                      << '\n';
        }
    }

    int failures_ = 0;
};
