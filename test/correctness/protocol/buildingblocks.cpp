#include "cases.h"

// dFSS building-block correctness cases.

#include <string>
#include <vector>

void check_equality(ResultLog& log) {
    constexpr uint64_t payload = 29;
    struct EqualityCase {
        uint64_t point;
        uint64_t query;
    };
    const EqualityCase cases[] = {
        {0, 0},
        {0, 1},
        {6, 6},
        {6, 7},
        {uint64_t((1 << kBin) - 1), uint64_t((1 << kBin) - 1)},
        {uint64_t((1 << kBin) - 1), 0},
    };

    for (const auto& test : cases) {
        EqualityKey key = dfss::equalityOffline(
            party, split_share(test.point, kBin, test.point + 11),
            split_share(payload, kBout, 191 + test.point));
        GroupElement output = dfss::equality(
            party, split_share(test.query, kBin, test.query + 17), key);
        const uint64_t expected = test.point == test.query ? payload : 0;
        log.check_scalar("equality arithmetic point " +
                             std::to_string(test.point) + " query " +
                             std::to_string(test.query),
                         output, expected);
        GroupElement void_output(0, kBout);
        dfss::equality(
            party, &void_output,
            split_share(test.query, kBin, test.query + 17), key);
        log.check_scalar("equality arithmetic void point " +
                             std::to_string(test.point) + " query " +
                             std::to_string(test.query),
                         void_output, expected);
        freeEqualityKey(key);

        EqualityKey bit_key = dfss::equalityBitOffline(
            party, split_share(test.point, kBin, test.point + 23));
        BooleanElement bit_output = dfss::equalityBit(
            party, split_share(test.query, kBin, test.query + 29), bit_key);
        log.check_bit("equality bit arithmetic point " +
                          std::to_string(test.point) + " query " +
                          std::to_string(test.query),
                      bit_output,
                      static_cast<u8>(test.point == test.query));
        freeEqualityKey(bit_key);

        const block block_payload = osuCrypto::toBlock(0, payload);
        const block block_payload_server_share =
            osuCrypto::toBlock(0, 0x9a7b5c3d1e0f2468ULL);
        const block block_payload_share =
            party == SERVER ? block_payload_server_share
                            : (block_payload ^ block_payload_server_share);
        EqualityBlockKey block_key = dfss::equalityBlockOffline(
            party, split_share(test.point, kBin, test.point + 31),
            block_payload_share);
        block block_output = dfss::equalityBlock(
            party, split_share(test.query, kBin, test.query + 37),
            block_key);
        log.check_block("equality block arithmetic point " +
                            std::to_string(test.point) + " query " +
                            std::to_string(test.query),
                        block_output,
                        test.point == test.query ? block_payload
                                                  : osuCrypto::ZeroBlock);
        block void_block_output = osuCrypto::ZeroBlock;
        dfss::equalityBlock(
            party, &void_block_output,
            split_share(test.query, kBin, test.query + 37),
            block_key);
        log.check_block("equality block arithmetic void point " +
                            std::to_string(test.point) + " query " +
                            std::to_string(test.query),
                        void_block_output,
                        test.point == test.query ? block_payload
                                                  : osuCrypto::ZeroBlock);
        freeEqualityBlockKey(block_key);

        std::vector<u8> point_bits =
            split_bit_share(test.point, kBin, test.point + 41);
        std::vector<u8> query_bits =
            split_bit_share(test.query, kBin, test.query + 43);

        EqualityKey bit_input_key = dfss::equalityOffline(
            party, kBin, point_bits.data(),
            split_share(payload, kBout, 197 + test.point));
        GroupElement bit_input_output =
            dfss::equality(party, query_bits.data(), bit_input_key);
        log.check_scalar("equality arithmetic Boolean input point " +
                             std::to_string(test.point) + " query " +
                             std::to_string(test.query),
                         bit_input_output, expected);
        freeEqualityKey(bit_input_key);

        EqualityKey bit_input_void_key = dfss::equalityOffline(
            party, kBin, point_bits.data(),
            split_share(payload, kBout, 197 + test.point));
        GroupElement bit_input_void_output(0, kBout);
        dfss::equality(party, &bit_input_void_output, query_bits.data(),
                       bit_input_void_key);
        log.check_scalar("equality arithmetic Boolean input void point " +
                             std::to_string(test.point) + " query " +
                             std::to_string(test.query),
                         bit_input_void_output, expected);
        freeEqualityKey(bit_input_void_key);

        EqualityKey bit_input_bit_key =
            dfss::equalityBitOffline(party, kBin, point_bits.data());
        BooleanElement bit_input_bit_output =
            dfss::equalityBit(party, query_bits.data(), bit_input_bit_key);
        log.check_bit("equality bit Boolean input point " +
                          std::to_string(test.point) + " query " +
                          std::to_string(test.query),
                      bit_input_bit_output,
                      static_cast<u8>(test.point == test.query));
        freeEqualityKey(bit_input_bit_key);

        EqualityBlockKey bit_input_block_key = dfss::equalityBlockOffline(
            party, kBin, point_bits.data(), block_payload_share);
        block bit_input_block_output =
            dfss::equalityBlock(party, query_bits.data(),
                                bit_input_block_key);
        log.check_block("equality block Boolean input point " +
                            std::to_string(test.point) + " query " +
                            std::to_string(test.query),
                        bit_input_block_output,
                        test.point == test.query ? block_payload
                                                  : osuCrypto::ZeroBlock);
        freeEqualityBlockKey(bit_input_block_key);

        EqualityBlockKey bit_input_block_void_key =
            dfss::equalityBlockOffline(
                party, kBin, point_bits.data(), block_payload_share);
        block bit_input_block_void_output = osuCrypto::ZeroBlock;
        dfss::equalityBlock(party, &bit_input_block_void_output,
                            query_bits.data(), bit_input_block_void_key);
        log.check_block("equality block Boolean input void point " +
                            std::to_string(test.point) + " query " +
                            std::to_string(test.query),
                        bit_input_block_void_output,
                        test.point == test.query ? block_payload
                                                  : osuCrypto::ZeroBlock);
        freeEqualityBlockKey(bit_input_block_void_key);
    }
}

void check_modular(ResultLog& log) {
    constexpr uint64_t modulus = 8;
    for (uint64_t input : {uint64_t(0), uint64_t(7), uint64_t(8),
                           uint64_t(15)}) {
        ModularKeyPack key =
            dfss::modularOffline(party, GroupElement(modulus, kBin), kBout);
        GroupElement output = dfss::modular(
            party, split_share(input, kBin, input + 6), modulus, key);
        log.check_scalar("power-of-two dfss::modular reduction " +
                             std::to_string(input) + " mod " +
                             std::to_string(modulus),
                         output, input % modulus);
    }
}

void check_truncate_and_reduce(ResultLog& log) {
    constexpr int input_bits = 5;
    constexpr int truncated_bits = 2;
    for (uint64_t input : {uint64_t(0), uint64_t(1), uint64_t(13),
                           uint64_t((1 << input_bits) - 1)}) {
        TRKeyPack key =
            dfss::truncateOffline(party, input_bits, truncated_bits);
        GroupElement output = dfss::truncate(
            party, split_share(input, input_bits, input + 19), truncated_bits,
            key);
        log.check_scalar("truncate and reduce " + std::to_string(input),
                         output, input >> truncated_bits);
    }

    TRKeyPack top_bit_key = dfss::truncateOffline(party, kBin, kBin - 1);
    GroupElement top_bit = dfss::truncate(
        party, split_share(12, kBin, 7), kBin - 1, top_bit_key);
    log.check_scalar("truncate and reduce top bit", top_bit, 1);

    TRKeyPack carry_key =
        dfss::truncateOffline(party, input_bits, truncated_bits);
    GroupElement carry_input(party == SERVER ? 3 : 6, input_bits);
    GroupElement carry_output =
        dfss::truncate(party, carry_input, truncated_bits, carry_key);
    log.check_scalar("truncate and reduce low-share carry", carry_output, 2);
}

void check_digdec(ResultLog& log) {
    constexpr int digit_bits = 2;
    struct DigDecCase {
        uint64_t input;
        std::vector<uint64_t> expected;
    };
    const DigDecCase cases[] = {
        {0, {0, 0}},
        {1, {1, 0}},
        {13, {1, 3}},
        {15, {3, 3}},
    };
    for (const auto& test : cases) {
        DigDecKeyPack key = dfss::digdecOffline(party, kBin, digit_bits);
        GroupElement output[] = {
            GroupElement(0, digit_bits),
            GroupElement(0, digit_bits),
        };
        dfss::digdec(
            party, split_share(test.input, kBin, test.input + 11), output,
            digit_bits, key);
        log.check_vector("digit decomposition low to high " +
                             std::to_string(test.input),
                         output, test.expected, digit_bits);
    }
}

void check_public_lut(ResultLog& log) {
    const PublicLUTData table = generatePublicLUT(
        kBin, kBout, [](uint64_t i) { return 3 * i + 1; });
    std::vector<GroupElement> shifted(table.values.size());

    for (uint64_t input : {uint64_t(0), uint64_t(3),
                           uint64_t(table.values.size() - 1)}) {
        PublicLutKeyPack key = dfss::publicLutOffline(party, table);
        GroupElement output =
            dfss::publicLut(party, split_share(input, kBin, input + 9),
                            table, key, shifted.data());
        log.check_scalar("public LUT lookup " + std::to_string(input), output,
                         3 * input + 1);
        freePublicLutKeyPack(key);
    }
}

void check_private_lut(ResultLog& log) {
    constexpr int entries = 1 << kBin;
    GroupElement table[entries];
    for (int i = 0; i < entries; ++i) {
        table[i] = split_share(2 * i + 5, kBout, 37 + i);
    }

    for (uint64_t input : {uint64_t(0), uint64_t(7), uint64_t(entries - 1)}) {
        PrivateLutKey key = dfss::privateLutOffline(party, kBin, kBout, table);
        GroupElement output =
            dfss::privateLut(party, split_share(input, kBin, input + 13), key);
        log.check_scalar("private LUT lookup " + std::to_string(input), output,
                         2 * input + 5);
        freePrivateLutKey(key);
    }

    GroupElement two_entry_table[] = {
        split_share(5, kBin, 12),
        split_share(9, kBin, 14),
    };
    PrivateLutKey public_index_key =
        dfss::privateLutOffline(party, 1, kBin, two_entry_table);
    GroupElement public_index_output =
        dfss::privateLut(party, public_share(1, 1), public_index_key);
    log.check_scalar("private LUT one-bit public index", public_index_output, 9);
    freePrivateLutKey(public_index_key);

    PrivateLutKey split_index_key =
        dfss::privateLutOffline(party, 1, kBin, two_entry_table);
    GroupElement split_index(party == SERVER ? 1 : 0, 1);
    GroupElement split_index_output =
        dfss::privateLut(party, split_index, split_index_key);
    log.check_scalar("private LUT one-bit split index", split_index_output, 9);
    freePrivateLutKey(split_index_key);

    TRKeyPack truncated_index_key =
        dfss::truncateOffline(party, kBin, kBin - 1);
    GroupElement truncated_index = dfss::truncate(
        party, split_share(12, kBin, 7), kBin - 1, truncated_index_key);
    PrivateLutKey truncated_lut_key =
        dfss::privateLutOffline(party, 1, kBin, two_entry_table);
    GroupElement truncated_index_output =
        dfss::privateLut(party, truncated_index, truncated_lut_key);
    log.check_scalar("private LUT truncated one-bit index",
                     truncated_index_output, 9);
    freePrivateLutKey(truncated_lut_key);
}
