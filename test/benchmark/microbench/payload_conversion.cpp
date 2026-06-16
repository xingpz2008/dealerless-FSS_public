#include "protocol/benchmarks.h"
#include "common.h"
#include "report.h"

// Payload-conversion comparison microbenchmark.

#include "mpc/secure_ops.h"

#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

void bench_multiplexer2_vector(int party_id,
                               const std::vector<uint8_t>& control_bit,
                               const std::vector<GroupElement>& dataA,
                               const std::vector<GroupElement>& dataB,
                               std::vector<GroupElement>& output,
                               Peer* player) {
    const int size = static_cast<int>(control_bit.size());
    if (static_cast<int>(dataA.size()) < size ||
        static_cast<int>(dataB.size()) < size ||
        static_cast<int>(output.size()) < size) {
        throw std::invalid_argument("payload conversion MUX vector size mismatch");
    }
    std::vector<GroupElement> a_minus_b(size);
    std::vector<uint8_t> real_sel(size);
    for (int i = 0; i < size; i++) {
        a_minus_b[i] = dataA[i] - dataB[i];
        real_sel[i] = control_bit[i] ^ static_cast<uint8_t>(party_id - SERVER);
    }
    multiplexer(party_id, real_sel, a_minus_b.data(), output.data(), size,
                player);
    for (int i = 0; i < size; i++) {
        output[i] = output[i] + dataB[i];
    }
}

void bench_parallel_multiplexer_vector(int party_id,
                                       const std::vector<uint8_t>& sel,
                                       const std::vector<GroupElement>& data,
                                       std::vector<GroupElement>& output,
                                       Peer* player) {
    const int size = static_cast<int>(sel.size());
    if (size <= 0) {
        return;
    }
    if (static_cast<int>(data.size()) < size ||
        static_cast<int>(output.size()) < size) {
        throw std::invalid_argument("parallel MUX vector size mismatch");
    }
    const int bits = data[0].bitsize;
    const uint64_t mask = mask_for_bits(bits);
    std::vector<uint64_t> corr_data(size);
    std::vector<uint64_t> data_s(size, 0);
    std::vector<uint64_t> data_r(size, 0);
    std::vector<uint8_t> choice(size);
    std::vector<GroupElement> local(size, GroupElement(0, bits));

    for (int i = 0; i < size; i++) {
        if (data[i].bitsize != bits || output[i].bitsize != bits) {
            throw std::invalid_argument("parallel MUX requires one ring size");
        }
        choice[i] = static_cast<uint8_t>(sel[i] != 0);
        local[i] = choice[i] ? data[i] : GroupElement(0, bits);
        corr_data[i] = (data[i].value - 2 * local[i].value) & mask;
    }

    sci::OTPack* otpack = player->getOTPack();
    std::thread reversed;
    std::thread straight;
    if (party_id == SERVER) {
        straight = std::thread([&] {
            otpack->iknp_straight->send_cot(data_s.data(), corr_data.data(),
                                            size, bits);
        });
        reversed = std::thread([&] {
            otpack->iknp_reversed->recv_cot(
                data_r.data(), reinterpret_cast<bool*>(choice.data()), size,
                bits);
        });
    } else if (party_id == CLIENT) {
        straight = std::thread([&] {
            otpack->iknp_straight->recv_cot(
                data_r.data(), reinterpret_cast<bool*>(choice.data()), size,
                bits);
        });
        reversed = std::thread([&] {
            otpack->iknp_reversed->send_cot(data_s.data(), corr_data.data(),
                                            size, bits);
        });
    } else {
        throw std::invalid_argument("parallel MUX unsupported party");
    }
    straight.join();
    reversed.join();

    for (int i = 0; i < size; i++) {
        output[i] = local[i] + GroupElement(data_r[i], bits) -
                    GroupElement(data_s[i], bits);
    }
}

void bench_parallel_multiplexer2_vector(int party_id,
                                        const std::vector<uint8_t>& control_bit,
                                        const std::vector<GroupElement>& dataA,
                                        const std::vector<GroupElement>& dataB,
                                        std::vector<GroupElement>& output,
                                        Peer* player) {
    const int size = static_cast<int>(control_bit.size());
    if (static_cast<int>(dataA.size()) < size ||
        static_cast<int>(dataB.size()) < size ||
        static_cast<int>(output.size()) < size) {
        throw std::invalid_argument("parallel payload MUX2 vector size mismatch");
    }
    std::vector<GroupElement> a_minus_b(size);
    std::vector<uint8_t> real_sel(size);
    for (int i = 0; i < size; i++) {
        a_minus_b[i] = dataA[i] - dataB[i];
        real_sel[i] = control_bit[i] ^ static_cast<uint8_t>(party_id - SERVER);
    }
    bench_parallel_multiplexer_vector(party_id, real_sel, a_minus_b, output,
                                      player);
    for (int i = 0; i < size; i++) {
        output[i] = output[i] + dataB[i];
    }
}

void direct_ot_ring_mult_total(int party_id,
                               const std::vector<GroupElement>& input0,
                               const std::vector<GroupElement>& input1,
                               std::vector<GroupElement>& output,
                               Peer* player) {
    const int size = static_cast<int>(input0.size());
    if (size <= 0) {
        return;
    }
    if (static_cast<int>(input1.size()) < size ||
        static_cast<int>(output.size()) < size) {
        throw std::invalid_argument("direct OT multiplication vector size mismatch");
    }

    std::vector<GroupElement> ot_input(2 * size);
    std::vector<GroupElement> cross_terms(2 * size,
                                          GroupElement(0, input0[0].bitsize));
    for (int i = 0; i < size; i++) {
        if (input0[i].bitsize != input0[0].bitsize ||
            input1[i].bitsize != input0[0].bitsize) {
            throw std::invalid_argument(
                "direct OT multiplication requires one ring size");
        }
        if (party_id == SERVER) {
            ot_input[i] = input0[i];
            ot_input[size + i] = input1[i];
        } else {
            ot_input[i] = input1[i];
            ot_input[size + i] = input0[i];
        }
    }

    cross_term_gen(party_id, ot_input.data(), cross_terms.data(),
                   party_id == SERVER, 2 * size, player);
    for (int i = 0; i < size; i++) {
        output[i] = input0[i] * input1[i] + cross_terms[i] +
                    cross_terms[size + i];
    }
}

void cmp2bit_inputs_for_payload_bench(int party_id, int index, uint8_t& high,
                                      uint8_t& low) {
    if (party_id == SERVER) {
        high = static_cast<uint8_t>((index >> 1) & 1);
        low = static_cast<uint8_t>(index & 1);
    } else {
        high = static_cast<uint8_t>((index >> 2) & 1);
        low = static_cast<uint8_t>((index + 1) & 1);
    }
}

uint8_t cmp2bit_expected_choice(int index) {
    uint8_t server_high = 0;
    uint8_t server_low = 0;
    uint8_t client_high = 0;
    uint8_t client_low = 0;
    cmp2bit_inputs_for_payload_bench(SERVER, index, server_high, server_low);
    cmp2bit_inputs_for_payload_bench(CLIENT, index, client_high, client_low);
    const uint8_t combined_high = server_high ^ client_high;
    const uint8_t combined_low = server_low ^ client_low;
    return client_low ^
           (combined_high & (combined_high ^ combined_low ^ uint8_t(1)));
}

std::vector<GroupElement> make_payload_bench_shares(int bits, int count,
                                                    uint64_t base,
                                                    uint64_t server_base) {
    std::vector<GroupElement> shares(count);
    const uint64_t mask = mask_for_bits(bits);
    for (int i = 0; i < count; i++) {
        const uint64_t value = (base + static_cast<uint64_t>(17 * i)) & mask;
        const uint64_t server_share =
            (server_base + static_cast<uint64_t>(31 * i)) & mask;
        shares[i] = split_share(value, bits, server_share);
    }
    return shares;
}

std::vector<uint64_t> make_payload_bench_public_values(int bits, int count,
                                                       uint64_t base) {
    std::vector<uint64_t> values(count);
    const uint64_t mask = mask_for_bits(bits);
    for (int i = 0; i < count; i++) {
        values[i] = (base + static_cast<uint64_t>(17 * i)) & mask;
    }
    return values;
}

uint8_t payload_choice_from_control_sum(int party_id, uint64_t control_sum) {
    const uint64_t local_signed_sum =
        party_id == SERVER ? control_sum : uint64_t(0) - control_sum;
    return static_cast<uint8_t>((local_signed_sum >> 1) & 1);
}

uint64_t control_sum_for_payload_choice_share(uint8_t share) {
    return share ? 2 : 0;
}

enum class PayloadConvVariant {
    SecondLsbMux,
    ParallelMux,
    XingCmp2BitMux,
    DirectOtMult,
    BeaverTotalMult,
};

struct PayloadRunResult {
    bool ok = true;
    uint64_t direct_iopack_comm = 0;
    uint64_t direct_iopack_rounds = 0;
};

std::string payload_variant_protocol(PayloadConvVariant variant) {
    switch (variant) {
        case PayloadConvVariant::SecondLsbMux:
            return "second_lsb_mux_total";
        case PayloadConvVariant::ParallelMux:
            return "parallel_mux";
        case PayloadConvVariant::XingCmp2BitMux:
            return "xing_cmp2bit_mux_total";
        case PayloadConvVariant::DirectOtMult:
            return "ring_mult_direct_ot_total";
        case PayloadConvVariant::BeaverTotalMult:
            return "ring_mult_beaver_total";
    }
    throw std::invalid_argument("unknown payload conversion variant");
}

std::string payload_variant_notes(PayloadConvVariant variant) {
    switch (variant) {
        case PayloadConvVariant::SecondLsbMux:
            return "local_second_lsb_choice;batched_arithmetic_mux;final_reconstruct";
        case PayloadConvVariant::ParallelMux:
            return "local_second_lsb_choice;parallel_sirnn_style_arithmetic_mux;final_reconstruct";
        case PayloadConvVariant::XingCmp2BitMux:
            return "scalar_cmp2bit_repeated;kkot_and_triples_counted;batched_arithmetic_mux;final_reconstruct";
        case PayloadConvVariant::DirectOtMult:
            return "direct_cross_term_ot_multiplication;final_reconstruct";
        case PayloadConvVariant::BeaverTotalMult:
            return "beaver_triple_generation_plus_beaver_open;final_reconstruct";
    }
    throw std::invalid_argument("unknown payload conversion variant");
}

std::vector<PayloadConvVariant> payload_variants() {
    return {PayloadConvVariant::SecondLsbMux,
            PayloadConvVariant::ParallelMux,
            PayloadConvVariant::XingCmp2BitMux,
            PayloadConvVariant::DirectOtMult,
            PayloadConvVariant::BeaverTotalMult};
}

PayloadRunResult execute_payload_variant(PayloadConvVariant variant, int Bout,
                                         int n, int r, Peer* active_peer) {
    PayloadRunResult result;
    const uint64_t offset = static_cast<uint64_t>(1000 + 97 * r);
    std::vector<GroupElement> dataA =
        make_payload_bench_shares(Bout, n, 11 + offset, 100 + offset);
    std::vector<GroupElement> dataB =
        make_payload_bench_shares(Bout, n, 29 + offset, 300 + offset);
    const std::vector<uint64_t> publicA =
        make_payload_bench_public_values(Bout, n, 11 + offset);
    const std::vector<uint64_t> publicB =
        make_payload_bench_public_values(Bout, n, 29 + offset);
    std::vector<GroupElement> out(n, GroupElement(0, Bout));

    if (variant == PayloadConvVariant::SecondLsbMux) {
        std::vector<uint8_t> choices(n);
        for (int i = 0; i < n; i++) {
            const uint8_t publicChoice = static_cast<uint8_t>((i + r) & 1);
            const uint8_t serverShare = static_cast<uint8_t>((i >> 1) & 1);
            const uint8_t localShare =
                party == SERVER ? serverShare
                                : static_cast<uint8_t>(publicChoice ^
                                                       serverShare);
            choices[i] = payload_choice_from_control_sum(
                party, control_sum_for_payload_choice_share(localShare));
        }
        bench_multiplexer2_vector(party, choices, dataA, dataB, out,
                                  active_peer);
        reconstruct(n, out.data(), Bout);

        std::vector<uint64_t> expected(n);
        for (int i = 0; i < n; i++) {
            const uint8_t publicChoice = static_cast<uint8_t>((i + r) & 1);
            expected[i] = publicChoice ? publicB[i] : publicA[i];
        }
        result.ok = check_reconstructed_vector(out, expected);
        return result;
    }

    if (variant == PayloadConvVariant::ParallelMux) {
        std::vector<uint8_t> choices(n);
        for (int i = 0; i < n; i++) {
            const uint8_t publicChoice = static_cast<uint8_t>((i + r) & 1);
            const uint8_t serverShare = static_cast<uint8_t>((i >> 1) & 1);
            const uint8_t localShare =
                party == SERVER ? serverShare
                                : static_cast<uint8_t>(publicChoice ^
                                                       serverShare);
            choices[i] = payload_choice_from_control_sum(
                party, control_sum_for_payload_choice_share(localShare));
        }
        const uint64_t directCommBefore = active_peer->getIOPack()->get_comm();
        const uint64_t directRoundsBefore =
            active_peer->getIOPack()->get_rounds();
        bench_parallel_multiplexer2_vector(party, choices, dataA, dataB, out,
                                           active_peer);
        result.direct_iopack_comm =
            active_peer->getIOPack()->get_comm() - directCommBefore;
        result.direct_iopack_rounds =
            active_peer->getIOPack()->get_rounds() - directRoundsBefore;
        reconstruct(n, out.data(), Bout);

        std::vector<uint64_t> expected(n);
        for (int i = 0; i < n; i++) {
            const uint8_t publicChoice = static_cast<uint8_t>((i + r) & 1);
            expected[i] = publicChoice ? publicB[i] : publicA[i];
        }
        result.ok = check_reconstructed_vector(out, expected);
        return result;
    }

    if (variant == PayloadConvVariant::XingCmp2BitMux) {
        const uint64_t directCommBefore = active_peer->getIOPack()->get_comm();
        const uint64_t directRoundsBefore =
            active_peer->getIOPack()->get_rounds();
        std::vector<uint8_t> choices(n);
        for (int i = 0; i < n; i++) {
            uint8_t high = 0;
            uint8_t low = 0;
            cmp2bit_inputs_for_payload_bench(party, i + r, high, low);
            choices[i] = cmp_2bit_opt(party, high, low, active_peer);
        }
        result.direct_iopack_comm =
            active_peer->getIOPack()->get_comm() - directCommBefore;
        result.direct_iopack_rounds =
            active_peer->getIOPack()->get_rounds() - directRoundsBefore;
        bench_multiplexer2_vector(party, choices, dataA, dataB, out,
                                  active_peer);
        reconstruct(n, out.data(), Bout);

        std::vector<uint64_t> expected(n);
        for (int i = 0; i < n; i++) {
            const uint8_t publicChoice = cmp2bit_expected_choice(i + r);
            expected[i] = publicChoice ? publicB[i] : publicA[i];
        }
        result.ok = check_reconstructed_vector(out, expected);
        return result;
    }

    std::vector<GroupElement> x =
        make_payload_bench_shares(Bout, n, 7 + offset, 500 + offset);
    std::vector<GroupElement> y =
        make_payload_bench_shares(Bout, n, 13 + offset, 700 + offset);
    const std::vector<uint64_t> publicX =
        make_payload_bench_public_values(Bout, n, 7 + offset);
    const std::vector<uint64_t> publicY =
        make_payload_bench_public_values(Bout, n, 13 + offset);
    std::vector<uint64_t> expectedProduct(n);
    const uint64_t productMask = mask_for_bits(Bout);
    for (int i = 0; i < n; i++) {
        expectedProduct[i] = (publicX[i] * publicY[i]) & productMask;
    }

    if (variant == PayloadConvVariant::DirectOtMult) {
        direct_ot_ring_mult_total(party, x, y, out, active_peer);
    } else if (variant == PayloadConvVariant::BeaverTotalMult) {
        std::vector<GroupElement> a(n, GroupElement(0, Bout));
        std::vector<GroupElement> b(n, GroupElement(0, Bout));
        std::vector<GroupElement> c(n, GroupElement(0, Bout));
        beaver_mult_offline(party, a.data(), b.data(), c.data(), active_peer,
                            n);
        beaver_mult_online(party, x.data(), y.data(), a.data(), b.data(),
                           c.data(), out.data(), n, active_peer);
    } else {
        throw std::invalid_argument("unknown payload conversion variant");
    }
    reconstruct(n, out.data(), Bout);
    result.ok = check_reconstructed_vector(out, expectedProduct);
    return result;
}

PhaseMetric measure_payload_warm_variant(PayloadConvVariant variant, int Bout,
                                         int batch, int repeat, bool& ok) {
    PhaseMetric total;
    for (int r = 0; r < repeat; r++) {
        peer->sync();
        const CounterSnapshot before = snapshot();
        const auto start = Clock::now();
        PayloadRunResult run =
            execute_payload_variant(variant, Bout, batch, r, peer);
        const auto end = Clock::now();
        const CounterSnapshot after = snapshot();
        peer->sync();
        PhaseMetric metric =
            diff_metric(before, after, elapsed_us(start, end));
        metric.sent += run.direct_iopack_comm;
        metric.peer_rounds += run.direct_iopack_rounds;
        add_metric(total, metric);
        ok = ok && run.ok;
    }
    return total;
}

void emit_payload_row(const std::string& group, PayloadConvVariant variant,
                      const PhaseMetric& metric, bool ok, int Bout, int batch,
                      int repeat, const std::string& measurementNote) {
    Row row;
    row.group = group;
    row.protocol = payload_variant_protocol(variant);
    row.phase = "total";
    row.Bin = 2;
    row.Bout = Bout;
    row.repeat = repeat;
    row.evaluatedPoints = batch;
    row.metric = metric;
    row.status = ok ? "ok" : "correctness_failed";
    std::ostringstream notes;
    notes << payload_variant_notes(variant)
          << ";conversions_per_repeat=" << batch
          << ";total_conversions=" << (batch * repeat) << ';'
          << measurementNote << ";time_us_per_conversion="
          << (static_cast<double>(metric.time_us) /
              static_cast<double>(batch * repeat))
          << ";raw_party_comm_bytes_per_conversion="
          << (static_cast<double>(metric_comm(metric)) /
              static_cast<double>(batch * repeat));
    row.notes = notes.str();
    emit_row(row);
}

}  // namespace

namespace {

void run_payload_conversion_grid(int repeat) {
    struct Set {
        int Bout;
        int batch;
        int repeat;
    };
    const std::vector<int> batches = {1, 8, 64, 256};
    std::vector<Set> sets;
    for (int Bout : {16, 32}) {
        for (int batch : batches) {
            sets.push_back({Bout, batch, repeat});
        }
    }

    for (const Set& set : sets) {
        for (PayloadConvVariant variant : payload_variants()) {
            bool ok = true;
            PhaseMetric metric = measure_payload_warm_variant(
                variant, set.Bout, set.batch, set.repeat, ok);
            emit_payload_row(
                "payload_conversion", variant, metric, ok, set.Bout,
                set.batch, set.repeat,
                "warm_peer_total_excludes_peer_otpack_base_setup");
        }
    }
}

}  // namespace

void run_payload_conversion_bench(const BenchConfig& config) {
    run_payload_conversion_grid(config.repeat);
}
