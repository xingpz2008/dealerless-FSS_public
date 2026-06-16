#include "legacy/dcf.h"
#include "legacy/dpf.h"
#include "ArgMapping.h"
#include "mpc/api.h"
#include "mpc/comms.h"

#include <chrono>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

using namespace sci;

int party_instance = 0;
int party = 0;
int32_t bitlength = 32;
int num_threads = 1;
int port = 32000;
std::string address = "127.0.0.1";
int num_argmax = 1000;
uint8_t choice_bit = 0;
bool verbose = false;
int length = 1;
Peer* client = nullptr;
Peer* server = nullptr;
Dealer* dealer = nullptr;
Peer* peer = nullptr;

namespace {

using Clock = std::chrono::steady_clock;

GroupElement split_share(uint64_t value, int bitsize, uint64_t server_share) {
    if (party == SERVER) {
        return GroupElement(server_share, bitsize);
    }
    return GroupElement(value - server_share, bitsize);
}

void free_dpf_key(DPFKeyPack& key) {
    freeDPFKeyPack(key);
}

uint64_t elapsed_us(Clock::time_point start, Clock::time_point end) {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(end - start).count());
}

bool check_scalar(const std::string& name, GroupElement actual, uint64_t expected) {
    reconstruct(&actual);
    const bool ok = actual.value == expected;
    if (party == SERVER) {
        std::cout << (ok ? "[PASS] " : "[FAIL] ") << name
                  << " actual=" << actual.value << " expected=" << expected << '\n';
    }
    return ok;
}

}  // namespace

int main(int argc, char** argv) {
    int stress_bits = 19;
    int output_bits = 16;
    int repeat = 1;
    int dcf_batch_size = 128;
    int eval_all_bits = 12;

    ArgMapping amap;
    amap.arg("r", party, "Role of party: SERVER = 2; CLIENT = 3");
    amap.arg("p", port, "Port Number");
    amap.arg("b", stress_bits, "DPF/DCF input bit length");
    amap.arg("o", output_bits, "DPF/DCF output bit length");
    amap.arg("n", repeat, "Number of high-depth repetitions");
    amap.arg("m", dcf_batch_size, "DCF batch evaluation size");
    amap.arg("a", eval_all_bits, "DPF evalAll bit length");
    amap.parse(argc, argv);

    if (party == CLIENT) {
        server = new Peer(address, port);
        peer = server;
    } else if (party == SERVER) {
        client = waitForPeer(port);
        peer = client;
    } else {
        std::cerr << "Pass r=2 for SERVER or r=3 for CLIENT.\n";
        return 2;
    }

    int failures = 0;
    uint64_t dpf_keygen_us = 0;
    uint64_t dpf_eval_us = 0;
    uint64_t dpf_eval_all_us = 0;
    uint64_t dcf_keygen_us = 0;
    uint64_t dcf_eval_us = 0;
    uint64_t dcf_batch_eval_us = 0;

    const uint64_t domain_mask =
        stress_bits == 64 ? ~uint64_t(0) : ((uint64_t(1) << stress_bits) - 1);
    const uint64_t payload_mask =
        output_bits == 64 ? ~uint64_t(0) : ((uint64_t(1) << output_bits) - 1);

    for (int iter = 0; iter < repeat; ++iter) {
        const uint64_t dpf_point = (123456 + 4099ULL * iter) & domain_mask;
        const uint64_t dpf_payload = (31337 + 17ULL * iter) & payload_mask;
        auto start = Clock::now();
        DPFKeyPack dpf_key = keyGenDPF(
            party, stress_bits, output_bits,
            split_share(dpf_point, stress_bits, 45678 + iter),
            split_share(dpf_payload, output_bits, 22222 + iter), false);
        dpf_keygen_us += elapsed_us(start, Clock::now());

        GroupElement dpf_hit(0, output_bits);
        GroupElement dpf_miss(0, output_bits);
        start = Clock::now();
        evalDPF(party, &dpf_hit, GroupElement(dpf_point, stress_bits), dpf_key, false);
        evalDPF(party, &dpf_miss, GroupElement((dpf_point + 1) & domain_mask, stress_bits),
                dpf_key, false);
        dpf_eval_us += elapsed_us(start, Clock::now());
        failures += check_scalar("high-depth DPF point hit", dpf_hit, dpf_payload) ? 0 : 1;
        failures += check_scalar("high-depth DPF point miss", dpf_miss, 0) ? 0 : 1;
        free_dpf_key(dpf_key);

        const uint64_t eval_all_point =
            (37 + 17ULL * iter) & ((uint64_t(1) << eval_all_bits) - 1);
        DPFKeyPack eval_all_key = keyGenDPF(
            party, eval_all_bits, output_bits,
            split_share(eval_all_point, eval_all_bits, 21 + iter),
            split_share(dpf_payload, output_bits, 333 + iter), false);
        std::vector<GroupElement> eval_all_output(uint64_t(1) << eval_all_bits);
        for (auto& value : eval_all_output) {
            value = GroupElement(0, output_bits);
        }
        start = Clock::now();
        evalAll(party, eval_all_output.data(), eval_all_key, eval_all_bits);
        dpf_eval_all_us += elapsed_us(start, Clock::now());
        failures += check_scalar("DPF evalAll stress hit",
                                 eval_all_output[eval_all_point],
                                 dpf_payload) ? 0 : 1;
        failures += check_scalar("DPF evalAll stress miss",
                                 eval_all_output[(eval_all_point + 1) & ((uint64_t(1) << eval_all_bits) - 1)],
                                 0) ? 0 : 1;
        free_dpf_key(eval_all_key);

        const uint64_t dcf_threshold = (200000 + 257ULL * iter) & domain_mask;
        const uint64_t dcf_payload = (4567 + 31ULL * iter) & payload_mask;
        start = Clock::now();
        newDCFKeyPack dcf_key = keyGenNewDCF(
            party, stress_bits, output_bits,
            split_share(dcf_threshold, stress_bits, 76543 + iter),
            split_share(dcf_payload, output_bits, 12345 + iter));
        dcf_keygen_us += elapsed_us(start, Clock::now());

        newDCFKeyPack dcf_keys[2] = {dcf_key, dcf_key};
        GroupElement queries[2] = {
            GroupElement((dcf_threshold + domain_mask) & domain_mask, stress_bits),
            GroupElement(dcf_threshold, stress_bits),
        };
        GroupElement outputs[2] = {
            GroupElement(0, output_bits),
            GroupElement(0, output_bits),
        };
        start = Clock::now();
        evalNewDCF(party, outputs, queries, dcf_keys, 2, stress_bits);
        dcf_eval_us += elapsed_us(start, Clock::now());
        failures += check_scalar("high-depth DCF below threshold", outputs[0],
                                 dcf_payload) ? 0 : 1;
        failures += check_scalar("high-depth DCF at threshold", outputs[1], 0) ? 0 : 1;

        std::vector<newDCFKeyPack> batch_keys(dcf_batch_size, dcf_key);
        std::vector<GroupElement> batch_queries(dcf_batch_size);
        std::vector<GroupElement> batch_outputs(dcf_batch_size);
        for (int i = 0; i < dcf_batch_size; i++) {
            const uint64_t offset = static_cast<uint64_t>(i) - dcf_batch_size / 2;
            batch_queries[i] =
                GroupElement((dcf_threshold + offset) & domain_mask, stress_bits);
            batch_outputs[i] = GroupElement(0, output_bits);
        }
        start = Clock::now();
        evalNewDCF(party, batch_outputs.data(), batch_queries.data(),
                   batch_keys.data(), dcf_batch_size, stress_bits);
        dcf_batch_eval_us += elapsed_us(start, Clock::now());
        failures += check_scalar("batched DCF first below threshold",
                                 batch_outputs[0], dcf_payload) ? 0 : 1;
        failures += check_scalar("batched DCF last at-or-above threshold",
                                 batch_outputs[dcf_batch_size - 1], 0) ? 0 : 1;
        freeNewDCFKeyPack(dcf_key);
    }

    if (party == SERVER) {
        std::cout << "Safety/performance checks: "
                  << (failures == 0 ? "PASS" : "FAIL")
                  << " (" << failures << " failed)\n";
        std::cout << "Timing microseconds total: "
                  << "dpf_keygen=" << dpf_keygen_us
                  << " dpf_eval_2pt=" << dpf_eval_us
                  << " dpf_eval_all=" << dpf_eval_all_us
                  << " dcf_keygen=" << dcf_keygen_us
                  << " dcf_eval_2pt=" << dcf_eval_us
                  << " dcf_eval_batch=" << dcf_batch_eval_us
                  << " repeat=" << repeat
                  << " bits=" << stress_bits
                  << " output_bits=" << output_bits
                  << " dcf_batch_size=" << dcf_batch_size
                  << " eval_all_bits=" << eval_all_bits << '\n';
    }

    return failures == 0 ? 0 : 1;
}
