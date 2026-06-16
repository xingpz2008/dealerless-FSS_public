#pragma once

#include "mpc/api.h"
#include "buildingblock/comparison.h"
#include "buildingblock/digit_decomposition.h"
#include "buildingblock/equality.h"
#include "buildingblock/lut.h"
#include "buildingblock/mic.h"
#include "buildingblock/modular.h"
#include "buildingblock/ring_extension.h"
#include "buildingblock/truncation.h"
#include "mpc/comms.h"
#include "fss/dpf.h"
#include "fss/fss_wrapper.h"
#include "fss/idpf.h"
#include "math/polyeval.h"
#include "commons/public_data.h"

#include <chrono>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

using dfss::defaultDPFETSuffixBits;
using dfss::evalAllDPF;
using dfss::evalBooleanCorrelatedDPF;
using dfss::evalCorrelatedDPF;
using dfss::evalDPFET;
using dfss::evaliDPF;
using dfss::keyGenBooleanCorrelatedDPF;
using dfss::keyGenCorrelatedDPF;
using dfss::keyGenDPFET;
using dfss::keyGeniDPF;

extern int party_instance;
extern int party;
extern int32_t bitlength;
extern int num_threads;
extern int port;
extern std::string address;
extern int num_argmax;
extern uint8_t choice_bit;
extern bool verbose;
extern int length;
extern Peer* client;
extern Peer* server;
extern Dealer* dealer;
extern Peer* peer;

using Clock = std::chrono::steady_clock;

struct CounterSnapshot {
    uint64_t sent = 0;
    uint64_t received = 0;
    uint64_t peer_rounds = 0;
    int32_t reconstruct_rounds = 0;
};

struct PhaseMetric {
    uint64_t time_us = 0;
    uint64_t sent = 0;
    uint64_t received = 0;
    uint64_t peer_rounds = 0;
    int32_t reconstruct_rounds = 0;
};

struct BenchConfig {
    std::string bench;
    int role = 0;
    int port = 32000;
    int repeat = 10;

    int Bin = -1;
    int Bout = -1;

    bool et = false;
    int suffixBits = -1;

    int parts = -1;
    int scale = -1;
    int degree = -1;

    std::string phase = "all";
    std::string protocol = "all";
    std::string output = "table";

    bool checkCorrectness = true;
};

struct Row {
    std::string group;
    std::string protocol;
    std::string phase;
    int Bin = 0;
    int Bout = 0;
    int repeat = 0;
    int suffixBits = -1;
    int lambdaBits = 128;
    int degree = -1;
    int scale = -1;
    int segments = -1;
    int intervalCount = -1;
    int evaluatedPoints = -1;
    PhaseMetric metric;
    double plaintextMaxAbsError = 0.0;
    double ciphertextVsPlaintextMaxAbsError = 0.0;
    std::string status = "ok";
    std::string notes;
};

extern BenchConfig g_bench_config;

uint64_t elapsed_us(Clock::time_point start, Clock::time_point end);
CounterSnapshot snapshot();
PhaseMetric diff_metric(const CounterSnapshot& before,
                        const CounterSnapshot& after,
                        uint64_t time_us);

template <typename Fn>
PhaseMetric measure_phase(Fn&& fn) {
    peer->sync();
    const CounterSnapshot before = snapshot();
    const auto start = Clock::now();
    fn();
    const auto end = Clock::now();
    const CounterSnapshot after = snapshot();
    peer->sync();
    return diff_metric(before, after, elapsed_us(start, end));
}

template <typename Fn>
PhaseMetric measure_offline_phase(Fn&& fn) {
    peer->reset_ot_precompute();
    return measure_phase(std::forward<Fn>(fn));
}

template <typename Fn>
PhaseMetric measure_online_phase(Fn&& fn) {
    return measure_phase(std::forward<Fn>(fn));
}

void add_metric(PhaseMetric& total, const PhaseMetric& cur);
uint64_t metric_comm(const PhaseMetric& metric);
GroupElement split_share(uint64_t value, int bitsize, uint64_t server_share);
uint64_t mask_for_bits(int bits);
int64_t signed_from_twos(uint64_t value, int bits);
uint64_t twos_from_signed(int64_t value, int bits);
double real_from_fixed(uint64_t value, int bits, int scale);
int config_suffix_bits(const BenchConfig& config);
void reconstruct_for_check(GroupElement& value);
bool check_reconstructed_vector(const std::vector<GroupElement>& output,
                                const std::vector<uint64_t>& expected);
