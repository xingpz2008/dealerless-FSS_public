#include "helper/cli.h"
#include "helper/common.h"
#include "helper/report.h"
#include "protocol/benchmarks.h"

// Command-line entry point and explicit dispatch for dFSS benchmarks.

#include <exception>
#include <iostream>
#include <iterator>
#include <stdexcept>
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
BenchConfig g_bench_config;

namespace {

struct BenchmarkEntry {
    const char* name;
    void (*run)(const BenchConfig& config);
};

const BenchmarkEntry kBenchmarks[] = {
    {"et", run_et_bench},
    {"dpf", run_dpf_bench},
    {"idpf", run_idpf_bench},
    {"lut", run_lut_bench},
    {"mic", run_mic_bench},
    {"comparison", run_comparison_bench},
    {"poly", run_poly_bench},
    {"equality", run_equality_bench},
    {"payload_conversion", run_payload_conversion_bench},
};

const char* kMainBenchmarkNames[] = {
    "et", "dpf", "idpf", "lut", "mic", "comparison", "poly", "equality",
};

const char* kMicroBenchmarkNames[] = {
    "payload_conversion",
};

std::vector<std::string> benchmark_names() {
    std::vector<std::string> names;
    for (const auto& benchmark : kBenchmarks) {
        names.push_back(benchmark.name);
    }
    return names;
}

std::vector<std::string> main_benchmark_names() {
    return std::vector<std::string>(
        std::begin(kMainBenchmarkNames), std::end(kMainBenchmarkNames));
}

std::vector<std::string> micro_benchmark_names() {
    return std::vector<std::string>(
        std::begin(kMicroBenchmarkNames), std::end(kMicroBenchmarkNames));
}

const BenchmarkEntry* find_benchmark(const std::string& name) {
    for (const auto& benchmark : kBenchmarks) {
        if (name == benchmark.name) {
            return &benchmark;
        }
    }
    return nullptr;
}

void print_run_header(const BenchConfig& config) {
    if (!output_wants_table(config)) {
        return;
    }
    std::cout << "dFSS Benchmark: " << config.bench << "\n"
              << "Party: " << (party == SERVER ? "server" : "client") << "\n"
              << "Parameters: Bin=" << config.Bin << " Bout=" << config.Bout
              << " repeat=" << config.repeat << " phase=" << config.phase
              << " correctness="
              << (config.checkCorrectness ? "on" : "off");
    if (config.et) {
        std::cout << " et=on suffix="
                  << (config.suffixBits < 0
                          ? std::string("default")
                          : std::to_string(config.suffixBits));
    }
    if (config.parts > 0) {
        std::cout << " parts=" << config.parts;
    }
    if (config.scale >= 0) {
        std::cout << " scale=" << config.scale;
    }
    if (config.degree >= 0) {
        std::cout << " degree=" << config.degree;
    }
    std::cout << "\n";
}

void connect_peer(const BenchConfig& config) {
    party = config.role;
    port = config.port;

    if (party == CLIENT) {
        server = new Peer(address, port);
        peer = server;
    } else if (party == SERVER) {
        client = waitForPeer(port);
        peer = client;
    }
}

void run_benchmark(const BenchConfig& config) {
    const BenchmarkEntry* benchmark = find_benchmark(config.bench);
    if (benchmark == nullptr) {
        throw std::invalid_argument("unknown benchmark: " + config.bench);
    }
    print_run_header(config);
    benchmark->run(config);
}

}  // namespace

int main(int argc, char** argv) {
    try {
        const std::vector<std::string> names = benchmark_names();
        const auto args = parse_bench_args(argc, argv);
        if (has_bench_arg(args, "help")) {
            print_bench_help(argv[0], main_benchmark_names(),
                             micro_benchmark_names());
            return 0;
        }

        g_bench_config = make_bench_config(args, names);
        connect_peer(g_bench_config);

        std::cerr << "DFSS_EXT_BENCH party=" << party
                  << " bench=" << g_bench_config.bench
                  << " repeat=" << g_bench_config.repeat
                  << " phase=" << g_bench_config.phase
                  << " output=" << g_bench_config.output
                  << " round_source=peer->rounds"
                  << " reconstruct_round_source=numRounds"
                  << " comm_source=raw per-party peer byte counters;"
                  << " aggregate reports should sum bytes_sent across parties\n";

        run_benchmark(g_bench_config);
        emit_table_summary();
    } catch (const std::exception& ex) {
        std::cerr << "DFSS_EXT_BENCH error: " << ex.what() << '\n';
        return 1;
    }

    if (party == SERVER) {
        std::cout << "DFSS_EXT_BENCH_DONE\n";
    }
    return 0;
}
