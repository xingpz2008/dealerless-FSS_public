#include "legacy_correctness_common.h"

#include "ArgMapping.h"

// Command-line entry point and registry for legacy correctness cases.

#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>

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

struct CorrectnessCase {
    int id;
    const char* name;
    void (*run)(ResultLog&);
};

const CorrectnessCase kCorrectnessCases[] = {
    {1, "DPF", check_dpf},
    {2, "DCF", check_dcf},
    {3, "comparison", check_legacy_comparison},
    {4, "modular", check_legacy_modular},
    {5, "truncate", check_legacy_truncate_and_reduce},
    {6, "containment", check_containment},
    {7, "public LUT", check_legacy_public_lut},
    {8, "private LUT", check_legacy_private_lut},
    {9, "digit decomposition", check_legacy_digdec},
    {10, "spline", check_spline_poly_approx},
    {11, "trigonometric", check_trigonometric},
    {12, "proximity", check_case_studies},
};

std::string correctness_case_help() {
    std::ostringstream out;
    out << "Case: all = 0";
    for (const auto& test : kCorrectnessCases) {
        out << "; " << test.name << " = " << test.id;
    }
    return out.str();
}

}  // namespace

int main(int argc, char** argv) {
    int test_case = 0;
    ArgMapping amap;
    amap.arg("r", party, "Role of party: SERVER = 2; CLIENT = 3");
    amap.arg("p", port, "Port Number");
    const std::string case_help = correctness_case_help();
    amap.arg("t", test_case, case_help.c_str());
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

    ResultLog log;
    for (const auto& test : kCorrectnessCases) {
        if (test_case == 0 || test_case == test.id) {
            test.run(log);
        }
    }

    if (party == SERVER) {
        std::cout << "Correctness checks: "
                  << (log.failures() == 0 ? "PASS" : "FAIL")
                  << " (" << log.failures() << " failed)\n";
    }
    return log.failures() == 0 ? 0 : 1;
}
