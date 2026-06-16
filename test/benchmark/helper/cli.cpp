#include "cli.h"

// Explicit CLI parsing for one concrete dFSS benchmark.

#include <algorithm>
#include <cctype>
#include <iostream>
#include <set>
#include <sstream>
#include <stdexcept>

namespace {

std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return value;
}

std::string join_names(const std::vector<std::string>& names) {
    std::ostringstream out;
    for (size_t i = 0; i < names.size(); i++) {
        if (i != 0) {
            out << ", ";
        }
        out << names[i];
    }
    return out.str();
}

bool supported_bench(const std::vector<std::string>& names,
                     const std::string& bench) {
    return std::find(names.begin(), names.end(), bench) != names.end();
}

std::string get_string(const BenchArgMap& args, const std::string& name,
                       const std::string& defaultValue = "") {
    const auto it = args.find(name);
    return it == args.end() ? defaultValue : it->second;
}

int get_int(const BenchArgMap& args, const std::string& name,
            int defaultValue) {
    const auto it = args.find(name);
    if (it == args.end()) {
        return defaultValue;
    }
    return std::stoi(it->second);
}

bool parse_bool_value(const std::string& value) {
    const std::string v = lower(value);
    if (v == "1" || v == "true" || v == "yes" || v == "on") {
        return true;
    }
    if (v == "0" || v == "false" || v == "no" || v == "off") {
        return false;
    }
    throw std::invalid_argument("invalid boolean value '" + value + "'");
}

bool get_bool(const BenchArgMap& args, const std::string& name,
              bool defaultValue) {
    const auto it = args.find(name);
    return it == args.end() ? defaultValue : parse_bool_value(it->second);
}

int parse_role(const BenchArgMap& args) {
    const std::string role = lower(get_string(args, "role"));
    if (role == "server") {
        return SERVER;
    }
    if (role == "client") {
        return CLIENT;
    }
    return 0;
}

void reject_unknown_args(const BenchArgMap& args) {
    static const std::set<std::string> kAllowed = {
        "bench", "bin", "bout", "correctness", "degree", "et", "help",
        "output", "parts", "phase", "port", "protocol", "repeat", "role",
        "scale", "skip-correctness", "skip_correctness", "suffix",
        "suffix_bits", "suffixbits"};

    for (const auto& item : args) {
        if (kAllowed.find(item.first) == kAllowed.end()) {
            throw std::invalid_argument(
                "unknown argument '" + item.first +
                "'. Use help=1 for the explicit benchmark CLI.");
        }
    }
}

void normalize_and_validate(BenchConfig& config, const BenchArgMap& args,
                            const std::vector<std::string>& benchNames) {
    config.bench = lower(config.bench);
    config.phase = lower(config.phase);
    config.output = lower(config.output);
    config.protocol = lower(config.protocol);

    if (!supported_bench(benchNames, config.bench)) {
        throw std::invalid_argument("unknown benchmark '" + config.bench +
                                    "'. Supported: " +
                                    join_names(benchNames));
    }
    if (config.repeat <= 0) {
        throw std::invalid_argument("repeat must be positive");
    }
    if (config.role != SERVER && config.role != CLIENT) {
        throw std::invalid_argument("role must be server or client");
    }
    if (config.bench == "payload_conversion" && config.Bin < 0) {
        config.Bin = 2;
    }
    if (config.Bin <= 0) {
        throw std::invalid_argument("benchmark requires bin=N");
    }
    if (config.Bout < 0) {
        config.Bout = config.Bin;
    }
    if (config.Bout <= 0) {
        throw std::invalid_argument("bout must be positive");
    }
    if (config.phase != "all" && config.phase != "offline") {
        throw std::invalid_argument("phase must be all or offline");
    }
    if (config.output != "table" && config.output != "csv" &&
        config.output != "both") {
        throw std::invalid_argument("output must be table, csv, or both");
    }

    const bool suffixProvided =
        has_bench_arg(args, "suffix") || has_bench_arg(args, "suffixbits") ||
        has_bench_arg(args, "suffix_bits");
    if (!config.et && suffixProvided) {
        throw std::invalid_argument("suffix requires et=1");
    }
    if (config.suffixBits != -1 && config.suffixBits <= 0) {
        throw std::invalid_argument("suffix must be -1 or a positive integer");
    }

    if (config.bench == "poly") {
        if (config.scale < 0 || config.degree < 0 || config.parts <= 0) {
            throw std::invalid_argument(
                "poly requires scale=N degree=N parts=N");
        }
    } else if (config.bench == "mic") {
        if (config.parts < 0) {
            config.parts = 1;
        }
        if (config.parts <= 0) {
            throw std::invalid_argument("mic parts must be positive");
        }
    }
}

}  // namespace

BenchArgMap parse_bench_args(int argc, char** argv) {
    BenchArgMap args;
    for (int i = 1; i < argc; i++) {
        const std::string token(argv[i]);
        if (token == "-h" || token == "--help" || token == "help" ||
            token == "help=1") {
            args["help"] = "1";
            continue;
        }
        const size_t eq = token.find('=');
        if (eq == std::string::npos) {
            throw std::invalid_argument(
                "expected key=value argument, got '" + token + "'");
        }
        args[lower(token.substr(0, eq))] = token.substr(eq + 1);
    }
    reject_unknown_args(args);
    return args;
}

bool has_bench_arg(const BenchArgMap& args, const std::string& name) {
    return args.find(name) != args.end();
}

BenchConfig make_bench_config(const BenchArgMap& args,
                              const std::vector<std::string>& benchNames) {
    BenchConfig config;
    config.role = parse_role(args);
    config.port = get_int(args, "port", 32000);
    config.repeat = get_int(args, "repeat", 10);
    config.bench = get_string(args, "bench");
    config.Bin = get_int(args, "bin", -1);
    config.Bout = get_int(args, "bout", -1);
    config.et = get_bool(args, "et", false);
    config.suffixBits =
        get_int(args, "suffix",
                get_int(args, "suffixbits",
                        get_int(args, "suffix_bits", -1)));
    config.parts = get_int(args, "parts", -1);
    config.scale = get_int(args, "scale", -1);
    config.degree = get_int(args, "degree", -1);
    config.phase = get_string(args, "phase", "all");
    config.protocol = get_string(args, "protocol", "all");
    config.output = get_string(args, "output", "table");

    if (has_bench_arg(args, "correctness")) {
        config.checkCorrectness = get_bool(args, "correctness", true);
    }
    if (get_bool(args, "skip_correctness", false) ||
        get_bool(args, "skip-correctness", false)) {
        config.checkCorrectness = false;
    }

    const bool etProvided = has_bench_arg(args, "et");
    if (!etProvided &&
        (lower(config.bench) == "et" || lower(config.bench) == "lut" ||
         lower(config.bench) == "poly")) {
        config.et = true;
    }

    normalize_and_validate(config, args, benchNames);
    return config;
}

void print_bench_help(const char* program,
                      const std::vector<std::string>& mainBenchNames,
                      const std::vector<std::string>& microBenchNames) {
    std::cout
        << "Usage:\n"
        << "  " << program
        << " role=server port=32000 bench=poly bin=16 scale=8 degree=2 parts=8\n"
        << "  " << program
        << " role=client port=32000 bench=poly bin=16 scale=8 degree=2 parts=8\n\n"
        << "Main benchmarks:\n"
        << "  " << join_names(mainBenchNames) << "\n\n"
        << "Microbenchmarks:\n"
        << "  " << join_names(microBenchNames) << "\n\n"
        << "Common parameters:\n"
        << "  role=server|client\n"
        << "  port=N, default 32000\n"
        << "  repeat=N, default 10\n"
        << "  bench=NAME\n"
        << "  bin=N, bout=N (default bout=bin)\n"
        << "  phase=all|offline, default all\n"
        << "  output=table|csv|both, default table\n"
        << "  correctness=0 or skip_correctness=1 to skip correctness checks\n\n"
        << "ET parameters:\n"
        << "  et=0|1, suffix=N. suffix defaults to -1.\n"
        << "  et=0 means non-ET; et=1 suffix=-1 means default suffix;\n"
        << "  et=1 suffix=N uses explicit suffix N, including suffix=1.\n\n"
        << "Benchmark-specific parameters:\n"
        << "  poly requires bin, scale, degree, parts; bout defaults to bin.\n"
        << "  mic uses parts as interval count, default 1.\n"
        << "  comparison defaults bout=bin.\n"
        << "  payload_conversion defaults bin=2 and uses its own Bout/batch grid.\n";
}
