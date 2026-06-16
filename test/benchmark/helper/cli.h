#pragma once

#include "common.h"

#include <map>
#include <string>
#include <vector>

using BenchArgMap = std::map<std::string, std::string>;

BenchArgMap parse_bench_args(int argc, char** argv);
bool has_bench_arg(const BenchArgMap& args, const std::string& name);
BenchConfig make_bench_config(const BenchArgMap& args,
                              const std::vector<std::string>& benchNames);
void print_bench_help(const char* program,
                      const std::vector<std::string>& mainBenchNames,
                      const std::vector<std::string>& microBenchNames);
