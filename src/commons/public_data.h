#pragma once

#include "commons/group_element.h"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

struct PublicLUTData {
    int Bin = 0;
    int Bout = 0;
    std::vector<GroupElement> values;
};

struct PublicPiecewisePolyData {
    int Bin = 0;
    int Bout = 0;
    int scale = 0;
    int degree = 0;
    std::vector<uint64_t> breakpoints;
    std::vector<GroupElement> coefficients;
};

PublicLUTData generatePublicLUT(
    int Bin, int Bout,
    const std::function<uint64_t(uint64_t)>& generator);

void savePublicLUT(const std::string& path, const PublicLUTData& table);

PublicLUTData loadPublicLUT(const std::string& path);

PublicPiecewisePolyData makePublicPiecewisePolynomial(
    int Bin, int Bout, int scale, int degree,
    const std::vector<uint64_t>& breakpoints,
    const std::vector<GroupElement>& coefficients);

PublicPiecewisePolyData generatePublicPiecewisePolynomial(
    int Bin, int Bout, int scale, int degree,
    const std::vector<uint64_t>& breakpoints,
    const std::function<uint64_t(int, int)>& coefficient_generator);

PublicPiecewisePolyData fitPublicPiecewisePolynomialLeastSquares(
    int Bin, int Bout, int scale, int degree,
    const std::vector<uint64_t>& breakpoints,
    const std::function<double(double)>& function,
    int samples_per_segment = 0);

void savePublicPiecewisePolynomial(
    const std::string& path, const PublicPiecewisePolyData& poly);

PublicPiecewisePolyData loadPublicPiecewisePolynomial(const std::string& path);
