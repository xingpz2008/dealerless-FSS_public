#include "commons/public_data.h"

#include <algorithm>
#include <cmath>
#include <fstream>
#include <stdexcept>

namespace {

constexpr uint64_t kPublicLUTMagic = 0x54464c4255504644ULL; // DF-PUBLT
constexpr uint64_t kPublicLUTVersion = 1;
constexpr uint64_t kPublicPolyMagic = 0x594c4f5042555044ULL; // DF-PUBPOLY
constexpr uint64_t kPublicPolyVersion = 1;

uint64_t checkedEntryCount(int Bin) {
    if (Bin < 0 || Bin >= 63) {
        throw std::invalid_argument("Public LUT requires 0 <= Bin < 63");
    }
    return uint64_t(1) << Bin;
}

void writeU64(std::ofstream& out, uint64_t value) {
    out.write(reinterpret_cast<const char*>(&value), sizeof(value));
    if (!out) {
        throw std::runtime_error("Failed to write public LUT data");
    }
}

uint64_t readU64(std::ifstream& in) {
    uint64_t value = 0;
    in.read(reinterpret_cast<char*>(&value), sizeof(value));
    if (!in) {
        throw std::runtime_error("Failed to read public LUT data");
    }
    return value;
}

}  // namespace

PublicLUTData generatePublicLUT(
    int Bin, int Bout,
    const std::function<uint64_t(uint64_t)>& generator) {
    if (Bout <= 0 || Bout > 64) {
        throw std::invalid_argument("Public LUT requires 0 < Bout <= 64");
    }
    const uint64_t entry_count = checkedEntryCount(Bin);
    PublicLUTData table;
    table.Bin = Bin;
    table.Bout = Bout;
    table.values.resize(static_cast<size_t>(entry_count));
    for (uint64_t i = 0; i < entry_count; i++) {
        table.values[static_cast<size_t>(i)] =
            GroupElement(generator(i), Bout);
    }
    return table;
}

void savePublicLUT(const std::string& path, const PublicLUTData& table) {
    const uint64_t entry_count = checkedEntryCount(table.Bin);
    if (table.Bout <= 0 || table.Bout > 64) {
        throw std::invalid_argument("Public LUT requires 0 < Bout <= 64");
    }
    if (table.values.size() != static_cast<size_t>(entry_count)) {
        throw std::invalid_argument("Public LUT entry count does not match Bin");
    }

    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        throw std::runtime_error("Failed to open public LUT file for writing");
    }

    writeU64(out, kPublicLUTMagic);
    writeU64(out, kPublicLUTVersion);
    writeU64(out, static_cast<uint64_t>(table.Bin));
    writeU64(out, static_cast<uint64_t>(table.Bout));
    writeU64(out, entry_count);
    for (const GroupElement& value : table.values) {
        GroupElement normalized(value.value, table.Bout);
        writeU64(out, normalized.value);
    }
}

PublicLUTData loadPublicLUT(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("Failed to open public LUT file for reading");
    }

    const uint64_t magic = readU64(in);
    const uint64_t version = readU64(in);
    if (magic != kPublicLUTMagic || version != kPublicLUTVersion) {
        throw std::runtime_error("Invalid public LUT file header");
    }

    const int Bin = static_cast<int>(readU64(in));
    const int Bout = static_cast<int>(readU64(in));
    const uint64_t entry_count = readU64(in);
    if (entry_count != checkedEntryCount(Bin)) {
        throw std::runtime_error("Public LUT file entry count does not match Bin");
    }
    if (Bout <= 0 || Bout > 64) {
        throw std::runtime_error("Public LUT file has invalid Bout");
    }

    PublicLUTData table;
    table.Bin = Bin;
    table.Bout = Bout;
    table.values.resize(static_cast<size_t>(entry_count));
    for (uint64_t i = 0; i < entry_count; i++) {
        table.values[static_cast<size_t>(i)] =
            GroupElement(readU64(in), Bout);
    }
    return table;
}

namespace {

void validatePiecewisePolynomial(const PublicPiecewisePolyData& poly) {
    checkedEntryCount(poly.Bin);
    if (poly.Bout <= 0 || poly.Bout > 64) {
        throw std::invalid_argument(
            "Public piecewise polynomial requires 0 < Bout <= 64");
    }
    if (poly.scale < 0 || poly.degree < 0) {
        throw std::invalid_argument(
            "Public piecewise polynomial requires nonnegative scale and degree");
    }
    if (poly.breakpoints.size() < 2) {
        throw std::invalid_argument(
            "Public piecewise polynomial requires at least one segment");
    }
    if (poly.breakpoints.front() != 0 ||
        poly.breakpoints.back() != (uint64_t(1) << poly.Bin)) {
        throw std::invalid_argument(
            "Public piecewise polynomial breakpoints must cover [0, 2^Bin)");
    }
    for (size_t i = 1; i < poly.breakpoints.size(); i++) {
        if (poly.breakpoints[i - 1] >= poly.breakpoints[i]) {
            throw std::invalid_argument(
                "Public piecewise polynomial breakpoints must be increasing");
        }
    }
    const size_t segment_count = poly.breakpoints.size() - 1;
    const size_t expected_coefficients =
        segment_count * static_cast<size_t>(poly.degree + 1);
    if (poly.coefficients.size() != expected_coefficients) {
        throw std::invalid_argument(
            "Public piecewise polynomial coefficient count mismatch");
    }
}

int64_t signedFromTwosPublic(uint64_t value, int bits) {
    if (bits == 64) {
        return static_cast<int64_t>(value);
    }
    const uint64_t sign_bit = uint64_t(1) << (bits - 1);
    const uint64_t modulus = uint64_t(1) << bits;
    if ((value & sign_bit) == 0) {
        return static_cast<int64_t>(value);
    }
    return static_cast<int64_t>(value) - static_cast<int64_t>(modulus);
}

uint64_t twosFromSignedPublic(int64_t value, int bits) {
    if (bits == 64) {
        return static_cast<uint64_t>(value);
    }
    return static_cast<uint64_t>(value) & ((uint64_t(1) << bits) - 1);
}

std::vector<long double> solveLinearSystem(
    std::vector<std::vector<long double>> matrix,
    std::vector<long double> rhs) {
    const int n = static_cast<int>(rhs.size());
    for (int col = 0; col < n; col++) {
        int pivot = col;
        for (int row = col + 1; row < n; row++) {
            if (std::fabs(matrix[row][col]) >
                std::fabs(matrix[pivot][col])) {
                pivot = row;
            }
        }
        if (std::fabs(matrix[pivot][col]) < 1e-24L) {
            throw std::runtime_error("Polynomial fitting matrix is singular");
        }
        if (pivot != col) {
            std::swap(matrix[pivot], matrix[col]);
            std::swap(rhs[pivot], rhs[col]);
        }
        const long double divisor = matrix[col][col];
        for (int j = col; j < n; j++) {
            matrix[col][j] /= divisor;
        }
        rhs[col] /= divisor;
        for (int row = 0; row < n; row++) {
            if (row == col) {
                continue;
            }
            const long double factor = matrix[row][col];
            for (int j = col; j < n; j++) {
                matrix[row][j] -= factor * matrix[col][j];
            }
            rhs[row] -= factor * rhs[col];
        }
    }
    return rhs;
}

}  // namespace

PublicPiecewisePolyData makePublicPiecewisePolynomial(
    int Bin, int Bout, int scale, int degree,
    const std::vector<uint64_t>& breakpoints,
    const std::vector<GroupElement>& coefficients) {
    PublicPiecewisePolyData poly;
    poly.Bin = Bin;
    poly.Bout = Bout;
    poly.scale = scale;
    poly.degree = degree;
    poly.breakpoints = breakpoints;
    poly.coefficients = coefficients;
    for (GroupElement& coefficient : poly.coefficients) {
        coefficient = GroupElement(coefficient.value, Bout);
    }
    validatePiecewisePolynomial(poly);
    return poly;
}

PublicPiecewisePolyData generatePublicPiecewisePolynomial(
    int Bin, int Bout, int scale, int degree,
    const std::vector<uint64_t>& breakpoints,
    const std::function<uint64_t(int, int)>& coefficient_generator) {
    if (breakpoints.size() < 2) {
        throw std::invalid_argument(
            "Public piecewise polynomial requires at least one segment");
    }
    const int segment_count = static_cast<int>(breakpoints.size()) - 1;
    std::vector<GroupElement> coefficients(
        static_cast<size_t>(segment_count) * static_cast<size_t>(degree + 1));
    for (int m = 0; m < segment_count; m++) {
        for (int i = 0; i <= degree; i++) {
            coefficients[static_cast<size_t>(m * (degree + 1) + i)] =
                GroupElement(coefficient_generator(m, i), Bout);
        }
    }
    return makePublicPiecewisePolynomial(
        Bin, Bout, scale, degree, breakpoints, coefficients);
}

PublicPiecewisePolyData fitPublicPiecewisePolynomialLeastSquares(
    int Bin, int Bout, int scale, int degree,
    const std::vector<uint64_t>& breakpoints,
    const std::function<double(double)>& function,
    int samples_per_segment) {
    if (degree < 0 || scale < 0) {
        throw std::invalid_argument(
            "Polynomial fitting requires nonnegative degree and scale");
    }
    if (samples_per_segment != 0 && samples_per_segment < degree + 1) {
        throw std::invalid_argument(
            "Polynomial fitting needs at least degree + 1 samples per segment");
    }

    const int segment_count = static_cast<int>(breakpoints.size()) - 1;
    const int coefficient_count = degree + 1;
    std::vector<GroupElement> coefficients(
        static_cast<size_t>(segment_count * coefficient_count));
    const long double scale_factor =
        static_cast<long double>(uint64_t(1) << scale);

    for (int m = 0; m < segment_count; m++) {
        const uint64_t left = breakpoints[m];
        const uint64_t right = breakpoints[m + 1];
        const uint64_t width = right - left;
        const int sample_count =
            samples_per_segment > 0
                ? samples_per_segment
                : static_cast<int>(std::max<uint64_t>(
                      static_cast<uint64_t>(degree + 1),
                      std::min<uint64_t>(width, 64)));

        std::vector<std::vector<long double>> normal(
            coefficient_count,
            std::vector<long double>(coefficient_count, 0));
        std::vector<long double> rhs(coefficient_count, 0);

        for (int s = 0; s < sample_count; s++) {
            uint64_t encoded_x = left;
            if (sample_count == 1) {
                encoded_x = left;
            } else {
                encoded_x = left +
                            (width - 1) * static_cast<uint64_t>(s) /
                                static_cast<uint64_t>(sample_count - 1);
            }
            const long double x =
                static_cast<long double>(signedFromTwosPublic(encoded_x, Bin)) /
                scale_factor;
            const long double y = static_cast<long double>(
                function(static_cast<double>(x)));

            std::vector<long double> powers(2 * degree + 1, 1);
            for (int i = 1; i <= 2 * degree; i++) {
                powers[i] = powers[i - 1] * x;
            }
            for (int row = 0; row <= degree; row++) {
                rhs[row] += y * powers[row];
                for (int col = 0; col <= degree; col++) {
                    normal[row][col] += powers[row + col];
                }
            }
        }

        const std::vector<long double> fitted =
            solveLinearSystem(normal, rhs);
        for (int i = 0; i <= degree; i++) {
            const long double scaled = std::floor(fitted[i] * scale_factor);
            const int64_t encoded = static_cast<int64_t>(scaled);
            coefficients[static_cast<size_t>(m * coefficient_count + i)] =
                GroupElement(twosFromSignedPublic(encoded, Bout), Bout);
        }
    }

    return makePublicPiecewisePolynomial(
        Bin, Bout, scale, degree, breakpoints, coefficients);
}

void savePublicPiecewisePolynomial(
    const std::string& path, const PublicPiecewisePolyData& poly) {
    validatePiecewisePolynomial(poly);
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        throw std::runtime_error(
            "Failed to open public polynomial file for writing");
    }

    writeU64(out, kPublicPolyMagic);
    writeU64(out, kPublicPolyVersion);
    writeU64(out, static_cast<uint64_t>(poly.Bin));
    writeU64(out, static_cast<uint64_t>(poly.Bout));
    writeU64(out, static_cast<uint64_t>(poly.scale));
    writeU64(out, static_cast<uint64_t>(poly.degree));
    writeU64(out, static_cast<uint64_t>(poly.breakpoints.size() - 1));
    for (uint64_t breakpoint : poly.breakpoints) {
        writeU64(out, breakpoint);
    }
    for (const GroupElement& coefficient : poly.coefficients) {
        GroupElement normalized(coefficient.value, poly.Bout);
        writeU64(out, normalized.value);
    }
}

PublicPiecewisePolyData loadPublicPiecewisePolynomial(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error(
            "Failed to open public polynomial file for reading");
    }

    const uint64_t magic = readU64(in);
    const uint64_t version = readU64(in);
    if (magic != kPublicPolyMagic || version != kPublicPolyVersion) {
        throw std::runtime_error("Invalid public polynomial file header");
    }

    PublicPiecewisePolyData poly;
    poly.Bin = static_cast<int>(readU64(in));
    poly.Bout = static_cast<int>(readU64(in));
    poly.scale = static_cast<int>(readU64(in));
    poly.degree = static_cast<int>(readU64(in));
    const uint64_t segment_count = readU64(in);
    poly.breakpoints.resize(static_cast<size_t>(segment_count + 1));
    for (uint64_t i = 0; i <= segment_count; i++) {
        poly.breakpoints[static_cast<size_t>(i)] = readU64(in);
    }
    poly.coefficients.resize(
        static_cast<size_t>(segment_count) *
        static_cast<size_t>(poly.degree + 1));
    for (GroupElement& coefficient : poly.coefficients) {
        coefficient = GroupElement(readU64(in), poly.Bout);
    }
    validatePiecewisePolynomial(poly);
    return poly;
}
