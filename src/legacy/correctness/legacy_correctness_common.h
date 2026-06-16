#pragma once

#include "test_common.h"

#include "legacy/cleartext.h"
#include "legacy/dcf.h"
#include "legacy/dpf.h"
#include "legacy/math.h"
#include "legacy/basic_ops.h"
#include "legacy/comparison.h"
#include "legacy/containment.h"
#include "legacy/lut.h"
#include "legacy/spline_approx.h"

inline void free_dpf_key(DPFKeyPack& key) {
    freeDPFKeyPack(key);
}

void check_dpf(ResultLog& log);
void check_dcf(ResultLog& log);
void check_legacy_comparison(ResultLog& log);
void check_legacy_modular(ResultLog& log);
void check_legacy_truncate_and_reduce(ResultLog& log);
void check_containment(ResultLog& log);
void check_legacy_public_lut(ResultLog& log);
void check_legacy_private_lut(ResultLog& log);
void check_legacy_digdec(ResultLog& log);
void check_spline_poly_approx(ResultLog& log);
void check_trigonometric(ResultLog& log);
void check_case_studies(ResultLog& log);
