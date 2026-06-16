#pragma once

#include "common/test_common.h"

#include "buildingblock/comparison.h"
#include "buildingblock/digit_decomposition.h"
#include "buildingblock/equality.h"
#include "buildingblock/lut.h"
#include "buildingblock/mic.h"
#include "buildingblock/modular.h"
#include "buildingblock/ring_extension.h"
#include "buildingblock/truncation.h"
#include "fss/dpf.h"
#include "fss/fss_wrapper.h"
#include "fss/idpf.h"
#include "math/luteval.h"
#include "math/polyeval.h"

using dfss::defaultDPFETSuffixBits;
using dfss::evalAllDPF;
using dfss::evalAllCorrelatedDPF;
using dfss::evalAllDPFET;
using dfss::evalBooleanCorrelatedDPF;
using dfss::evalCorrelatedDPF;
using dfss::evalCorrelatedDPFBit;
using dfss::evalDPFET;
using dfss::evaliDPF;
using dfss::keyGenBooleanCorrelatedDPF;
using dfss::keyGenCorrelatedDPF;
using dfss::keyGenCorrelatedDPFBit;
using dfss::keyGenDPFET;
using dfss::keyGeniDPF;

inline void free_dpf_key(DPFKeyPack& key) {
    freeDPFKeyPack(key);
}

void check_correlated_dpf(ResultLog& log);
void check_boolean_correlated_dpf(ResultLog& log);
void check_idpf(ResultLog& log);
void check_dpf_et(ResultLog& log);

void check_equality(ResultLog& log);
void check_modular(ResultLog& log);
void check_truncate_and_reduce(ResultLog& log);
void check_public_lut(ResultLog& log);
void check_private_lut(ResultLog& log);
void check_digdec(ResultLog& log);
void check_mic(ResultLog& log);
void check_comparison(ResultLog& log);
void check_signed_ring_ops(ResultLog& log);
void check_public_lut_et_mode(ResultLog& log);
void check_public_lut_full_mode(ResultLog& log);
void check_mic_poly_eval(ResultLog& log);
