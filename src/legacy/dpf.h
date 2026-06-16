/*
 * Description: Refer to README.md
 * Author: Pengzhi Xing
 * Email: p.xing@std.uestc.edu.cn
 * Last Modified: 2024-12-02
 * License: Apache-2.0 License
 * Copyright (c) 2024 Pengzhi Xing
 * Usage:
 * Example:
 *
 * Change Log:
 * 2024-12-02 - Initial version of the authentication module
 */
#pragma once
#include <array>
#include <vector>
#include <utility>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/AES.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/gsl/span>
#include <cmath>
#include "commons/group_element.h"
#include "commons/keypack.h"
#include "mpc/comms.h"
#include "mpc/api.h"
#include "mpc/secure_ops.h"

using namespace osuCrypto;

inline u8 lsb(const block &b)
{
    return _mm_cvtsi128_si64x(b) & 1;
}

// PRG output conversion helpers used by legacy DPF/DCF key generation.
void two_pc_convert(int bitsize, const block& b, uint64_t *out, block* out_s);
void two_pc_convert(int bitsize, int groupSize, const block& b, uint64_t *out);

// Legacy dealerless DPF: one shared point, one arithmetic payload.
DPFKeyPack keyGenDPF(int party_id, int Bin, int Bout,
                     GroupElement idx, GroupElement payload, bool masked = true);

// Point evaluation APIs. Overloads returning a value are thin convenience
// wrappers over the pointer-output forms used by legacy code.
void evalDPF(int party, GroupElement *res, GroupElement idx, const DPFKeyPack &key, bool masked = true);
GroupElement evalDPF(int party, GroupElement idx, const DPFKeyPack &key, bool masked = true);

// Batched point evaluation with constant rounds, masked.
void evalDPF(int party, GroupElement *res, GroupElement *idx, const DPFKeyPack *keyList, int size, int max_bitsize);

// Full-domain evaluation APIs. Use point/batch evaluation for large domains.
void evalAll(int party, GroupElement* res, const DPFKeyPack& key, int length);
