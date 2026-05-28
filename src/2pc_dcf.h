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
#include "group_element.h"
#include "keypack.h"
#include "2pc_idpf.h"

using namespace osuCrypto;

[[deprecated("Legacy incorrect iDCF path: do not use for correctness-sensitive code.")]]
iDCFKeyPack keyGeniDCF(int party_id, int Bin, int Bout, GroupElement idx, const GroupElement& payload, bool masked = true);

newDCFKeyPack keyGenNewDCF(int party_id, int Bin, int Bout, GroupElement idx, GroupElement payload);

[[deprecated("Legacy incorrect iDCF path: do not use for correctness-sensitive code.")]]
void evaliDCFNext(int party, uint64_t idx, block* st_s, u8* st_t, block* cw, u8* t_l, u8* t_r,
                  const GroupElement W_cw, block* res_s, u8* res_t, GroupElement* y);

[[deprecated("Legacy incorrect iDCF path: do not use for correctness-sensitive code.")]]
void evaliDCF(int party, GroupElement *res, GroupElement idx, const iDCFKeyPack& key, bool masked);

[[deprecated("Legacy incorrect iDCF path: do not use for correctness-sensitive code.")]]
void evaliDCF(int party, GroupElement *res, GroupElement idx, const iDCFKeyPack& key);

[[deprecated("Legacy incorrect iDCF path: do not use for correctness-sensitive code.")]]
void evaliDCF(int party, GroupElement* res, const GroupElement* idx, const iDCFKeyPack* keyList, int size, int max_bitsize);

void evalNewDCF(int party, GroupElement* res, const GroupElement* idx, const newDCFKeyPack* keyList, int size, int max_bitsize);
