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
#include "commons/group_element.h"
#include "legacy/keypack.h"
#include "legacy/dpf.h"

using namespace osuCrypto;

newDCFKeyPack keyGenNewDCF(int party_id, int Bin, int Bout, GroupElement idx, GroupElement payload);

void evalNewDCF(int party, GroupElement* res, const GroupElement* idx, const newDCFKeyPack* keyList, int size, int max_bitsize);
