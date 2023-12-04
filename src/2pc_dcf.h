//
// Created by  邢鹏志 on 2023/1/31.
//

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

// extern uint64_t aes_evals_count;


iDCFKeyPack keyGeniDCF(int party_id, int Bin, int Bout, GroupElement idx, GroupElement* payload)
__attribute__((optimize("O0")));

void evaliDCFNext(int party, uint64_t idx, block* st_s, u8* st_t, block* cw, u8* t_l, u8* t_r,
                  const GroupElement W_cw, block* res_s, u8* res_t, GroupElement* y)
                  __attribute__((optimize("O0")));

void evaliDCF(int party, GroupElement *res, GroupElement idx, const iDCFKeyPack key)
                    __attribute__((optimize("O0")));

