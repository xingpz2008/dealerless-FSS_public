#pragma once

#include <cryptoTools/Common/Defines.h>

#include "commons/types.h"
#include "commons/group_element.h"
#include "commons/keypack.h"

namespace dfss {

// Ordinary full-GGM DPF key generation with Boolean-shared target bits supplied
// by the caller. This is the mask-free FSS-core form of the pre-refactor DPF.
DPFKeyPack keyGenDPF(int party_id, int Bin, int Bout,
                     const BooleanElement* alpha_bits, GroupElement beta);

// Correlated DPF key generation with Boolean-shared target bits supplied by
// the caller. This FSS-level entry point does not run BitDec or create masks.
DPFKeyPack keyGenCorrelatedDPF(int party_id, int Bin, int Bout,
                               const BooleanElement* alpha_bits,
                               GroupElement beta);

// Boolean 0/1 output variant of correlated DPF. The output is XOR shared.
DPFKeyPack keyGenCorrelatedDPFBit(int party_id, int Bin,
                                  const BooleanElement* alpha_bits);

// Block/XOR-output variant of correlated DPF.
BooleanDPFKeyPack keyGenBooleanCorrelatedDPF(
    int party_id, int Bin, const BooleanElement* alpha_bits,
                               osuCrypto::block beta);

GroupElement evalDPF(int party_id, GroupElement public_x,
                     const DPFKeyPack& key);

GroupElement evalCorrelatedDPF(int party_id, GroupElement public_x,
                               const DPFKeyPack& key);

BooleanElement evalCorrelatedDPFBit(int party_id, GroupElement public_x,
                                    const DPFKeyPack& key);

osuCrypto::block evalBooleanCorrelatedDPF(int party_id, GroupElement public_x,
                                          const BooleanDPFKeyPack& key);

void evalAllCorrelatedDPF(int party_id, GroupElement* output,
                          const DPFKeyPack& key, int length);
void evalAllDPF(int party_id, GroupElement* output, const DPFKeyPack& key);

int defaultETSuffixBits(int Bin, int Bout, int lambdaBits = 128);

DPFKeyPack keyGenET(int party_id, int Bin, int Bout,
                    const BooleanElement* alpha_bits, GroupElement beta,
                    int lambdaBits = 128);

DPFKeyPack keyGenET(int party_id, int Bin, int Bout, int suffixBits,
                    const BooleanElement* alpha_bits, GroupElement beta);

void evalET(int party_id, GroupElement* output, uint64_t public_x,
            const DPFKeyPack& key);

GroupElement evalET(int party_id, uint64_t public_x, const DPFKeyPack& key);

void evalAllET(int party_id, GroupElement* output, const DPFKeyPack& key);

}  // namespace dfss
