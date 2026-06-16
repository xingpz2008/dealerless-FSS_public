#pragma once

#include <cryptoTools/Common/Defines.h>
#include <vector>

#include "commons/types.h"
#include "commons/group_element.h"
#include "commons/keypack.h"

namespace dfss {

namespace wrapper {

// Shared-input FSS adaptation. These APIs take arithmetic shares as input,
// handle BitDec/masks locally, and dispatch to FSS core APIs.
struct DPFOptions {
    bool masked = true;
    bool correlated = true;
    // -1: no early termination; -2: use default suffix; >=0: explicit suffix.
    int earlyTerminationSuffixBits = -1;
};

DPFKeyPack keyGenDPF(int party_id, GroupElement input, GroupElement beta,
                     DPFOptions options = {});

DPFKeyPack keyGenDPF(int party_id, int Bin, const BooleanElement* input_bits,
                     GroupElement beta, DPFOptions options = {});

DPFKeyPack keyGenDPF(int party_id, GroupElement input, GroupElement beta,
                     bool earlyTermination);

DPFKeyPack keyGenDPF(int party_id, GroupElement input, GroupElement beta,
                     int suffixBits);

GroupElement evalDPF(int party_id, GroupElement input, const DPFKeyPack& key,
                     DPFOptions options = {});

GroupElement evalDPF(int party_id, const BooleanElement* input_bits,
                     const DPFKeyPack& key, DPFOptions options = {});

void evalDPF(int party_id, GroupElement* output, GroupElement input,
             const DPFKeyPack& key, DPFOptions options = {});

void evalDPF(int party_id, GroupElement* output,
             const BooleanElement* input_bits, const DPFKeyPack& key,
             DPFOptions options = {});

void evalAllDPF(int party_id, GroupElement* output, const DPFKeyPack& key);

DPFKeyPack keyGenDPF(int party_id, GroupElement input, bool masked = true);

DPFKeyPack keyGenDPF(int party_id, int Bin, const BooleanElement* input_bits,
                     bool masked = true);

BooleanElement evalDPFBit(int party_id, GroupElement input,
                          const DPFKeyPack& key, bool masked = true);

BooleanElement evalDPFBit(int party_id, const BooleanElement* input_bits,
                          const DPFKeyPack& key, bool masked = true);

BooleanDPFKeyPack keyGenDPF(int party_id, GroupElement input,
                            osuCrypto::block beta, bool masked = true);

BooleanDPFKeyPack keyGenDPF(int party_id, int Bin,
                            const BooleanElement* input_bits,
                            osuCrypto::block beta, bool masked = true);

osuCrypto::block evalDPFBlock(int party_id, GroupElement input,
                              const BooleanDPFKeyPack& key,
                              bool masked = true);

osuCrypto::block evalDPFBlock(int party_id, const BooleanElement* input_bits,
                              const BooleanDPFKeyPack& key,
                              bool masked = true);

DPFKeyPack keyGeniDPF(int party_id, GroupElement input,
                      const GroupElement* beta_per_level,
                      bool masked = false);

DPFKeyPack keyGeniDPF(int party_id, GroupElement input, bool masked = false);

DPFKeyPack keyGenRandomDPF(int party_id, int Bin, GroupElement beta,
                           GroupElement* random_target_share,
                           DPFOptions options = {});

DPFKeyPack keyGenRandomiDPF(int party_id, int Bin,
                            const GroupElement* beta_per_level,
                            GroupElement* random_target_share);

DPFKeyPack keyGenRandomiDPF(int party_id, int Bin,
                            GroupElement* random_target_share);

}  // namespace wrapper

// Compatibility aliases used during migration. New code should prefer the
// dfss::wrapper namespace above.
DPFKeyPack keyGenArithmeticDPF(int party_id, GroupElement input,
                               GroupElement beta, bool correlated = true,
                               bool masked = true);

DPFKeyPack keyGenCorrelatedDPF(int party_id, int Bin, int Bout,
                               GroupElement input, GroupElement beta,
                               bool masked = true);

void evalArithmeticDPF(int party_id, GroupElement* output,
                       GroupElement input, const DPFKeyPack& key,
                       bool correlated = true, bool masked = true);

GroupElement evalArithmeticDPF(int party_id, GroupElement input,
                               const DPFKeyPack& key,
                               bool correlated = true,
                               bool masked = true);

void evalCorrelatedDPF(int party_id, GroupElement* output,
                       GroupElement input, const DPFKeyPack& key,
                       bool masked = true);

GroupElement evalCorrelatedDPF(int party_id, GroupElement input,
                               const DPFKeyPack& key, bool masked);

DPFKeyPack keyGenCorrelatedDPFBit(int party_id, GroupElement input,
                                  bool masked = true);

DPFKeyPack keyGenCorrelatedDPFBit(int party_id, int Bin,
                                  GroupElement input, bool masked = true);

BooleanElement evalCorrelatedDPFBit(int party_id, GroupElement input,
                                    const DPFKeyPack& key,
                                    bool masked);

BooleanDPFKeyPack keyGenBooleanCorrelatedDPF(
    int party_id, GroupElement input, osuCrypto::block beta,
    bool masked = true);

BooleanDPFKeyPack keyGenBooleanCorrelatedDPF(
    int party_id, int Bin, GroupElement input, osuCrypto::block beta,
    bool masked = true);

osuCrypto::block evalBooleanCorrelatedDPF(
    int party_id, GroupElement input, const BooleanDPFKeyPack& key,
    bool masked);

void evalBooleanCorrelatedDPF(
    int party_id, osuCrypto::block* output, GroupElement input,
    const BooleanDPFKeyPack& key, bool masked);

DPFKeyPack keyGeniDPF(int party_id, GroupElement input,
                      const GroupElement* beta_per_level,
                      bool masked = false);

DPFKeyPack keyGeniDPF(int party_id, int Bin, int Bout, GroupElement input,
                      const GroupElement* beta_per_level,
                      bool call_from_DCF = false, bool masked = false);

std::vector<GroupElement> evaliDPF(int party_id, GroupElement input,
                                   const DPFKeyPack& key,
                                   bool masked);

int defaultDPFETSuffixBits(int Bin, int Bout, int lambdaBits = 128);

DPFKeyPack keyGenDPFET(int party_id, int Bin, int Bout, GroupElement input,
                       GroupElement beta, int lambdaBits = 128);

DPFKeyPack keyGenDPFET(int party_id, int Bin, int Bout, int suffixBits,
                       GroupElement input, GroupElement beta);

void evalDPFET(int party_id, GroupElement* output, uint64_t public_x,
               const DPFKeyPack& key);

GroupElement evalDPFET(int party_id, uint64_t public_x,
                       const DPFKeyPack& key);

void evalAllDPFET(int party_id, GroupElement* output, const DPFKeyPack& key);

}  // namespace dfss
