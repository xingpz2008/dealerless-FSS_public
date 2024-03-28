//
// Created by root on 12/6/23.
//

#include "2pc_idpf.h"
#include "2pc_dcf.h"
#include "2pcwrapper.h"
#include "assert.h"

ModularKeyPack modular_offline(int party_id, GroupElement N, GroupElement* res);

GroupElement modular(int party_id, GroupElement input, int N, ModularKeyPack key);

TRKeyPack truncate_and_reduce_offline(int party_id, int l, int s);

GroupElement truncate_and_reduce(int party_id, GroupElement input, int s, TRKeyPack key);

ContainmentKeyPack containment_offline(int party_id, GroupElement* knots_list, int knots_size);

void containment(int party_id, GroupElement input, GroupElement* output, int knots_size, ContainmentKeyPack key);

DigDecKeyPack digdec_offline(int party_id, int Bin, int NewBitSize);

void digdec(int party_id, GroupElement input, GroupElement* output, int NewBitSize, DigDecKeyPack key);
