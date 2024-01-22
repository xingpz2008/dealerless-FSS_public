//
// Created by root on 12/6/23.
//

#include "2pc_idpf.h"
#include "2pc_dcf.h"
#include "2pcwrapper.h"
#include "assert.h"

ModularKeyPack modular_offline(int party_id, GroupElement N, GroupElement* res);

GroupElement modular(int party_id, GroupElement input, int N, ModularKeyPack key);