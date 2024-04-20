//
// Created by root on 4/16/24.
//

#include "group_element.h"
#include "2pc_api.h"
#include "utils.h"

SineKeyPack sine_offline(int party_id, int Bin, int Bout, int scale, bool using_lut,
                         int digdec_new_bitsize, int approx_segNum, int approx_deg);

GroupElement sine(int party_id, GroupElement input, SineKeyPack key);