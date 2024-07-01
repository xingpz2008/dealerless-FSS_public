//
// Created by root on 4/16/24.
//

#include "group_element.h"
#include "2pc_api.h"
#include "utils.h"

SineKeyPack sine_offline(int party_id, int Bin, int Bout, int scale, bool using_lut,
                         int digdec_new_bitsize, int approx_segNum, int approx_deg)__attribute__((optimize("O0")));

GroupElement sine(int party_id, GroupElement input, SineKeyPack key)__attribute__((optimize("O0")));

CosineKeyPack cosine_offline(int party_id, int Bin, int Bout, int scale, bool using_lut,
                         int digdec_new_bitsize, int approx_segNum, int approx_deg);

GroupElement cosine(int party_id, GroupElement input, CosineKeyPack key);

TangentKeyPack tangent_offline(int party_id, int Bin, int Bout, int scale, bool using_lut,
                               int approx_segNum, int approx_deg);

GroupElement tangent(int party_id, GroupElement input, TangentKeyPack key);

ProximityKeyPack proximity_offline(int party_id, int Bin, int scale, bool using_lut, int digdec_new_bitsize,
                               int approx_segNum, int approx_deg)__attribute__((optimize("O0")));

GroupElement proximity(int party_id, GroupElement xA, GroupElement yA, GroupElement xB, GroupElement yB,
                       ProximityKeyPack key)__attribute__((optimize("O0")));