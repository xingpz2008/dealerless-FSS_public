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

#include "group_element.h"
#include "2pc_api.h"
#include "utils.h"

SineKeyPack sine_offline(int party_id, int Bin, int Bout, int scale, bool using_lut,
                         int digdec_new_bitsize, int approx_segNum, int approx_deg);

GroupElement sine(int party_id, GroupElement input, const SineKeyPack& key);

CosineKeyPack cosine_offline(int party_id, int Bin, int Bout, int scale, bool using_lut,
                         int digdec_new_bitsize, int approx_segNum, int approx_deg);

GroupElement cosine(int party_id, GroupElement input, const CosineKeyPack& key);

TangentKeyPack tangent_offline(int party_id, int Bin, int Bout, int scale, bool using_lut,
                               int approx_segNum, int approx_deg);

GroupElement tangent(int party_id, GroupElement input, const TangentKeyPack& key);

ProximityKeyPack proximity_offline(int party_id, int Bin, int scale, bool using_lut, int digdec_new_bitsize,
                               int approx_segNum, int approx_deg);

GroupElement proximity(int party_id, GroupElement xA, GroupElement yA, GroupElement xB, GroupElement yB,
                       const ProximityKeyPack& key);

BiometricKeyPack biometric_offline(int party_id, int Bin, int scale, bool using_lut,
                                   int approx_segNum, int approx_deg);

void biometric(int party_id, GroupElement xA, GroupElement yA, GroupElement xB, GroupElement yB,
               GroupElement* output, const BiometricKeyPack& key);
