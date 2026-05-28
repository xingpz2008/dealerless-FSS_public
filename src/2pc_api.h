#pragma once

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
#include "2pc_idpf.h"
#include "2pc_dcf.h"
#include "2pcwrapper.h"
#include "assert.h"
#include "group_element.h"

ComparisonKeyPack comparison_offline(int party_id, int Bin, int Bout, GroupElement c, const GroupElement& payload, bool public_payload);

ComparisonKeyPack comparison_offline(int party_id, int Bin, int Bout, GroupElement c, const GroupElement* payload, bool public_payload);

void comparison(int party_id, GroupElement* res, GroupElement idx, const ComparisonKeyPack& key);

GroupElement comparison(int party_id, GroupElement idx, const ComparisonKeyPack& key);

void comparison(int party_id, GroupElement* res, const GroupElement* idx, const ComparisonKeyPack* KeyList,
                int size, int max_bitsize);

[[deprecated("Use ring_extend with an offline ComparisonKeyPack; zero_extend performs direct online MILL/B2A.")]]
GroupElement zero_extend(int party_id, GroupElement input, int output_bits);

ComparisonKeyPack ring_extend_offline(int party_id, int input_bits, int output_bits);

GroupElement ring_extend(int party_id, GroupElement input, int output_bits,
                         const ComparisonKeyPack& key);

ModularKeyPack modular_offline(int party_id, GroupElement N, int Bout);

GroupElement modular(int party_id, GroupElement input, int N, const ModularKeyPack& key);

TRKeyPack truncate_and_reduce_offline(int party_id, int l, int s);

GroupElement truncate_and_reduce(int party_id, GroupElement input, int s, const TRKeyPack& key);

ContainmentKeyPack containment_offline(int party_id, int Bout, const GroupElement* knots_list, int knots_size);

ContainmentKeyPack containment_offline_public(int party_id, int Bout, const GroupElement* knots_list, int knots_size);

void containment(int party_id, GroupElement input, GroupElement* output, int knots_size, const ContainmentKeyPack& key);

DigDecKeyPack digdec_offline(int party_id, int Bin, int NewBitSize);

void digdec(int party_id, GroupElement input, GroupElement* output, int NewBitSize, const DigDecKeyPack& key);

DPFKeyPack pub_lut_offline(int party_id, int idx_bitlen, int lut_bitlen);

GroupElement pub_lut(int party_id, GroupElement input, const GroupElement* table, GroupElement* shifted_full_domain_res,
                 int table_size, int output_bitlen, const DPFKeyPack& key);

PrivateLutKey pri_lut_offline(int party_id, int idx_bitlen, int lut_bitlen, const GroupElement* priList);

GroupElement pri_lut(int party_id, GroupElement idx, const PrivateLutKey& key);

SplinePolyApproxKeyPack spline_poly_approx_offline(int party_id, int Bin, int Bout,
                                                   const GroupElement* publicCoefficientList, int degree,
                                                   int segNum, int fixed_scale = 0);

GroupElement spline_poly_approx(int party_id, GroupElement input, const SplinePolyApproxKeyPack& key);

[[deprecated("Legacy performance baseline only: fixed-point masked Approx is not correctness-safe.")]]
SplinePolyApproxKeyPack spline_poly_approx_offline_legacy_no_online_beaver(
    int party_id, int Bin, int Bout, const GroupElement* publicCoefficientList,
    int degree, int segNum, int fixed_scale = 0);

[[deprecated("Legacy performance baseline only: fixed-point masked Approx is not correctness-safe.")]]
GroupElement spline_poly_approx_legacy_no_online_beaver(
    int party_id, GroupElement input, const SplinePolyApproxKeyPack& key);
