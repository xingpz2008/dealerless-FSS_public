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

ComparisonKeyPack comparison_offline(int party_id, int Bin, int Bout, GroupElement c, GroupElement* payload, bool public_payload);

void comparison(int party_id, GroupElement* res, GroupElement idx, ComparisonKeyPack key);

void comparison(int party_id, GroupElement* res, GroupElement* idx, ComparisonKeyPack* KeyList,
                int size, int max_bitsize);

ModularKeyPack modular_offline(int party_id, GroupElement N, int Bout);

GroupElement modular(int party_id, GroupElement input, int N, ModularKeyPack key);

TRKeyPack truncate_and_reduce_offline(int party_id, int l, int s);

GroupElement truncate_and_reduce(int party_id, GroupElement input, int s, TRKeyPack key);

ContainmentKeyPack containment_offline(int party_id, int Bout, GroupElement* knots_list, int knots_size);

void containment(int party_id, GroupElement input, GroupElement* output, int knots_size, ContainmentKeyPack key);

DigDecKeyPack digdec_offline(int party_id, int Bin, int NewBitSize);

void digdec(int party_id, GroupElement input, GroupElement* output, int NewBitSize, DigDecKeyPack key);

DPFKeyPack pub_lut_offline(int party_id, int idx_bitlen, int lut_bitlen);

GroupElement pub_lut(int party_id, GroupElement input, GroupElement* table, GroupElement* shifted_full_domain_res,
                 int table_size, int output_bitlen, DPFKeyPack key);

PrivateLutKey pri_lut_offline(int party_id, int idx_bitlen, int lut_bitlen, GroupElement* priList);

GroupElement pri_lut(int party_id, GroupElement idx, PrivateLutKey key);

SplinePolyApproxKeyPack spline_poly_approx_offline(int party_id, int Bin, int Bout,
                                                   GroupElement* publicCoefficientList, int degree, int segNum);

GroupElement spline_poly_approx(int party_id, GroupElement input, SplinePolyApproxKeyPack key);