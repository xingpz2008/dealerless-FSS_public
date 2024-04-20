//
// Created by root on 12/6/23.
//

#include "2pc_idpf.h"
#include "2pc_dcf.h"
#include "2pcwrapper.h"
#include "assert.h"
#include "group_element.h"

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