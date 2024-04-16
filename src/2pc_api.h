//
// Created by root on 12/6/23.
//

#include "2pc_idpf.h"
#include "2pc_dcf.h"
#include "2pcwrapper.h"
#include "assert.h"
#include "group_element.h"

ModularKeyPack modular_offline(int party_id, GroupElement N, GroupElement* res);

GroupElement modular(int party_id, GroupElement input, int N, ModularKeyPack key);

TRKeyPack truncate_and_reduce_offline(int party_id, int l, int s);

GroupElement truncate_and_reduce(int party_id, GroupElement input, int s, TRKeyPack key);

ContainmentKeyPack containment_offline(int party_id, GroupElement* knots_list, int knots_size);

void containment(int party_id, GroupElement input, GroupElement* output, int knots_size, ContainmentKeyPack key);

DigDecKeyPack digdec_offline(int party_id, int Bin, int NewBitSize);

void digdec(int party_id, GroupElement input, GroupElement* output, int NewBitSize, DigDecKeyPack key);

DPFKeyPack lut_offline(int party_id,int table_size, int idx_bitlen, int lut_bitlen);

GroupElement lut(int party_id, GroupElement input, GroupElement* table, int table_size, int output_bitlen, DPFKeyPack key);

SplinePolyApproxKeyPack spline_poly_approx_offline(int party_id, int Bin, int Bout,
                                                   GroupElement* publicCoefficientList, int degree, int segNum);

void spline_poly_approx(int party_id, GroupElement input, GroupElement* output, SplinePolyApproxKeyPack key);