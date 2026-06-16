/*
Original Authors: Deepak Kumaraswamy, Kanav Gupta
Modified by: Pengzhi Xing
Copyright:
Original Copyright (c) 2022 Microsoft Research
Copyright (c) 2024 Pengzhi Xing
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#pragma once

#include "commons/group_element.h"
#include <cmath>

#define M_PI 3.14159265358979323846

int64_t getSignedValue(GroupElement x);

int fixed_point_approx_eval_bits(int output_bits, int scale);

void create_approx_spline(int uuid, int bitsize, int scale, GroupElement* coefficientList);

void create_sub_lut(int function, int Bin, int Bout, int scale, int segNum, GroupElement** lut);

int randint_range(int n,int m);

float decode_from_ge_binary(GroupElement x, int bitlen, int scale);

uint64_t encode_to_ge_binary(float x, int bitlen, int scale);

int get_ulp(GroupElement x, GroupElement y);
