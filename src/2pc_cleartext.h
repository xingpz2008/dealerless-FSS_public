//
// Created by root on 4/28/24.
//
#include "group_element.h"
#include "utils.h"

GroupElement inner_product(GroupElement* A, GroupElement* B, int size, int scale);

GroupElement cleartext_sin(GroupElement input, int scale, bool using_lut)__attribute__((optimize("O0")));