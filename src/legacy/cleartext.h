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
#include "commons/group_element.h"
#include "legacy/utils.h"
#include <cassert>
#include <time.h>
#include <cmath>
#define M_PI 3.14159265358979323846

GroupElement inner_product(const GroupElement* A, const GroupElement* B, int size, int scale);

GroupElement cleartext_sin(GroupElement input, int scale, bool using_lut);

GroupElement cleartext_cosine(GroupElement input, int scale, bool using_lut);

GroupElement cleartext_tangent(GroupElement input, int scale, bool using_lut);

int cleartext_proximity(GroupElement xA, GroupElement yA, GroupElement xB, GroupElement yB,
                                 int scale, bool using_lut);

int cleartext_biometric(GroupElement xA, GroupElement yA, GroupElement xB, GroupElement yB,
                        int scale, bool using_lut);
