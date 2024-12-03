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
#include "../../src/group_element.h"
#include "../../src/2pc_cleartext.h"
#include <cmath>
#define M_PI 3.14159265358979323846

using namespace sci;
using namespace std;
using namespace osuCrypto;

int party = 0;
int32_t bitlength = 32;
int num_threads = 1;
int port = 32000;
std::string address = "127.0.0.1";
int num_argmax = 1000;
uint8_t choice_bit = 0;
bool verbose = 1;
int length = 1;
Peer* client = nullptr;
Peer* server = nullptr;
Dealer* dealer = nullptr;
Peer* peer = nullptr;
extern int32_t numRounds;

int bitsize = 18;
int scale = 9;
float left_pt = 0;
float right_pt = 0.5;
bool using_lut = false;


int main(int argc, char **argv){
    float resolution = (float)1 / (1 << scale);
    float value = (float)left_pt;
    int test_num = (int)((right_pt - left_pt) / resolution);
    int ulp = 0;
    int max_delta_ulp = 0;
    int i_max = 0;
    int delta_ulp = 0;
    for (int i = 0; i < test_num; i++){
        GroupElement input(value + (resolution) * i, bitsize, scale);
        GroupElement output = cleartext_cosine(input, scale, using_lut);
        GroupElement lib_output = GroupElement(cos(M_PI * (value + (resolution) * i)), bitsize, scale);
        delta_ulp = abs((int)output.value - (int)lib_output.value);
        if (delta_ulp > max_delta_ulp){
            i_max = i;
            max_delta_ulp = delta_ulp;
        }
        ulp += delta_ulp;
    }

    std::cout << "Accumulated ULP error = " << ulp << " within " << test_num << " testcases, avg_ULP = " << (float)ulp / test_num << std::endl;

}