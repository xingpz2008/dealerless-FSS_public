//
// Created by root on 3/17/23.
//
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

int bitsize = 16;
int scale = 9;
float left_pt = 0;
float right_pt = 0.5;
bool using_lut = false;

/*
MUX wrapper:

void multiplexer(int party_id, uint8_t *sel, block *dataA, block *output,
                 int32_t size, Peer* player);

void multiplexer(int party_id, uint8_t *sel, uint64_t *dataA, uint64_t *output,
                 int32_t size, int32_t bw_x, int32_t bw_y, Peer* player);

void multiplexer(int party_id, uint8_t *sel, GroupElement *dataA, GroupElement *output,
                 int32_t size, Peer* player);

void multiplexer2(int party_id, uint8_t *sel, uint64_t *dataA, uint64_t *dataB, uint64_t *output,
                  int32_t size, int32_t bw_x, int32_t bw_y, Peer* player);

void multiplexer2(int party_id, uint8_t *control_bit, osuCrypto::block* dataA, osuCrypto::block* dataB,
                          osuCrypto::block* output, int32_t size, Peer* player);

void multiplexer2(int party_id, uint8_t *control_bit, GroupElement* dataA, GroupElement* dataB,
                          GroupElement* output, int32_t size, Peer* player);

*/

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
        if (i == 40){
            int sss = 9;
        }
        GroupElement output = cleartext_sin(input, scale, using_lut);
        GroupElement lib_output = GroupElement(sin(M_PI * (value + (resolution) * i)), bitsize, scale);
        delta_ulp = abs((int)output.value - (int)lib_output.value);
        if (delta_ulp > max_delta_ulp){
            i_max = i;
            max_delta_ulp = delta_ulp;
        }
        ulp += delta_ulp;
    }

    std::cout << "Accumulated ULP error = " << ulp << " within " << test_num << " testcases, avg_ULP = " << (float)ulp / test_num << std::endl;

    // std::cout << "Value = " << output.value << " With bit size " << output.bitsize << std::endl;
    // std::cout << "Lib value = " << GroupElement(sin(M_PI * value), 16, 9).value << std::endl;
}