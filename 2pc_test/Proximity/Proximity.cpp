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
    float value = 0.43;
    GroupElement input(value, 16, 9);
    GroupElement output = cleartext_sin(input, 9, true);
    std::cout << "Value = " << output.value << " With bit size " << output.bitsize << std::endl;
    std::cout << "Lib value = " << GroupElement(sin(M_PI * value), 16, 9).value << std::endl;
}