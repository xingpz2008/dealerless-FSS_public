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
#include "../../src/2pc_math.h"
#include "../../src/utils.h"
#include <cmath>
#include <ctime>
#define M_PI 3.14159265358979323846

using namespace sci;
using namespace std;
using namespace osuCrypto;
using namespace chrono;

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

int bitsize = 8;
int scale = 5;
float left_pt = 0;
float right_pt = 0.5;
bool using_lut = false;


// Note: CASE_STUDIES Test can be formulated as:
// delta = sin^2 pi [(xA-xB)/2] + cos pi xA * cos pi xB * sin^2 pi [(yA-yB)/2]



int main(int argc, char **argv){
    ArgMapping amap;
    amap.arg("r", party, "Role of party: ALICE = 1; BOB = 2");
    amap.arg("p", port, "Port Number");
    amap.parse(argc, argv);

    srand((unsigned)time(NULL));
    float resolution = (float)1 / (1 << scale);
    float value = (float)left_pt;
    int test_num = (int)((right_pt - left_pt) / resolution);
    int ulp = 0;
    int max_delta_ulp = 0;
    int i_max = 0;
    int delta_ulp = 0;
    for (int i = 0; i < test_num; i++){
        GroupElement xA(randint_range(0, encode_to_ge_binary(right_pt, bitsize, scale)), bitsize);
        GroupElement xB(randint_range(0, encode_to_ge_binary(right_pt, bitsize, scale)), bitsize);
        GroupElement yA(randint_range(0, encode_to_ge_binary(right_pt, bitsize, scale)), bitsize);
        GroupElement yB(randint_range(0, encode_to_ge_binary(right_pt, bitsize, scale)), bitsize);

        float real_xA = decode_from_ge_binary(xA, bitsize, scale);
        float real_xB = decode_from_ge_binary(xB, bitsize, scale);
        float real_yA = decode_from_ge_binary(yA, bitsize, scale);
        float real_yB = decode_from_ge_binary(yB, bitsize, scale);

        // Wrapper: GroupElement cleartext_proximity(GroupElement xA, GroupElement yA, GroupElement xB, GroupElement yB, ...)
        delta_ulp = cleartext_proximity(xA, yA, xB, yB, scale, using_lut);
        if (delta_ulp > max_delta_ulp){
            i_max = i;
            max_delta_ulp = delta_ulp;
        }
        ulp += delta_ulp;
    }

    // MPC ciphertext calculation
    auto start = std::chrono::high_resolution_clock::now();
    auto end = std::chrono::high_resolution_clock::now();
    auto offline_duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    auto online_duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    uint64_t init_byte, rounds;
    uint64_t mid_byte, mid_rounds;

    if(party==CLIENT){
        cout << "Client execution." << endl;
        server = new Peer(address, port);
        peer = server;
        init_byte = peer->bytesSent;
        rounds = peer->rounds;
    }
    else{
        cout << "Server execution." << endl;
        //server = new Peer(address, port);
        client = waitForPeer(port);
        peer = client;
        init_byte = peer->bytesSent;
        rounds = peer->rounds;
    }

    start = std::chrono::high_resolution_clock::now();
    ProximityKeyPack key = proximity_offline(party, bitsize, scale, using_lut, (scale - 1) / 2,
                                             16, 2);

    mid_byte = peer->bytesSent - init_byte;
    mid_rounds = peer->rounds - rounds;
    end = std::chrono::high_resolution_clock::now();
    offline_duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    start = std::chrono::high_resolution_clock::now();
    proximity(party, GroupElement(1, bitsize), GroupElement(1, bitsize), GroupElement(1, bitsize), GroupElement(1, bitsize), key);
    end = std::chrono::high_resolution_clock::now();
    online_duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    std::cout << "[Accuracy] Accumulated ULP error = " << ulp << " within " << test_num << " testcases, avg_ULP = " << (float)ulp / test_num << std::endl;
    std::cout << "[Offline Performance] Bytes Sent(Bytes) = " << mid_byte << " , Rounds = " << mid_rounds << ", Time(MicroSec) " << offline_duration << std::endl;
    std::cout << "[Online Performance] Bytes Sent(Bytes) = " << peer->bytesSent - mid_byte << " , Rounds = " << peer->rounds - mid_rounds << ", Time(MicroSec) " << online_duration << std::endl;
}