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
#include "../../src/2pc_math.h"
#include "../../src/deps/utils/ArgMapping/ArgMapping.h"
#include "../../src/deps/cryptoTools/cryptoTools/Common/Defines.h"
#include "../../src/2pcwrapper.h"
#include "../../src/2pc_api.h"
#include "../../src/comms.h"

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
int function = 0;
int Bin = 8;
int Bout = 8;
int scale = 5;
int using_lut = 1;

int main(int argc, char **argv){
    ArgMapping amap;
    amap.arg("r", party, "Role of party: ALICE = 2; BOB = 3");
    amap.arg("p", port, "Port Number");
    amap.arg("v", verbose, "Verbose");
    amap.arg("f", function, "Function");
    amap.arg("i", Bin, "Input Bit length");
    amap.arg("o", Bout, "Output Bit length");
    amap.arg("l", using_lut, "Using LUT");
    amap.parse(argc, argv);
    int mul_size = 1+1;

    GroupElement* input = new GroupElement[mul_size];
    GroupElement* output = new GroupElement[mul_size];
    u8 sel[mul_size];
    for (int i = 0; i < mul_size; i++){
        input[i] = GroupElement(3, 2);
        output[i] = GroupElement(3, 2);
    }
    SineKeyPack sin_key;
    CosineKeyPack cos_key;
    TangentKeyPack tan_key;

    uint64_t init;
    uint64_t init_rounds;

    auto start = std::chrono::high_resolution_clock::now();
    auto mid = std::chrono::high_resolution_clock::now();
    auto end = std::chrono::high_resolution_clock::now();
    auto online_duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    auto offline_duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    auto total_duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    if(party==CLIENT){
        cout << "Client execution." << endl;
        server = new Peer(address, port);
        peer = server;
    }else{
        cout << "Server execution." << endl;
        client = waitForPeer(port);
        peer = client;
    }
    uint64_t init_byte, rounds;
    uint64_t mid_byte, mid_rounds;
    init_byte = peer->bytesSent;
    rounds = peer->rounds;

    start = std::chrono::high_resolution_clock::now();
    switch (function) {
        case 0:{
            sin_key = sine_offline(party, Bin, Bout, scale, (bool)using_lut, 3, 16, 2);
            break;
        }
        case 1: {
            cos_key = cosine_offline(party, Bin, Bout, scale, (bool)using_lut, 3, 16, 2);
            break;
        }
        case 2: {
            tan_key = tangent_offline(party, Bin, Bout, scale, (bool)using_lut, 16, 2);
            break;
        }
        default: {
            std::cout << "[ERROR] No matching function!" << std::endl;
        }
    }
    mid = std::chrono::high_resolution_clock::now();
    mid_byte = peer->bytesSent;
    mid_rounds = peer->rounds;
    switch (function) {
        case 0:{
            sine(party, GroupElement(1, Bin), sin_key);
            break;
        }
        case 1: {
            cosine(party, GroupElement(1, Bin), cos_key);
            break;
        }
        case 2: {
            tangent(party, GroupElement(1, Bin), tan_key);
            break;
        }
        default: {
            std::cout << "[ERROR] No matching function!" << std::endl;
        }
    }
    end = std::chrono::high_resolution_clock::now();

    online_duration = std::chrono::duration_cast<std::chrono::microseconds>(end - mid).count();
    offline_duration = std::chrono::duration_cast<std::chrono::microseconds>(mid - start).count();
    total_duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    std::cout << "Init (Bytes, Rounds) = " << init_byte << ", " << rounds << std::endl;
    std::cout << "Offline (Bytes, Rounds, Time (microsec)) = " << (mid_byte - init_byte) << ", " << mid_rounds - rounds << ", " << offline_duration << std::endl;
    std::cout << "Online (Bytes, Rounds, Time (microsec)) = " << (peer->bytesSent - mid_byte) << ", " << peer->rounds - mid_rounds << ", " << online_duration << std::endl;
    std::cout << "Total (Bytes, Rounds, Time (microsec)) = " << (peer->bytesSent - init_byte)  << ", " << peer->rounds - rounds << ", " << total_duration << std::endl;

    delete[] input;
    delete[] output;
}