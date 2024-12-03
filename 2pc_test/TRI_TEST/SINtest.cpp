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
    ArgMapping amap;
    amap.arg("r", party, "Role of party: ALICE = 1; BOB = 2");
    amap.arg("p", port, "Port Number");
    amap.arg("b", choice_bit, "Choice bit");
    amap.arg("v", verbose, "Verbose");
    amap.arg("l", length, "Arr length");
    amap.parse(argc, argv);
    int mul_size = 1+1;

    GroupElement* input = new GroupElement[mul_size];
    GroupElement* output = new GroupElement[mul_size];
    u8 sel[mul_size];
    for (int i = 0; i < mul_size; i++){
        input[i] = GroupElement(3, 2);
        output[i] = GroupElement(3, 2);
    }
    SineKeyPack key;

    if(party==CLIENT){
        cout << "Client execution." << endl;
        server = new Peer(address, port);
        peer = server;
        uint64_t init = peer->bytesSent;
        uint64_t init_rounds = peer->rounds;
        // key = tangent_offline(party, 16, 16, 9, false, 16, 2);
        key = sine_offline(party, 8, 8, 5, true, 3, 16, 2);
        // int party_id, GroupElement* input, GroupElement* output, bool hold_arithmetic, int size, Peer* player
        // peer->send_cot(input, output, mul_size, true);
        // cross_term_gen(party, input, output, true, mul_size, peer);
        //modular_offline(party, GroupElement(2,2), 2);
        /*
        for (int i = 0; i < 20; i++){
            peer->send_cot(input, output, mul_size, false);
        }
         */
        uint64_t overhead[3] = {0,0,0};
        overhead[0] = peer->bytesSent - init;
        overhead[1] = peer->bytesReceived;
        overhead[2] = peer->rounds - init_rounds;
        //tangent(party, GroupElement(1, 16), key);
        sine(party, GroupElement(1, 8), key);
        std::cout << "Offline Overhead: 1. Send = " << overhead[0] << ", 2. Received = " << overhead[1] << ", 3. Rounds = " << overhead[2] << std::endl;
        std::cout << "Online Overhead: 1. Send = " << peer->bytesSent - overhead[0] << ", 2. Received = " << peer->bytesReceived - overhead[1]<< ", 3. Rounds = " << peer->rounds - overhead[2]<< std::endl;
    }
    else{
        cout << "Server execution." << endl;
        client = waitForPeer(port);
        peer = client;
        // key = tangent_offline(party, 16, 16, 9, false, 16, 2);
        key = sine_offline(party, 8, 8, 5, true, 3, 16, 2);
        //peer->recv_cot(output, mul_size, sel, true);
        //cross_term_gen(party, input, output, false, mul_size, peer);
        //modular_offline(party, GroupElement(2,2), 2);
        /*
        for (int i = 0; i < 20; i++){
            peer->recv_cot(output, mul_size, sel, false);
        }
         */
        std::cout << "Overhead: 1. Send = " << peer->bytesSent << ", 2. Received = " << peer->bytesReceived << ", 3. Rounds = " << numRounds << std::endl;
        sine(party, GroupElement(1, 8), key);
        // tangent(party, GroupElement(1, 16), key);
        std::cout << "Overhead: 1. Send = " << peer->bytesSent << ", 2. Received = " << peer->bytesReceived << ", 3. Rounds = " << numRounds << std::endl;
    }
    delete[] input;
    delete[] output;
}