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
#include "../../src/2pc_idpf.h"
#include "../../src/group_element.h"
#include "../../src/ArgMapping.h"
#include "../../src/2pc_dcf.h"
#include "../../src/2pc_api.h"
#include<iostream>

int party_instance = 0;
int Bin = 8;
int Bout = 8;

using namespace sci;
using namespace std;
using namespace osuCrypto;

int party = 0;
int32_t bitlength = 32;
int num_threads = 1;
int port = 32000;
std::string address = "127.0.0.1";
int num_argmax = 1000;
bool verbose = 1;
int length = 1;
Peer* client = nullptr;
Peer* server = nullptr;
Dealer* dealer = nullptr;
Peer* peer = nullptr;
int function = 0;

int main(int argc, char **argv){
    ArgMapping amap;
    amap.arg("r", party, "Role of party: ALICE = 2; BOB = 3");
    amap.arg("p", port, "Port Number");
    amap.arg("i", Bin, "bit length in");
    amap.arg("o", Bout, "bit length");
    amap.arg("f", function, "Function choice: DPF = 0; DCF = 1; DPF-based Equality Test = 2; DCF-based comparison = 3");
    amap.parse(argc, argv);

    GroupElement x = GroupElement(2, Bin);
    GroupElement payload = GroupElement(party -2, Bout);
    GroupElement* payload_list = new GroupElement[Bin];
    GroupElement* res = new GroupElement(0);
    GroupElement ires[Bin];
    GroupElement idcf_res=GroupElement(0, Bout);
    for (int i=0; i<Bin; i++){
        payload_list[i] = GroupElement(party - 2, Bout);
    }

    DPFKeyPack DPF_key;
    newDCFKeyPack DCF_key;
    DPFKeyPack EQ_key;
    ComparisonKeyPack CMP_key;

    auto start = std::chrono::high_resolution_clock::now();
    auto mid = std::chrono::high_resolution_clock::now();
    auto end = std::chrono::high_resolution_clock::now();
    auto online_duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    auto offline_duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    auto total_duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    uint64_t init_byte, rounds;
    uint64_t mid_byte, mid_rounds;

    if(party==CLIENT){
        cout << "Client execution. Payload.value = " << payload.value << endl;
        server = new Peer(address, port);
        peer = server;
        init_byte = peer->bytesSent;
        rounds = peer->rounds;
    }else {
        cout << "Server execution, Payload.value = " << payload.value<< endl;
        client = waitForPeer(port);
        peer = client;
        init_byte = peer->bytesSent;
        rounds = peer->rounds;
    }

    start = std::chrono::high_resolution_clock::now();

    switch (function) {
        case 0:{
            DPF_key = keyGenDPF(party, Bin, Bout, GroupElement(1, Bin), payload, false);
            break;
        }
        case 1:{
            DCF_key = keyGenNewDCF(party, Bin, Bout, GroupElement(1, Bin), payload);
            break;
        }
        case 2:{
            EQ_key = keyGenDPF(party, Bin, Bout, GroupElement(1, Bin), payload);
            break;
        }
        case 3:{
            CMP_key = comparison_offline(party, Bin, Bout, GroupElement(1, Bin), &payload, true);
            break;
        }
        default:{
            std::cout << "[ERROR] No matching function!" << std::endl;
        }
    }
    mid_byte = peer->bytesSent;
    mid_rounds = peer->rounds;
    mid = std::chrono::high_resolution_clock::now();
    std::cout << "============Online start========="<<std::endl;
    switch (function) {
        case 0:{
            evalDPF(party, res, x, DPF_key, false);
            break;
        }
        case 1:{
            evalNewDCF(party, res, &x, &DCF_key, 1, Bin);
            break;
        }
        case 2:{
            evalDPF(party, res, x, EQ_key);
            break;
        }
        case 3:{
            comparison(party, res, &x, &CMP_key, 1, Bin);
            break;
        }
        default:{
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

    return 0;
}