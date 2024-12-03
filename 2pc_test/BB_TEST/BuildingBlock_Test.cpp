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
int Bin = 18;
int Bout = 18;
int scale = 9;

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
int function = 0;

#define MODULAR 1
int MODULAR_N = 2;

#define TRUNCATE_AND_REDUCE 2
int TR_S = Bin / 2;

#define CONTAINMENT 3
int CTN_SIZE = 4;
GroupElement CTN_KNOTS[] = {GroupElement(0.5, Bin, scale), GroupElement(1, Bin, scale),
                            GroupElement(1.5, Bin, scale), GroupElement(2, Bin, scale)};

#define DIGDEC 4
// WARNING: segNum must fully divide the bit size
int DIGDEC_SEG = 2;
int DIGDEC_NEW_BITSIZE = Bin / DIGDEC_SEG;

#define PUBLUT 5

#define PRILUT 6

#define APPROX 7
int APPROX_DEG = 2;
int APPROX_SEG = 16;

int main(int argc, char **argv){
    ArgMapping amap;
    amap.arg("r", party, "Role of party: ALICE = 2; BOB = 3");
    amap.arg("p", port, "Port Number");
    amap.arg("v", verbose, "Verbose");
    amap.arg("i", Bin, "bit length in");
    amap.arg("o", Bout, "bit length");
    amap.arg("f", function, "function");
    amap.arg("s", scale, "Scale");
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

    // define key
    TestKeyPack key;

    auto start = std::chrono::high_resolution_clock::now();
    auto end = std::chrono::high_resolution_clock::now();
    auto dpf_duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    uint64_t init_byte, rounds;
    uint64_t mid_byte, mid_rounds;

    if(party==CLIENT){
        cout << "Client execution. Test function = " << function << endl;
        server = new Peer(address, port);
        peer = server;
        init_byte = peer->bytesSent;
        rounds = peer->rounds;
    }
    else{
        cout << "Server execution, Test function = " << function<< endl;
        client = waitForPeer(port);
        peer = client;
        init_byte = peer->bytesSent;
        rounds = peer->rounds;
    }

    start = std::chrono::high_resolution_clock::now();
    std::cout << "============Offline start========="<<std::endl;
    switch (function) {
        case MODULAR:{
            key.key1 = modular_offline(party, GroupElement(MODULAR_N, Bin), Bout);
            break;
        }
        case TRUNCATE_AND_REDUCE:{
            key.key2 = truncate_and_reduce_offline(party, Bin, TR_S);
            break;
        }
        case CONTAINMENT:{
            key.key3 = containment_offline(party, Bout, CTN_KNOTS, CTN_SIZE);
            break;
        }
        case DIGDEC:{
            key.key4 = digdec_offline(party, Bin, DIGDEC_NEW_BITSIZE);
            break;
        }
        case PUBLUT:{
            key.key5 = pub_lut_offline(party, Bin, Bout);
            break;
        }
        case PRILUT:{
            GroupElement* table = new GroupElement[1 << Bin];
            for (int i = 0; i < (1 << Bin); i++){
                table[i].bitsize = Bout;
            }
            key.key6 = pri_lut_offline(party, Bin, Bout, table);
            delete[] table;
            break;
        }
        case APPROX:{
            GroupElement* coefList = new GroupElement[(APPROX_DEG + 1) * APPROX_SEG];
            for (int i = 0; i < (APPROX_DEG + 1) * APPROX_SEG; i++){
                coefList[i].bitsize = Bin;
            }
            key.key7 = spline_poly_approx_offline(party, Bin, Bout, coefList,
                                                                     APPROX_DEG, APPROX_SEG);
            delete[] coefList;
            break;
        }
    }
    mid_byte = peer->bytesSent;
    mid_rounds = peer->rounds;
    std::cout << "============Online start========="<<std::endl;
    switch (function) {
        case MODULAR:{
            modular(party, x, MODULAR_N, key.key1);
            break;
        }
        case TRUNCATE_AND_REDUCE:{
            truncate_and_reduce(party, x, TR_S, key.key2);
            break;
        }
        case CONTAINMENT:{
            GroupElement* containment_output = new GroupElement[CTN_SIZE + 1];
            for (int i = 0; i < CTN_SIZE + 1; i++){
                containment_output[i].bitsize = Bout;
            }
            containment(party, x, containment_output, CTN_SIZE, key.key3);
            delete[] containment_output;
            break;
        }
        case DIGDEC:{
            GroupElement* digdec_output = new GroupElement[DIGDEC_SEG];
            for (int i = 0; i < DIGDEC_SEG; i++){
                digdec_output[i].bitsize = DIGDEC_NEW_BITSIZE;
            }
            digdec(party, x, digdec_output, DIGDEC_NEW_BITSIZE, key.key4);
            delete[] digdec_output;
            break;
        }
        case PUBLUT:{
            GroupElement* table = new GroupElement[1 << Bin];
            GroupElement* shifted = new GroupElement[1 << Bin];
            for (int i = 0; i < (1 << Bin); i++){
                table[i].bitsize = Bout;
                shifted[i].bitsize = Bout;
            }
            pub_lut(party, x, table, shifted, (1 << Bin), Bout, key.key5);
            delete[] table;
            delete[] shifted;
            break;
        }
        case PRILUT:{
            pri_lut(party, x, key.key6);
            break;
        }
        case APPROX:{
            spline_poly_approx(party, x, key.key7);
            break;
        }
    }
    end = std::chrono::high_resolution_clock::now();

    std::cout << "Init (Bytes, Rounds) = " << init_byte << ", " << rounds << std::endl;
    std::cout << "Offline (Bytes, Rounds) = " << (mid_byte - init_byte) << ", " << mid_rounds - rounds << std::endl;
    std::cout << "Online (Bytes, Rounds) = " << (peer->bytesSent - mid_byte) << ", " << peer->rounds - mid_rounds << std::endl;


    return 0;
}
