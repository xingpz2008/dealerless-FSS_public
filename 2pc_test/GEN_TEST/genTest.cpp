//
// Created by  邢鹏志 on 2023/2/5.
//
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
uint8_t choice_bit = 0;
bool verbose = 1;
int length = 1;
Peer* client = nullptr;
Peer* server = nullptr;
Dealer* dealer = nullptr;
Peer* peer = nullptr;

int main(int argc, char **argv){
    ArgMapping amap;
    amap.arg("r", party, "Role of party: ALICE = 1; BOB = 2");
    amap.arg("p", port, "Port Number");
    amap.arg("b", choice_bit, "Choice bit");
    amap.arg("v", verbose, "Verbose");
    amap.arg("i", Bin, "bit length in");
    amap.arg("o", Bout, "bit length");
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


    auto start = std::chrono::high_resolution_clock::now();
    auto end = std::chrono::high_resolution_clock::now();
    auto dpf_duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    uint64_t init_byte, rounds;
    uint64_t mid_byte, mid_rounds;

    if(party==CLIENT){
        cout << "Client execution. Payload.value = " << payload.value << endl;
        //client = new Peer(address, port);
        server = new Peer(address, port);
        peer = server;
        init_byte = peer->bytesSent;
        rounds = peer->rounds;
        start = std::chrono::high_resolution_clock::now();
        ComparisonKeyPack key = comparison_offline(party, Bin, Bout, GroupElement(1, Bin), &payload);
        //newDCFKeyPack key(keyGenNewDCF(party, Bin, Bout, GroupElement(1, Bin), payload));
        //DPFKeyPack key(keyGenDPF(party, Bin, Bout, GroupElement(1, Bin), payload));
        //iDCFKeyPack idcf_key(keyGeniDCF(party, Bin, Bout, GroupElement(1, Bin), &payload));
        mid_byte = peer->bytesSent;
        mid_rounds = peer->rounds;
        std::cout << "============Online start========="<<std::endl;
        comparison(party, res, &x, &key, 1, Bin);
        //evalNewDCF(party, res, &x, &key, 1, Bin);
        //evalDPF(party, res, x, key);
        //evaliDCF(party, &idcf_res, x, idcf_key);
        end = std::chrono::high_resolution_clock::now();
        //dpf_duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        //DPFKeyPack ikey(keyGeniDPF(party, Bin, Bout, GroupElement(2, Bin), payload_list));
        //evaliDPF(party, ires, x, ikey);
        //iDCFKeyPack idcf_key(keyGeniDCF(party, Bin, Bout, GroupElement(1, Bin), &payload));
        //evaliDCF(party, &idcf_res, x, idcf_key);
    }
    else{
        cout << "Server execution, Payload.value = " << payload.value<< endl;
        //server = new Peer(address, port);
        client = waitForPeer(port);
        peer = client;
        init_byte = peer->bytesSent;
        rounds = peer->rounds;
        start = std::chrono::high_resolution_clock::now();
        ComparisonKeyPack key(comparison_offline(party, Bin, Bout, GroupElement(1, Bin), &payload));
        //DPFKeyPack key(keyGenDPF(party, Bin, Bout, GroupElement(2, Bin), payload));
        //iDCFKeyPack idcf_key(keyGeniDCF(party, Bin, Bout, GroupElement(1, Bin), &payload));
        mid_byte = peer->bytesSent;
        mid_rounds = peer->rounds;
        std::cout << "============Online start========="<<std::endl;
        comparison(party, res, &x, &key, 1, Bin);
        //evalDPF(party, res, x, key);
        //evaliDCF(party, &idcf_res, x, idcf_key);
        end = std::chrono::high_resolution_clock::now();
        //dpf_duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        //DPFKeyPack ikey(keyGeniDPF(party, Bin, Bout, GroupElement(1, Bin), payload_list));
        //evaliDPF(party, ires, x, ikey);
        //iDCFKeyPack idcf_key(keyGeniDCF(party, Bin, Bout, GroupElement(1, Bin), &payload));
        //evaliDCF(party, &idcf_res, x, idcf_key);
    }
    std::cout << "Init (KBytes, Rounds) = " << init_byte << ", " << rounds << std::endl;
    std::cout << "Offline (KBytes, Rounds) = " << (mid_byte - init_byte)/(float)1024 << ", " << mid_rounds - rounds << std::endl;
    std::cout << "Online (KBytes, Rounds) = " << (peer->bytesSent - mid_byte)/(float)1024 << ", " << peer->rounds - mid_rounds << std::endl;

    /*
    auto final_end = std::chrono::high_resolution_clock::now();
    auto final_duration = std::chrono::duration_cast<std::chrono::microseconds>(final_end - end).count();
    std::cout << "(DPF) Party " << party << " :" << "Time = " << dpf_duration << std::endl;
    std::cout << "(iDPF) Party " << party << " :" << "Time = " << final_duration << std::endl;
    std::cout << "DPF Res:" << res->value % (1<<Bout) << std::endl;
    std::cout << "iDPF Res:";
    for (int i = 0; i < Bin; i++){
        std::cout << " " << ires[i].value % (1<<Bout) << ",";
    }
    std::cout << std::endl;
    std::cout << "iDCF Res: " << idcf_res.value << std::endl;
     */
    return 0;
}