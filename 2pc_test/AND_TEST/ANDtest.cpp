//
// Created by root on 3/17/23.
//
#include "../../src/2pcwrapper.h"
#include "../../src/deps/utils/ArgMapping/ArgMapping.h"
#include "../../src/deps/cryptoTools/cryptoTools/Common/Defines.h"

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

/*
AND wrapper:

u8 and_wrapper(int party_id, u8 dataA, u8 dataB, Peer* player);

*/

int main(int argc, char **argv){
    ArgMapping amap;
    amap.arg("r", party, "Role of party: ALICE = 1; BOB = 2");
    amap.arg("p", port, "Port Number");
    amap.arg("b", choice_bit, "Choice bit");
    amap.arg("v", verbose, "Verbose");
    amap.arg("l", length, "Arr length");
    amap.parse(argc, argv);

    // a = 1
    u8 a0 = 0;
    u8 a1 = 1;
    // b = 1
    u8 b0 = 1;
    u8 b1 = 0;


    cout << party << endl;
    u8 out = 0;

    if(party==CLIENT){
        cout << "Client execution." << endl;
        //cout << "Init out = " << *out << endl;
        //client = new Peer(address, port);
        server = new Peer(address, port);
        peer = server;
        out = and_wrapper(party, (u8)0, peer);
        out = and_wrapper(party, (u8)0, peer);
    }
    else{
        cout << "Server execution." << endl;
        //server = new Peer(address, port);
        client = waitForPeer(port);
        peer = client;
        out = and_wrapper(party, (u8)0, peer);
        out = and_wrapper(party, (u8)0, peer);
    }
    cout << (int)out << endl;
}