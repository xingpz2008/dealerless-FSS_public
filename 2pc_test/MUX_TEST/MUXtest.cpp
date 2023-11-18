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

    int bl = 4;
    u64 a = 1;
    block a_ = osuCrypto::toBlock(a);
    u64 b = 10;
    block b_ = osuCrypto::toBlock(b);

    GroupElement* out = new GroupElement(-1, bl);
    //uint64_t* out = 0;

    GroupElement a_ge(a, bl);
    GroupElement b_ge(b, bl);
    cout << party << endl;
    block b_out;

    if(party==CLIENT){
        cout << "Client execution." << endl;
        cout << "A = " << a_ << endl;
        //cout << "Init out = " << *out << endl;
        choice_bit = (uint8_t)1;
        cout << "Choice bit = " << (int)choice_bit << endl;
        //client = new Peer(address, port);
        server = new Peer(address, port);
        peer = server;
        multiplexer(party, &choice_bit, &a_ge, out, 1, peer);
        cout << out->value%(1ULL << bl) << endl;
    }
    else{
        cout << "Server execution." << endl;
        cout << "B = " << b_ << endl;
        //choice_bit = (uint8_t)1;
        cout << "Choice bit = " << (int)choice_bit << endl;
        //server = new Peer(address, port);
        client = waitForPeer(port);
        peer = client;

        multiplexer(party, &choice_bit, &b_ge, out, 1, peer);
        cout << out->value%(1ULL << bl) << endl;
    }
}