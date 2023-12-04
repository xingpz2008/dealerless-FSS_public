/*
Authors: Deepak Kumaraswamy, Kanav Gupta
Copyright:
Copyright (c) 2022 Microsoft Research
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include "comms.h"
#include "api.h"
#include <cassert>

/*
Peer::Peer(std::string ip, int port) {
    std::cerr << "trying to connect with server...";
    {
        recvsocket = socket(AF_INET, SOCK_STREAM, 0);
        if (recvsocket < 0) {
            perror("socket");
            exit(1);
        }
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr(ip.c_str());
        if (connect(recvsocket, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
            perror("connect");
            exit(1);
        }
        const int one = 1;
        setsockopt(recvsocket, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    }
    sleep(1);
    {
        sendsocket = socket(AF_INET, SOCK_STREAM, 0);
        if (sendsocket < 0) {
            perror("socket");
            exit(1);
        }
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port+3);
        addr.sin_addr.s_addr = inet_addr(ip.c_str());
        if (connect(sendsocket, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
            perror("connect");
            exit(1);
        }
        const int one = 1;
        setsockopt(sendsocket, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    }
    iopack_ = new sci::IOPack(party-1, port);
    otpack = new sci::OTPack(iopack_, party-1);
    std::cerr << "connected" << std::endl;
}
 */

Peer::Peer(std::string ip, int port) {
    std::cerr << "trying to connect with server...";
    {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr(ip.c_str());
        while (1) {
            recvsocket = socket(AF_INET, SOCK_STREAM, 0);

            if (connect(recvsocket, (struct sockaddr *)&addr,
                        sizeof(struct sockaddr)) == 0) {
                break;
            }

            ::close(recvsocket);
            usleep(1000);
        }
        const int one = 1;
        setsockopt(recvsocket, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    }
    sleep(1);
    {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port+3);
        addr.sin_addr.s_addr = inet_addr(ip.c_str());
        while(1){
            sendsocket = socket(AF_INET, SOCK_STREAM, 0);
            if (sendsocket < 0) {
                perror("socket");
                exit(1);
            }
            if (connect(sendsocket, (struct sockaddr *) &addr, sizeof(addr)) == 0) {
                break;
            }
            ::close(sendsocket);
            usleep(1000);
        }
        const int one = 1;
        setsockopt(sendsocket, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    }
    iopack_ = new sci::IOPack(party-1, port);
    otpack = new sci::OTPack(iopack_, party-1);
    std::cerr << "connected" << "\n";
}

void Peer::close() {
    if (useFile) {
        file.close();
    }
    else {
        ::close(sendsocket);
        ::close(recvsocket);
    }
}

Peer* waitForPeer(int port) {
    int sendsocket, recvsocket;
    std::cerr << "waiting for connection from client...";
    
    {
        struct sockaddr_in dest;
        struct sockaddr_in serv;
        socklen_t socksize = sizeof(struct sockaddr_in);
        memset(&serv, 0, sizeof(serv));
        serv.sin_family = AF_INET;
        serv.sin_addr.s_addr = htonl(INADDR_ANY);       /* set our address to any interface */
        serv.sin_port = htons(port); /* set the server port number */
        int mysocket = socket(AF_INET, SOCK_STREAM, 0);
        int reuse = 1;
        setsockopt(mysocket, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse,
                    sizeof(reuse));
        if (::bind(mysocket, (struct sockaddr *)&serv, sizeof(struct sockaddr)) < 0) {
            perror("error: bind");
            exit(1);
        }
        if (listen(mysocket, 1) < 0) {
            perror("error: listen");
            exit(1);
        }
        sendsocket = accept(mysocket, (struct sockaddr *)&dest, &socksize);
        const int one = 1;
        setsockopt(sendsocket, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        close(mysocket);
    }

    {
        struct sockaddr_in dest;
        struct sockaddr_in serv;
        socklen_t socksize = sizeof(struct sockaddr_in);
        memset(&serv, 0, sizeof(serv));
        serv.sin_family = AF_INET;
        serv.sin_addr.s_addr = htonl(INADDR_ANY);       /* set our address to any interface */
        serv.sin_port = htons(port+3); /* set the server port number */
        int mysocket = socket(AF_INET, SOCK_STREAM, 0);
        int reuse = 1;
        setsockopt(mysocket, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse,
                    sizeof(reuse));
        if (::bind(mysocket, (struct sockaddr *)&serv, sizeof(struct sockaddr)) < 0) {
            perror("error: bind");
            exit(1);
        }
        if (listen(mysocket, 1) < 0) {
            perror("error: listen");
            exit(1);
        }
        recvsocket = accept(mysocket, (struct sockaddr *)&dest, &socksize);
        const int one = 1;
        setsockopt(recvsocket, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        close(mysocket);
    }
    
    std::cerr << "connected" << std::endl;
    return new Peer(sendsocket, recvsocket);
}


void Peer::send_ge(const GroupElement &g, int bw) {
    if (bw > 32) {
        char *buf = (char *)(&g.value);
        if (useFile) {
            this->file.write(buf, 8);
        } else {
            send(sendsocket, buf, 8, 0);
        }
        bytesSent += 8;
    }
    else if (bw > 16) {
        char *buf = (char *)(&g.value);
        if (useFile) {
            this->file.write(buf, 4);
        } else {
            send(sendsocket, buf, 4, 0);
        }
        bytesSent += 4;
    }
    else if (bw > 8) {
        char *buf = (char *)(&g.value);
        if (useFile) {
            this->file.write(buf, 2);
        } else {
            send(sendsocket, buf, 2, 0);
        }
        bytesSent += 2;
    }
    else {
        char *buf = (char *)(&g.value);
        if (useFile) {
            this->file.write(buf, 1);
        } else {
            send(sendsocket, buf, 1, 0);
        }
        bytesSent += 1;
    }
}

void Peer::send_block(const osuCrypto::block &b) {
    char *buf = (char *)(&b);
    if (useFile) {
        this->file.write(buf, sizeof(osuCrypto::block));
    } else {
        send(sendsocket, buf, sizeof(osuCrypto::block), 0);
    }
    bytesSent += sizeof(osuCrypto::block);
}

osuCrypto::block Peer::recv_block(){
    char buf[sizeof(osuCrypto::block)];
    if (useFile) {
        this->file.read(buf, sizeof(osuCrypto::block));
    } else {
        recv(recvsocket, buf, sizeof(osuCrypto::block), MSG_WAITALL);
    }
    osuCrypto::block b = *(osuCrypto::block *)buf;
    bytesReceived += sizeof(osuCrypto::block);
    return b;
}

void Peer::send_u8(const u8 &b){
    char *buf = (char*)(&b);
    if (useFile) {
        this->file.write(buf, sizeof(u8));
    }
    else{
        send(sendsocket, buf, sizeof(u8), 0);
    }
    bytesSent += sizeof(u8);
}

u8 Peer::recv_u8(){
    char buf[sizeof(u8)];
    if (useFile) {
        this->file.read(buf, sizeof(u8));
    } else {
        recv(recvsocket, buf, sizeof(u8), MSG_WAITALL);
    }
    u8 b = *(u8*)buf;
    bytesReceived += sizeof(u8);
    return b;
}

void Peer::send_u64(const uint64_t &b){
    char *buf = (char*)(&b);
    if (useFile) {
        this->file.write(buf, sizeof(uint64_t));
    }
    else{
        send(sendsocket, buf, sizeof(uint64_t), 0);
    }
    bytesSent += sizeof(uint64_t);
}

uint64_t Peer::recv_u64(){
    char buf[sizeof(uint64_t)];
    if (useFile) {
        this->file.read(buf, sizeof(uint64_t));
    } else {
        recv(recvsocket, buf, sizeof(uint64_t), MSG_WAITALL);
    }
    uint64_t b = *(uint64_t *)buf;
    bytesReceived += sizeof(uint64_t);
    return b;
}

void Peer::send_ge(const GroupElement &g){
    send_u64(g.value);
    send_u64(g.bitsize);
}

void Peer::send_mask(const GroupElement &g) {
    send_ge(g, 64);
}

GroupElement Peer::recv_ge(){
    GroupElement tmp;
    uint64_t value = recv_u64();
    uint64_t bitsize = recv_u64();
    tmp.value = value;
    tmp.bitsize = bitsize;
    return tmp;
}

void Peer::send_input(const GroupElement &g) {
    send_ge(g, 64);
}

void Peer::send_batched_input(GroupElement *g, int size, int bw)
{
    if (bw > 32) {
        uint64_t *temp = new uint64_t[size];
        for (int i = 0; i < size; i++) {
            temp[i] = g[i].value;
        }
        char *buf = (char *)(temp);
        if (useFile) {
            this->file.write(buf, 8*size);
        } else {
            send(sendsocket, buf, 8*size, 0);
        }
        delete[] temp;
        bytesSent += 8*size;
    }
    else if (bw > 16) {
        uint32_t *temp = new uint32_t[size];
        for (int i = 0; i < size; i++) {
            temp[i] = (uint32_t)g[i].value;
        }
        char *buf = (char *)(temp);
        if (useFile) {
            this->file.write(buf, 4*size);
        } else {
            send(sendsocket, buf, 4*size, 0);
        }
        delete[] temp;
        bytesSent += 4*size;
    }
    else if (bw > 8) {
        uint16_t *temp = new uint16_t[size];
        for (int i = 0; i < size; i++) {
            temp[i] = (uint16_t)g[i].value;
        }
        char *buf = (char *)(temp);
        if (useFile) {
            this->file.write(buf, 2*size);
        } else {
            send(sendsocket, buf, 2*size, 0);
        }
        delete[] temp;
        bytesSent += 2*size;
    }
    else {
        uint8_t *temp = new uint8_t[size];
        for (int i = 0; i < size; i++) {
            temp[i] = (uint8_t)g[i].value;
        }
        char *buf = (char *)(temp);
        if (useFile) {
            this->file.write(buf, size);
        } else {
            send(sendsocket, buf, size, 0);
        }
        delete[] temp;
        bytesSent += size;
    }
}

void Peer::recv_batched_input(uint64_t *g, int size, int bw)
{
    if (bw > 32) {
        if (useFile) {
            this->file.read((char *)g, 8*size);
        } else {
            recv(recvsocket, (char *)g, 8*size, MSG_WAITALL);
        }
        bytesReceived += 8*size;
    }
    else if (bw > 16) {
        uint32_t *tmp = new uint32_t[size];
        if (useFile) {
            this->file.read((char *)tmp, 4*size);
        } else {
            recv(recvsocket, (char *)tmp, 4*size, MSG_WAITALL);
        }
        for (int i = 0; i < size; i++) {
            g[i] = tmp[i];
        }
        delete[] tmp;
        bytesReceived += 4*size;
    }
    else if (bw > 8) {
        uint16_t *tmp = new uint16_t[size];
        if (useFile) {
            this->file.read((char *)tmp, 2*size);
        } else {
            recv(recvsocket, (char *)tmp, 2*size, MSG_WAITALL);
        }
        for (int i = 0; i < size; i++) {
            g[i] = tmp[i];
        }
        delete[] tmp;
        bytesReceived += 2*size;
    }
    else {
        uint8_t *tmp = new uint8_t[size];
        if (useFile) {
            this->file.read((char *)tmp, size);
        } else {
            recv(recvsocket, (char *)tmp, size, MSG_WAITALL);
        }
        for (int i = 0; i < size; i++) {
            g[i] = tmp[i];
        }
        delete[] tmp;
        bytesReceived += size;
    }
}

void Peer::send_mult_key(const MultKey &k) {
    char *buf = (char *)(&k);
    if (useFile) {
        this->file.write(buf, sizeof(MultKey));
    } else {
        send(sendsocket, buf, sizeof(MultKey), 0);
    }
    bytesSent += sizeof(MultKey);
}

void Peer::send_matmul_key(const MatMulKey &k) {
    int s1 = k.s1;
    int s2 = k.s2;
    int s3 = k.s3;
    
    for(int i = 0; i < s1; i++) {
        for(int j = 0; j < s2; j++) {
            send_ge(Arr2DIdxRowM(k.a, s1, s2, i, j), k.Bin);
        }
    }

    for(int i = 0; i < s2; i++) {
        for(int j = 0; j < s3; j++) {
            send_ge(Arr2DIdxRowM(k.b, s2, s3, i, j), k.Bin);
        }
    }

    for(int i = 0; i < s1; i++) {
        for(int j = 0; j < s3; j++) {
            send_ge(Arr2DIdxRowM(k.c, s1, s3, i, j), k.Bout);
        }
    }
}

void Peer::send_conv2d_key(const Conv2DKey &k) {
    int N = k.N;
    int H = k.H;
    int W = k.W;
    int CO = k.CO;
    int CI = k.CI;
    int FH = k.FH;
    int FW = k.FW;
    int zPadHLeft = k.zPadHLeft;
    int zPadHRight = k.zPadHRight; 
    int zPadWLeft = k.zPadWLeft;
    int zPadWRight = k.zPadWRight;;
    int strideH = k.strideH;
    int strideW = k.strideW;

    int d0 = N;
    int d1 = ((H - FH + (zPadHLeft + zPadHRight)) / strideH) + 1;
    int d2 = ((W - FW + (zPadWLeft + zPadWRight)) / strideW) + 1;
    int d3 = CO;
    

    for(int n = 0; n < N; ++n) {
        for(int h = 0; h < H; ++h) {
            for(int w = 0; w < W; ++w) {
                for(int ci = 0; ci < CI; ++ci) {
                    send_ge(Arr4DIdxRowM(k.a, N, H, W, CI, n, h, w, ci), k.Bin);
                }
            }
        }
    }

    for(int fh = 0; fh < FH; ++fh) {
        for(int fw = 0; fw < FW; ++fw) {
            for(int ci = 0; ci < CI; ++ci) {
                for(int co = 0; co < CO; ++co) {
                    send_ge(Arr4DIdxRowM(k.b, FH, FW, CI, CO, fh, fw, ci, co), k.Bin);
                }
            }
        }
    }

    GroupElement *c = k.c;
    int Bout = k.Bout;
    for(int i = 0; i < d0; ++i) {
        for(int j = 0; j < d1; ++j) {
            for(int k = 0; k < d2; ++k) {
                for(int l = 0; l < d3; ++l) {
                    send_ge(Arr4DIdxRowM(c, d0, d1, d2, d3, i, j, k, l), Bout);
                }
            }
        }
    }
}

void Peer::send_dcf_keypack(const DCFKeyPack &kp) {
    for (int i = 0; i < kp.Bin + 1; ++i) {
        send_block(kp.k[i]);
    }
    for (int i = 0; i < kp.groupSize; ++i) {
        send_ge(kp.g[i], kp.Bout);
    }
    for (int i = 0; i < kp.groupSize * kp.Bin; ++i) {
        send_ge(kp.v[i], kp.Bout);
    }
}

void Peer::send_ddcf_keypack(const DualDCFKeyPack &kp) {
    send_dcf_keypack(kp.dcfKey);
    for (int i = 0; i < kp.groupSize; ++i) {
        send_ge(kp.sb[i], kp.Bout);
    }
}

void Peer::send_new_mult_key(const MultKeyNew &k, int bw1, int bw2)
{
    send_ge(k.a, bw1 + bw2);
    send_ge(k.b, bw1 + bw2);
    send_ge(k.c, bw1 + bw2);
    send_dcf_keypack(k.k1);
    send_dcf_keypack(k.k2);
    send_dcf_keypack(k.k3);
    send_dcf_keypack(k.k4);
}

void Peer::send_relu_key(const ReluKeyPack &kp) {
    int Bin = kp.Bin;
    int groupSize = 2;
    for(int i = 0; i < Bin + 1; ++i) {
        send_block(kp.k[i]);
    }
    for(int i = 0; i < groupSize; ++i) {
        send_ge(kp.g[i], kp.Bout);
    }
    for(int i = 0; i < Bin * groupSize; ++i) {
        send_ge(kp.v[i], kp.Bout);
    }
    send_ge(kp.e_b0, kp.Bout);
    send_ge(kp.e_b1, kp.Bout);
    send_ge(kp.beta_b0, kp.Bout);
    send_ge(kp.beta_b1, kp.Bout);
    send_ge(kp.r_b, kp.Bout);
}

void Peer::send_maxpool_key(const MaxpoolKeyPack &kp) {
    send_relu_key(kp.reluKey);
    send_ge(kp.rb, kp.Bout);
}

void Peer::send_scmp_keypack(const ScmpKeyPack &kp) {
    send_ddcf_keypack(kp.dualDcfKey);
    send_ge(kp.rb, kp.Bout);
}

void Peer::send_pubdiv_key(const PublicDivKeyPack &kp) {
    send_ddcf_keypack(kp.dualDcfKey);
    send_scmp_keypack(kp.scmpKey);
    send_ge(kp.zb, kp.Bout);
}

void Peer::send_ars_key(const ARSKeyPack &kp) {
    send_dcf_keypack(kp.dcfKey);
    if (kp.Bout > kp.Bin - kp.shift) {
        send_ddcf_keypack(kp.dualDcfKey);
    }
    send_ge(kp.rb, kp.Bout);
}

void Peer::send_spline_key(const SplineKeyPack &kp)
{
    send_dcf_keypack(kp.dcfKey);
    for(auto &pi: kp.p) {
        send_ge(pi, kp.Bin);
    }

    for(auto &row: kp.e_b) {
        for(auto &e: row) {
            send_ge(e, kp.Bout);
        }
    }

    for(auto &b: kp.beta_b) {
        send_ge(b, kp.Bout);
    }

    send_ge(kp.r_b, kp.Bout);
}

void Peer::send_signedpubdiv_key(const SignedPublicDivKeyPack &kp) {
    send_ge(kp.d, kp.Bin);
    send_dcf_keypack(kp.dcfKey);
    send_publicIC_key(kp.publicICkey);
    send_scmp_keypack(kp.scmpKey);
    send_ge(kp.A_share, kp.Bin);
    send_ge(kp.corr_share, kp.Bout);
    send_ge(kp.B_share, kp.Bout);
    send_ge(kp.rdiv_share, kp.Bout);
    send_ge(kp.rout_temp_share, kp.Bout);
    send_ge(kp.rout_share, kp.Bout);
}

void Peer::send_publicIC_key(const PublicICKeyPack &kp) {
    send_dcf_keypack(kp.dcfKey);
    send_ge(kp.zb, kp.Bout);
}

GroupElement Peer::recv_input() {
    char buf[8];
    if (useFile) {
        std::cerr << "Can't recv from peer in file mode\n";
        exit(1);
    } else {
        recv(recvsocket, buf, 8, MSG_WAITALL);
    }
    GroupElement g(*(uint64_t *)buf, bitlength);
    bytesReceived += 8;
    return g;
}

void Peer::send_cot(uint64_t data, uint64_t* output, int length) {
    uint64_t pre_comm = otpack->iopack->io->counter;
    uint64_t pre_rounds = otpack->iopack->io->num_rounds;
    otpack->iknp_straight->send_cot(output, &data, length, 64);
    numRounds += (otpack->iopack->io->num_rounds - pre_rounds);
    bytesSent += (otpack->iopack->io->counter - pre_comm);
}

void Peer::send_cot(GroupElement* data, GroupElement* output, int length, bool using_aux_iknp) {
    uint64_t pre_comm = otpack->iopack->io->counter;
    uint64_t pre_rounds = otpack->iopack->io->num_rounds;
    uint64_t _output[length];
    if (using_aux_iknp){
        otpack->iknp_reversed->send_cot(_output, &(data->value), length, data->bitsize);
    }else{
        otpack->iknp_straight->send_cot(_output, &(data->value), length, data->bitsize);
    }
    for (int i = 0; i < length; i++){
        std::cout << "In send_cot, " << i << "th output for sender is " << _output[i]%(1ULL<<data->bitsize) << " with input " << data->value%(1ULL<<data->bitsize)<< std::endl;
        output[i].value = _output[i];
        output[i].bitsize = data->bitsize;
    }
    numRounds += (otpack->iopack->io->num_rounds - pre_rounds);
    bytesSent += (otpack->iopack->io->counter - pre_comm);
}

void Peer::recv_cot(uint64_t* recv_arr, int size, uint8_t* sel){
    uint64_t pre_comm = otpack->iopack->io->counter;
    uint64_t pre_rounds = otpack->iopack->io->num_rounds;
    otpack->iknp_straight->recv_cot(recv_arr, (bool*)sel, size, 64);
    numRounds += (otpack->iopack->io->num_rounds - pre_rounds);
    bytesSent += (otpack->iopack->io->counter - pre_comm);
}

void Peer::recv_cot(GroupElement* recv_arr, int size, uint8_t* sel, bool using_aux_iknp){
    uint64_t pre_comm = otpack->iopack->io->counter;
    uint64_t pre_rounds = otpack->iopack->io->num_rounds;
    uint64_t recv_value_arr[size];
    if (using_aux_iknp){
        otpack->iknp_reversed->recv_cot(recv_value_arr, (bool*)sel, size, recv_arr[0].bitsize);
    }else{
        otpack->iknp_straight->recv_cot(recv_value_arr, (bool*)sel, size, recv_arr[0].bitsize);
    }
    for (int i = 0; i < size; i++){
        std::cout << "In recv_cot, " << i << "th output for receiver is " << recv_value_arr[i] %(recv_arr[0].bitsize)<< std::endl;
        recv_arr[i].value = recv_value_arr[i];
    }
    numRounds += (otpack->iopack->io->num_rounds - pre_rounds);
    bytesSent += (otpack->iopack->io->counter - pre_comm);
}

void Peer::send_cot(osuCrypto::block input, osuCrypto::block* output, int size){
    //std::cout << "Send beacon 1\n" ;
    uint64_t pre_comm =otpack->iopack->get_comm();
    //std::cout << "Send beacon 1.1\n" ;
    uint64_t pre_rounds = otpack->iopack->get_rounds();
    //std::cout << "Send beacon 2\n";
    otpack->iknp->send_cot(output, input, size);
    numRounds += (otpack->iopack->io->num_rounds - pre_rounds);
    bytesSent += (otpack->iopack->io->counter - pre_comm);
    //std::cout<< "Send beacon 3\n";
}

void Peer::recv_cot(osuCrypto::block* recv_arr, int size, bool* sel){
    uint64_t pre_comm = otpack->iopack->io->counter;
    uint64_t pre_rounds = otpack->iopack->io->num_rounds;
    otpack->iknp->recv_cot(recv_arr, sel, size);
    numRounds += (otpack->iopack->io->num_rounds - pre_rounds);
    bytesSent += (otpack->iopack->io->counter - pre_comm);
}

Dealer::Dealer(std::string ip, int port) {
    this->consocket = socket(AF_INET, SOCK_STREAM, 0);
    if (consocket < 0) {
        perror("socket");
        exit(1);
    }
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip.c_str());
    if (connect(consocket, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("connect");
        exit(1);
    }
}

void Dealer::close() {
    if (useFile) {
        file.close();
    }
    else {
        ::close(consocket);
    }
}

GroupElement Dealer::recv_mask() {
    char buf[8];
    if (useFile) {
        this->file.read(buf, 8);
    } else {
        recv(consocket, buf, 8, MSG_WAITALL);
    }
    GroupElement g(*(uint64_t *)buf, bitlength);
    bytesReceived += 8;
    return g;
}

MultKey Dealer::recv_mult_key() {
    char buf[sizeof(MultKey)];
    if (useFile) {
        this->file.read(buf, sizeof(MultKey));
    } else {
        recv(consocket, buf, sizeof(MultKey), MSG_WAITALL);
    }
    MultKey k(*(MultKey *)buf);
    bytesReceived += sizeof(MultKey);
    return k;
}

osuCrypto::block Dealer::recv_block() {
    char buf[sizeof(osuCrypto::block)];
    if (useFile) {
        this->file.read(buf, sizeof(osuCrypto::block));
    } else {
        recv(consocket, buf, sizeof(osuCrypto::block), MSG_WAITALL);
    }
    osuCrypto::block b = *(osuCrypto::block *)buf;
    bytesReceived += sizeof(osuCrypto::block);
    return b;
}

GroupElement Dealer::recv_ge(int bl) {
    if (bl > 32) {
        char buf[8];
        if (useFile) {
            this->file.read(buf, 8);
        } else {
            recv(consocket, buf, 8, MSG_WAITALL);
        }
        GroupElement g(*(uint64_t *)buf, bl);
        bytesReceived += 8;
        return g;
    }
    else if (bl > 16) {
        char buf[4];
        if (useFile) {
            this->file.read(buf, 4);
        } else {
            recv(consocket, buf, 4, MSG_WAITALL);
        }
        GroupElement g(*(uint32_t *)buf, bl);
        bytesReceived += 4;
        return g;
    }
    else if (bl > 8) {
        char buf[2];
        if (useFile) {
            this->file.read(buf, 2);
        } else {
            recv(consocket, buf, 2, MSG_WAITALL);
        }
        GroupElement g(*(uint16_t *)buf, bl);
        bytesReceived += 2;
        return g;
    }
    else {
        char buf[1];
        if (useFile) {
            this->file.read(buf, 1);
        } else {
            recv(consocket, buf, 1, MSG_WAITALL);
        }
        GroupElement g(*(uint8_t *)buf, bl);
        bytesReceived += 1;
        return g;
    }
}

DCFKeyPack Dealer::recv_dcf_keypack(int Bin, int Bout, int groupSize) {
    DCFKeyPack kp;
    kp.Bin = Bin;
    kp.Bout = Bout;
    kp.groupSize = groupSize;

    kp.k = new block[Bin + 1];
    for (int i = 0; i < Bin + 1; ++i) {
        kp.k[i] = recv_block();
    }
    kp.g = new GroupElement[groupSize];
    for (int i = 0; i < groupSize; ++i) {
        kp.g[i] = recv_ge(Bout);
    }
    kp.v = new GroupElement[Bin * groupSize];
    for (int i = 0; i < Bin * groupSize; ++i) {
        kp.v[i] = recv_ge(Bout);
    }
    return kp;
}

DualDCFKeyPack Dealer::recv_ddcf_keypack(int Bin, int Bout, int groupSize) {
    DualDCFKeyPack kp;
    kp.Bin = Bin;
    kp.Bout = Bout;
    kp.groupSize = groupSize;
    kp.dcfKey = recv_dcf_keypack(Bin, Bout, groupSize);
    kp.sb = new GroupElement[groupSize];
    for (int i = 0; i < groupSize; ++i) {
        kp.sb[i] = recv_ge(Bout);
    }
    return kp;
}

MultKeyNew Dealer::recv_new_mult_key(int bw1, int bw2)
{
    MultKeyNew kp;
    kp.a = recv_ge(bw1 + bw2);
    kp.b = recv_ge(bw1 + bw2);
    kp.c = recv_ge(bw1 + bw2);
    kp.k1 = recv_dcf_keypack(bw2, bw1, 1);
    kp.k2 = recv_dcf_keypack(bw1, bw2, 1);
    kp.k3 = recv_dcf_keypack(bw2, bw1, 1);
    kp.k4 = recv_dcf_keypack(bw1, bw2, 1);

    return kp;
}

MatMulKey Dealer::recv_matmul_key(int Bin, int Bout, int s1, int s2, int s3) {
    MatMulKey k;
    k.Bin = Bin;
    k.Bout = Bout;
    k.s1 = s1;
    k.s2 = s2;
    k.s3 = s3;

    k.a = make_array<GroupElement>(s1, s2);
    k.b = make_array<GroupElement>(s2, s3);
    k.c = make_array<GroupElement>(s1, s3);

    for(int i = 0; i < s1; ++i) {
        for(int j = 0; j < s2; ++j) {
            Arr2DIdxRowM(k.a, s1, s2, i, j) = (party == SERVER ? GroupElement(prngShared.get<uint64_t>(), Bin) : recv_ge(Bin));
        }
    }
    
    for(int i = 0; i < s2; ++i) {
        for(int j = 0; j < s3; ++j) {
            Arr2DIdxRowM(k.b, s2, s3, i, j) = (party == SERVER ? GroupElement(prngShared.get<uint64_t>(), Bin) : recv_ge(Bin));
        }
    }

    for(int i = 0; i < s1; ++i) {
        for(int j = 0; j < s3; ++j) {
            Arr2DIdxRowM(k.c, s1, s3, i, j) = (party == SERVER ? GroupElement(prngShared.get<uint64_t>(), Bout) : recv_ge(Bout));
        }
    }

    return k;
}

Conv2DKey Dealer::recv_conv2d_key(int Bin, int Bout, int64_t N, int64_t H, int64_t W,
                int64_t CI, int64_t FH, int64_t FW,
                int64_t CO, int64_t zPadHLeft,
                int64_t zPadHRight, int64_t zPadWLeft,
                int64_t zPadWRight, int64_t strideH,
                int64_t strideW) {
    Conv2DKey k;
    k.Bin = Bin;
    k.Bout = Bout;
    k.N = N;
    k.H = H;
    k.W = W;
    k.CO = CO;
    k.CI = CI;
    k.FH = FH;
    k.FW = FW;
    k.zPadHLeft = zPadHLeft;
    k.zPadHRight = zPadHRight; 
    k.zPadWLeft = zPadWLeft;
    k.zPadWRight = zPadWRight;;
    k.strideH = strideH;
    k.strideW = strideW;

    int d0 = N;
    int d1 = ((H - FH + (zPadHLeft + zPadHRight)) / strideH) + 1;
    int d2 = ((W - FW + (zPadWLeft + zPadWRight)) / strideW) + 1;
    int d3 = CO;

    k.a = make_array<GroupElement>(N, H, W, CI);
    k.b = make_array<GroupElement>(FH, FW, CI, CO);
    k.c = make_array<GroupElement>(d0, d1, d2, d3);

    for(int n = 0; n < N; ++n) {
        for(int h = 0; h < H; ++h) {
            for(int w = 0; w < W; ++w) {
                for(int ci = 0; ci < CI; ++ci) {
                    Arr4DIdxRowM(k.a, N, H, W, CI, n, h, w, ci) = (party == SERVER ? GroupElement(prngShared.get<uint64_t>(), Bin) : recv_ge(Bin));
                }
            }
        }
    }

    for(int fh = 0; fh < FH; ++fh) {
        for(int fw = 0; fw < FW; ++fw) {
            for(int ci = 0; ci < CI; ++ci) {
                for(int co = 0; co < CO; ++co) {
                    Arr4DIdxRowM(k.b, FH, FW, CI, CO, fh, fw, ci, co) = (party == SERVER ? GroupElement(prngShared.get<uint64_t>(), Bin) : recv_ge(Bin));
                }
            }
        }
    }

    GroupElement *c = k.c;
    for(int i = 0; i < d0; ++i) {
        for(int j = 0; j < d1; ++j) {
            for(int k = 0; k < d2; ++k) {
                for(int l = 0; l < d3; ++l) {
                    Arr4DIdxRowM(c, d0, d1, d2, d3, i, j, k, l) = (party == SERVER ? GroupElement(prngShared.get<uint64_t>(), Bout) : recv_ge(Bout));
                }
            }
        }
    }
    return k;
}

ReluKeyPack Dealer::recv_relu_key(int Bin, int Bout) {
    int groupSize = 2;
    ReluKeyPack kp;
    kp.Bin = Bin;
    kp.Bout = Bout;
    kp.k = new osuCrypto::block[Bin + 1];
    kp.g = new GroupElement[groupSize];
    kp.v = new GroupElement[Bin * groupSize];
    // kp.dcfKey = recv_dcf_keypack(Bin, Bout, groupSize);
    for(int i = 0; i < Bin + 1; ++i) {
        kp.k[i] = recv_block();
    }
    for(int i = 0; i < groupSize; ++i) {
        kp.g[i] = recv_ge(Bout);
    }
    for(int i = 0; i < Bin * groupSize; ++i) {
        kp.v[i] = recv_ge(Bout);
    }
    kp.e_b0 = recv_ge(Bout);
    kp.e_b1 = recv_ge(Bout);
    kp.beta_b0 = recv_ge(Bout);
    kp.beta_b1 = recv_ge(Bout);
    kp.r_b = recv_ge(Bout);
    return kp;
}

MaxpoolKeyPack Dealer::recv_maxpool_key(int Bin, int Bout) {
    MaxpoolKeyPack kp;
    kp.Bin = Bin; 
    kp.Bout = Bout;
    kp.reluKey = recv_relu_key(Bin, Bout);
    kp.rb = recv_ge(Bout);
    return kp;
}

ScmpKeyPack Dealer::recv_scmp_keypack(int Bin, int Bout) {
    int groupSize = 1;
    ScmpKeyPack kp;
    kp.Bin = Bin;
    kp.Bout = Bout;
    kp.dualDcfKey = recv_ddcf_keypack(Bin-1, Bout, groupSize);
    kp.rb = recv_ge(Bout);
    return kp;
}

PublicDivKeyPack Dealer::recv_pubdiv_key(int Bin, int Bout) {
    int groupSize = 1;
    PublicDivKeyPack kp;
    kp.Bin = Bin;
    kp.Bout = Bout;
    kp.dualDcfKey = recv_ddcf_keypack(Bin, Bout, groupSize);
    kp.scmpKey = recv_scmp_keypack(Bin, Bout);
    kp.zb = recv_ge(Bout);
    return kp;
}

ARSKeyPack Dealer::recv_ars_key(int Bin, int Bout, int shift) {
    ARSKeyPack kp;
    kp.Bin = Bin;
    kp.Bout = Bout;
    kp.shift = shift;

    int dcfGroupSize = 1, ddcfGroupSize = 2;
    kp.dcfKey = recv_dcf_keypack(shift, Bout, dcfGroupSize);
    if (Bout > Bin - shift) {
        kp.dualDcfKey = recv_ddcf_keypack(Bin - 1, Bout, ddcfGroupSize);
    }
    kp.rb = recv_ge(Bout);
    return kp;
}

void Peer::sync() {
    char buf[1] = {1};
    send(sendsocket, buf, 1, 0);
    recv(recvsocket, buf, 1, MSG_WAITALL);
    bytesReceived += 1;
    bytesSent += 1;
    always_assert(buf[0] == 1);
}

/*
void Peer::send_cot(block delta, block* output_data, int size) {
    // block: long long int, send_cot_primitives: uint 64t, aka unsigned long
    uint64_t pre_comm = otpack->iopack->io->counter;
    uint64_t pre_rounds = otpack->iopack->io->num_rounds;
    otpack->iknp->send_cot(output_data, delta, size);
    numRounds += (otpack->iopack->io->num_rounds - pre_rounds);
    bytesSent += (otpack->iopack->io->counter - pre_comm);
}

void Peer::recv_cot(block *recv_arr, int size, uint8_t *sel) {
    uint64_t pre_comm = otpack->iopack->io->counter;
    uint64_t pre_rounds = otpack->iopack->io->num_rounds;
    otpack->iknp->recv_cot(recv_arr, (bool*)sel, size);
    numRounds += (otpack->iopack->io->num_rounds - pre_rounds);
    bytesSent += (otpack->iopack->io->counter - pre_comm);
}
*/

SignedPublicDivKeyPack Dealer::recv_signedpubdiv_key(int Bin, int Bout) {
    SignedPublicDivKeyPack kp;
    kp.d = recv_ge(Bin);
    kp.Bin = Bin;
    kp.Bout = Bout;
    int groupSize = 1;
    kp.dcfKey = recv_dcf_keypack(Bin, Bout, groupSize);
    kp.publicICkey = recv_publicIC_key(Bin, Bout);
    kp.scmpKey = recv_scmp_keypack(Bin, Bout);
    kp.A_share = recv_ge(Bin);
    kp.corr_share = recv_ge(Bout);
    kp.B_share = recv_ge(Bout);
    kp.rdiv_share = recv_ge(Bout);
    kp.rout_temp_share = recv_ge(Bout);
    kp.rout_share = recv_ge(Bout);
    return kp;
}

PublicICKeyPack Dealer::recv_publicIC_key(int Bin, int Bout) {
    PublicICKeyPack kp;
    kp.Bin = Bin;
    kp.Bout = Bout;
    int groupSize = 1;
    kp.dcfKey = recv_dcf_keypack(Bin, Bout, groupSize);
    kp.zb = recv_ge(Bout);
    return kp;
}


SplineKeyPack Dealer::recv_spline_key(int Bin, int Bout, int numPoly, int degree)
{
    SplineKeyPack kp;
    kp.Bin = Bin;
    kp.Bout = Bout;
    kp.numPoly = numPoly;
    kp.degree = degree;
    kp.dcfKey = recv_dcf_keypack(16, Bout, numPoly * (degree + 1));

    kp.p.resize(numPoly + 1);
    for(int i = 0; i < numPoly + 1; ++i) {
        kp.p[i] = recv_ge(Bin);
    }

    kp.e_b.resize(numPoly);
    for(int i = 0; i < numPoly; ++i) {
        kp.e_b[i].resize(degree + 1);
        for(int j = 0; j < degree + 1; ++j) {
            kp.e_b[i][j] = recv_ge(Bout);
        }
    }

    kp.beta_b.resize(numPoly * (degree + 1));
    for(int i = 0; i < numPoly * (degree + 1); ++i) {
        kp.beta_b[i] = recv_ge(Bout);
    }

    kp.r_b = recv_ge(Bout);
    return kp;
}
