#include "mpc/api.h"

#include <cstring>
#include <chrono>
#include <stdexcept>
#include <thread>
#include <vector>

#include <sys/socket.h>

uint64_t evalMicroseconds = 0;
uint64_t reconstructMicroseconds = 0;
uint64_t dealerMicroseconds = 0;
uint64_t inputOfflineComm = 0;
uint64_t inputOnlineComm = 0;

bool localTruncation = false;
osuCrypto::PRNG prngShared(osuCrypto::sysRandomSeed());

namespace {

constexpr bool kParallelReconstruct = true;

}  // namespace

void StartComputation() {
    std::cerr << "=== COMPUTATION START ===\n\n";
    std::cerr << "bitlength = " << bitlength << std::endl;

    if (party != DEALER && peer != nullptr) {
        peer->sync();
        inputOfflineComm = (party == SERVER) ? peer->bytesSent
                                             : peer->bytesReceived;
        inputOnlineComm = (party == SERVER) ? peer->bytesReceived
                                            : peer->bytesSent;
        peer->bytesSent = 0;
        peer->bytesReceived = 0;
    }
}

int32_t numRounds = 0;

void EndComputation() {
    std::cerr << "\n=== COMPUTATION END ===\n\n";
    if (party != DEALER && peer != nullptr) {
        std::cerr << "Offline Communication = " << inputOfflineComm
                  << " bytes\n";
        std::cerr << "Online Rounds = " << numRounds << "\n";
        std::cerr << "Online Communication = "
                  << peer->bytesSent + peer->bytesReceived + inputOnlineComm
                  << " bytes\n";
        std::cerr << "Online Time = " << evalMicroseconds / 1000.0
                  << " milliseconds\n\n";
    } else if (server != nullptr && client != nullptr) {
        std::cerr << "Offline Communication = "
                  << server->bytesSent + client->bytesSent << " bytes\n";
        std::cerr << "Offline Time = " << dealerMicroseconds / 1000.0
                  << " milliseconds\n";
    }
    std::cerr << "=========\n";
}

void reconstruct(int32_t size, GroupElement* arr, int bw) {
    auto start = std::chrono::steady_clock::now();
    std::vector<uint64_t> tmp(size);
    if (kParallelReconstruct) {
        std::thread send_thread(&Peer::send_batched_input, peer, arr, size, bw);
        std::thread recv_thread(&Peer::recv_batched_input, peer, tmp.data(),
                                size, bw);
        send_thread.join();
        recv_thread.join();
    } else {
        peer->send_batched_input(arr, size, bw);
        peer->recv_batched_input(tmp.data(), size, bw);
    }
    for (int i = 0; i < size; i++) {
        arr[i] = arr[i] + tmp[i];
    }
    numRounds += 1;
    reconstructMicroseconds +=
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - start)
            .count();
}

void reconstruct(block* input) {
    auto start = std::chrono::steady_clock::now();
    peer->send_block(*input);
    *input = peer->recv_block() ^ *input;
    numRounds += 1;
    reconstructMicroseconds +=
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - start)
            .count();
}

void reconstruct(int32_t size, block* arr) {
    auto start = std::chrono::steady_clock::now();
    std::vector<block> tmp(size);
    if (kParallelReconstruct) {
        std::thread send_thread([&]() { peer->send_block(arr, size); });
        std::thread recv_thread([&]() { peer->recv_block(tmp.data(), size); });
        send_thread.join();
        recv_thread.join();
    } else {
        peer->send_block(arr, size);
        peer->recv_block(tmp.data(), size);
    }
    for (int i = 0; i < size; i++) {
        arr[i] = arr[i] ^ tmp[i];
    }
    numRounds += 1;
    reconstructMicroseconds +=
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - start)
            .count();
}

void reconstruct(block* block_input, u8* bit_arr, int bit_size) {
    if (bit_size < 0) {
        throw std::invalid_argument("reconstruct requires non-negative bit size");
    }

    auto start = std::chrono::steady_clock::now();
    const int block_bytes = static_cast<int>(sizeof(block));
    const int total_bytes = block_bytes + bit_size;
    std::vector<uint8_t> send_buf(total_bytes);
    std::vector<uint8_t> recv_buf(total_bytes);
    std::memcpy(send_buf.data(), block_input, block_bytes);
    if (bit_size > 0) {
        std::memcpy(send_buf.data() + block_bytes, bit_arr, bit_size);
    }

    auto send_buffer = [&]() {
        if (peer->useFile) {
            peer->file.write(reinterpret_cast<const char*>(send_buf.data()),
                             total_bytes);
        } else {
            send(peer->sendsocket, send_buf.data(), total_bytes, 0);
        }
    };
    auto recv_buffer = [&]() {
        if (peer->useFile) {
            peer->file.read(reinterpret_cast<char*>(recv_buf.data()),
                            total_bytes);
        } else {
            recv(peer->recvsocket, recv_buf.data(), total_bytes, MSG_WAITALL);
        }
    };

    // DPF layer CW opens are tiny (one block plus a few bits); spawning
    // threads for those small buffers costs more than the extra safety helps.
    if (kParallelReconstruct && total_bytes > 1024) {
        std::thread send_thread(send_buffer);
        std::thread recv_thread(recv_buffer);
        send_thread.join();
        recv_thread.join();
    } else {
        send_buffer();
        recv_buffer();
    }

    block remote_block;
    std::memcpy(&remote_block, recv_buf.data(), block_bytes);
    *block_input = *block_input ^ remote_block;
    for (int i = 0; i < bit_size; i++) {
        bit_arr[i] ^= recv_buf[block_bytes + i];
    }

    peer->bytesSent += total_bytes;
    peer->bytesReceived += total_bytes;
    peer->rounds += 2;
    numRounds += 1;
    reconstructMicroseconds +=
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - start)
            .count();
}

void reconstruct(u8* input) {
    auto start = std::chrono::steady_clock::now();
    peer->send_u8(*input);
    *input = peer->recv_u8() ^ *input;
    numRounds += 1;
    reconstructMicroseconds +=
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - start)
            .count();
}

void reconstruct(int32_t size, u8* arr) {
    auto start = std::chrono::steady_clock::now();
    std::vector<u8> tmp(size);
    if (kParallelReconstruct) {
        std::thread send_thread([&]() { peer->send_u8(arr, size); });
        std::thread recv_thread([&]() { peer->recv_u8(tmp.data(), size); });
        send_thread.join();
        recv_thread.join();
    } else {
        peer->send_u8(arr, size);
        peer->recv_u8(tmp.data(), size);
    }
    for (int i = 0; i < size; i++) {
        arr[i] = arr[i] ^ tmp[i];
    }
    numRounds += 1;
    reconstructMicroseconds +=
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - start)
            .count();
}

void reconstruct(GroupElement* input) {
    reconstruct(1, input, input->bitsize);
}
