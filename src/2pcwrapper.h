//
// Created by root on 3/8/23.
//

#include "group_element.h"
#include "comms.h"

using namespace osuCrypto;
using namespace sci;

void multiplexer(int party_id, uint8_t *sel, block *dataA, block *output,
                 int32_t size, Peer* player) __attribute__((optimize("O0")));

void multiplexer(int party_id, uint8_t *sel, uint64_t *dataA, uint64_t *output,
                 int32_t size, int32_t bw_x, int32_t bw_y, Peer* player) __attribute__((optimize("O0")));

void multiplexer(int party_id, uint8_t *sel, GroupElement *dataA, GroupElement *output,
                 int32_t size, Peer* player) __attribute__((optimize("O0")));

void multiplexer2(int party_id, uint8_t *sel, uint64_t *dataA, uint64_t *dataB, uint64_t *output,
                  int32_t size, int32_t bw_x, int32_t bw_y, Peer* player) __attribute__((optimize("O0")));

void multiplexer2(int party_id, uint8_t *control_bit, osuCrypto::block* dataA, osuCrypto::block* dataB,
                          osuCrypto::block* output, int32_t size, Peer* player) __attribute__((optimize("O0")));

void multiplexer2(int party_id, uint8_t *control_bit, GroupElement* dataA, GroupElement* dataB,
                          GroupElement* output, int32_t size, Peer* player) __attribute__((optimize("O0")));

void insecure_multiplexer2(int party_id, uint8_t *control_bit, GroupElement* dataA, GroupElement* dataB,
                           GroupElement* output, int32_t size, Peer* player);

void insecure_multiplexer(int party_id, uint8_t *control_bit, GroupElement* dataA,
                          GroupElement* output, int32_t size, Peer* player);

void and_wrapper(int party_id, GroupElement* dataA, GroupElement* dataB, GroupElement* output, int32_t size,
               Peer* player) __attribute__((optimize("O0")));

u8 and_wrapper(int party_id, GroupElement* dataA, GroupElement* dataB, Peer* player) __attribute__((optimize("O0")));

u8 and_wrapper(int party_id, u8 dataA, u8 dataB, Peer* player);

u8 and_wrapper(int party_id, u8 data, Peer* player);

u8 or_wrapper(int party_id, u8 dataA, u8 dataB, Peer* player);

u8 or_wrapper(int party_id, u8 data, Peer* player);

u8 cmp_2bit(int party_id, u8 a, u8 b, Peer* player);

u8 check_bit_overflow(int party_id, u8 x_share, u8 r_prev_share, Peer* player);
