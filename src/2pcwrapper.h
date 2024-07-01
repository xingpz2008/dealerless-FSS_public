//
// Created by root on 3/8/23.
//

#include "group_element.h"
#include "comms.h"
#include "api.h"

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

void and_wrapper(int party_id, u8* dataA, u8* dataB, u8* output, int size, Peer* player);

u8 and_wrapper(int party_id, u8 data, Peer* player);

u8 or_wrapper(int party_id, u8 dataA, u8 dataB, Peer* player);

void or_wrapper(int party_id, u8* dataA, u8* dataB, u8* output, int size, Peer* player);

u8 or_wrapper(int party_id, u8 data, Peer* player);

u8 cmp_2bit(int party_id, u8 a, u8 b, Peer* player);

u8 cmp_2bit_opt(int party_id, u8 a, u8 b, Peer* player);

void cmp_2bit_opt(int party_id, u8* a, u8* b, u8* output, int size, Peer* player);

u8 check_bit_overflow(int party_id, u8 x_share, u8 r_prev_share, Peer* player);

GroupElement cross_term_gen(int party_id, GroupElement* input, bool hold_arithmetic, Peer* player);

void cross_term_gen(int party_id, GroupElement* input, GroupElement* output, bool hold_arithmetic, int size, Peer* player)__attribute__((optimize("O0")));

void beaver_mult_offline(int party_id, GroupElement* a, GroupElement* b, GroupElement* c, Peer* player, int size);

void beaver_mult_online(int party_id, GroupElement input0, GroupElement input1,
                        GroupElement a, GroupElement b, GroupElement c,
                        GroupElement* output, Peer* player);

void beaver_mult_online(int party_id, GroupElement* input0, GroupElement* input1,
                        GroupElement* a, GroupElement* b, GroupElement* c,
                        GroupElement* output, int size, Peer* player);

void B2A(int party_id, u8* x, GroupElement* y, int size, int bw_y, Peer* player);