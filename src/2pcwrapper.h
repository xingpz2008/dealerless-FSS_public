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

#include "group_element.h"
#include "comms.h"
#include "api.h"

using namespace osuCrypto;
using namespace sci;

void multiplexer(int party_id, uint8_t *sel, const block *dataA, block *output,
                 int32_t size, Peer* player);

void multiplexer(int party_id, uint8_t *sel, const uint64_t *dataA, uint64_t *output,
                 int32_t size, int32_t bw_x, int32_t bw_y, Peer* player);

void multiplexer(int party_id, uint8_t *sel, const GroupElement *dataA, GroupElement *output,
                 int32_t size, Peer* player);

void multiplexer2(int party_id, uint8_t *sel, const uint64_t *dataA, const uint64_t *dataB, uint64_t *output,
                  int32_t size, int32_t bw_x, int32_t bw_y, Peer* player);

void multiplexer2(int party_id, uint8_t *control_bit, const osuCrypto::block* dataA, const osuCrypto::block* dataB,
                          osuCrypto::block* output, int32_t size, Peer* player);

osuCrypto::block multiplexer2(int party_id, uint8_t control_bit,
                              const osuCrypto::block& dataA,
                              const osuCrypto::block& dataB,
                              Peer* player);

void multiplexer2(int party_id, uint8_t *control_bit, const GroupElement* dataA, const GroupElement* dataB,
                          GroupElement* output, int32_t size, Peer* player);

GroupElement multiplexer2(int party_id, uint8_t control_bit,
                          const GroupElement& dataA,
                          const GroupElement& dataB,
                          Peer* player);

void insecure_multiplexer2(int party_id, uint8_t *control_bit, const GroupElement* dataA, const GroupElement* dataB,
                           GroupElement* output, int32_t size, Peer* player);

void insecure_multiplexer(int party_id, uint8_t *control_bit, const GroupElement* dataA,
                          GroupElement* output, int32_t size, Peer* player);

void and_wrapper(int party_id, const GroupElement* dataA, const GroupElement* dataB, GroupElement* output, int32_t size,
               Peer* player);

u8 and_wrapper(int party_id, const GroupElement* dataA, const GroupElement* dataB, Peer* player);

u8 and_wrapper(int party_id, u8 dataA, u8 dataB, Peer* player);

void and_wrapper(int party_id, const u8* dataA, const u8* dataB, u8* output, int size, Peer* player);

u8 and_wrapper(int party_id, u8 data, Peer* player);

u8 or_wrapper(int party_id, u8 dataA, u8 dataB, Peer* player);

void or_wrapper(int party_id, const u8* dataA, const u8* dataB, u8* output, int size, Peer* player);

u8 or_wrapper(int party_id, u8 data, Peer* player);

u8 cmp_2bit(int party_id, u8 a, u8 b, Peer* player);

u8 cmp_2bit_opt(int party_id, u8 a, u8 b, Peer* player);

void cmp_2bit_opt(int party_id, const u8* a, const u8* b, u8* output, int size, Peer* player);

u8 check_bit_overflow(int party_id, u8 x_share, u8 r_prev_share, Peer* player);

GroupElement cross_term_gen(int party_id, const GroupElement* input, bool hold_arithmetic, Peer* player);

void cross_term_gen(int party_id, const GroupElement* input, GroupElement* output, bool hold_arithmetic, int size, Peer* player);

void beaver_mult_offline(int party_id, GroupElement* a, GroupElement* b, GroupElement* c, Peer* player, int size);

void beaver_mult_online(int party_id, GroupElement input0, GroupElement input1,
                        GroupElement a, GroupElement b, GroupElement c,
                        GroupElement* output, Peer* player);

GroupElement beaver_mult_online(int party_id, GroupElement input0, GroupElement input1,
                                GroupElement a, GroupElement b, GroupElement c,
                                Peer* player);

void beaver_mult_online(int party_id, GroupElement* input0, GroupElement* input1,
                        const GroupElement* a, const GroupElement* b, const GroupElement* c,
                        GroupElement* output, int size, Peer* player);

void B2A(int party_id, u8* x, GroupElement* y, int size, int bw_y, Peer* player);

GroupElement B2A(int party_id, u8 x, int bw_y, Peer* player);
