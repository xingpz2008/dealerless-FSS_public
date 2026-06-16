#pragma once

#include "mpc/comms.h"
#include "commons/group_element.h"

#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <iostream>

#define MASK_PAIR(x) x, x##_mask

extern int32_t bitlength;
extern int32_t numRounds;

extern uint64_t evalMicroseconds;
extern uint64_t reconstructMicroseconds;
extern uint64_t dealerMicroseconds;
extern uint64_t inputOfflineComm;
extern uint64_t inputOnlineComm;

extern bool localTruncation;

inline void ClearMemSecret1(int32_t, MASK_PAIR(GroupElement* arr)) {
    delete[] arr;
    delete[] arr_mask;
}

inline void ClearMemSecret2(int32_t, int32_t, MASK_PAIR(GroupElement* arr)) {
    delete[] arr;
    delete[] arr_mask;
}

inline void ClearMemSecret3(int32_t, int32_t, int32_t,
                            MASK_PAIR(GroupElement* arr)) {
    delete[] arr;
    delete[] arr_mask;
}

inline void ClearMemSecret4(int32_t, int32_t, int32_t, int32_t,
                            MASK_PAIR(GroupElement* arr)) {
    delete[] arr;
    delete[] arr_mask;
}

inline void ClearMemSecret5(int32_t, int32_t, int32_t, int32_t, int32_t,
                            MASK_PAIR(GroupElement* arr)) {
    delete[] arr;
    delete[] arr_mask;
}

inline void ClearMemPublic1(int32_t, int32_t* arr) { delete[] arr; }
inline void ClearMemPublic2(int32_t, int32_t, int32_t* arr) { delete[] arr; }
inline void ClearMemPublic3(int32_t, int32_t, int32_t, int32_t* arr) {
    delete[] arr;
}
inline void ClearMemPublic4(int32_t, int32_t, int32_t, int32_t,
                            int32_t* arr) {
    delete[] arr;
}
inline void ClearMemPublic5(int32_t, int32_t, int32_t, int32_t, int32_t,
                            int32_t* arr) {
    delete[] arr;
}

inline GroupElement funcSSCons(uint64_t val) { return GroupElement(val, 64); }

void StartComputation();
void EndComputation();

void reconstruct(int32_t size, GroupElement* arr, int bw);
void reconstruct(GroupElement* input);
void reconstruct(u8* input);
void reconstruct(int32_t size, u8* arr);
void reconstruct(block* input);
void reconstruct(int32_t size, block* arr);
void reconstruct(block* block_input, u8* bit_arr, int bit_size);

inline void assert_failed(const char* file, int line, const char* function,
                          const char* expression) {
    std::cout << "Assertion failed: " << expression << " in " << function
              << " at " << file << ":" << line << std::endl;
    std::exit(1);
}

#define always_assert(expr) \
    (static_cast<bool>(expr) ? void(0) : assert_failed(__FILE__, __LINE__, __PRETTY_FUNCTION__, #expr))
