#ifndef HXY_COMMON_H
#define HXY_COMMON_H
#include "define.h"
#include <x86intrin.h>
#include <cstring>
#include <vector>
#include <emp-tool/emp-tool.h>
#include <emp-ot/emp-ot.h>
#include <seal/seal.h>

#include <iostream>
#include <fstream>
#include <cstdint>
#include <cassert>
#include <chrono>

using namespace std;
using namespace seal;
using namespace std::chrono;

using emp::NetIO;
using emp::PRG;
using emp::block;

const __m128i zero_128 = _mm_set_epi64x(0, 0);
const __m128i one_128= _mm_set_epi64x(0, 1);

const __m256i zero_256 = _mm256_set_epi64x(0, 0, 0, 0);
const __m256i one_256 = _mm256_set_epi64x(0, 0, 0, 1);

inline void CCR_function_H_inplace(block & x, const AES_KEY _aes) {
    static const block MASK = emp::makeBlock(0xFFFFFFFFFFFFFFFF, 0x00);
    block tmp_block;
    x = tmp_block = _mm_shuffle_epi32(x, 78) ^ (x & MASK); // x = \sigma(x), tmp = \sigma(x)
    AES_ecb_encrypt_blks(&tmp_block, 1, &_aes); // x = \sigma(x), tmp = AES(\sigma(x))
    x ^= tmp_block; // x = \sigma(x) xor AES(\sigma(x))
}

inline block CCR_function_H(const block &x, const AES_KEY& _aes) {
    block tmp = x;
    CCR_function_H_inplace(tmp, _aes); // tmp = \sigma(x) xor AES(\sigma(x))
    return tmp;
}

inline uint8_t leftRotate(uint8_t x, uint8_t d) {
    d &= 7;
    return (x << d) | (x >> (8 - d));
}

inline uint8_t rightRotate(uint8_t x, uint8_t d) {
    d &= 7;
    return (x >> d) | (x << (8 - d));
}

inline uint16_t leftRotate(uint16_t x, uint8_t d) {
    d &= 15;
    return (x << d) | (x >> (16 - d));
}

inline uint16_t rightRotate(uint16_t x, uint8_t d) {
    d &= 15;
    return (x >> d) | (x << (16 - d));
}

inline uint32_t leftRotate(uint32_t x, uint8_t d) {
    d &= 31;
    return (x << d) | (x >> (32 - d));
}

inline uint32_t rightRotate(uint32_t x, uint8_t d) {
    d &= 31;
    return (x >> d) | (x << (32 - d));
}

inline uint64_t leftRotate(uint64_t x, uint8_t d) {
    d &= 63;
    return (x << d) | (x >> (64 - d));
}

inline uint64_t rightRotate(uint64_t x, uint8_t d) {
    d &= 63;
    return (x >> d) | (x << (64 - d));
}

inline __m128i leftRotate(__m128i x, uint8_t d) {
    d &= 127;
    __m128i ret;
    auto x_ptr = (uint64_t *) & x;
    auto ret_ptr = (uint64_t *) & ret;
    if (d < 64) {
        memcpy(ret_ptr, x_ptr, 2 * sizeof(uint64_t));
    }
    if (64 <= d) {
        memcpy(ret_ptr, x_ptr + 1, sizeof(uint64_t));
        memcpy(ret_ptr + 1, x_ptr, sizeof(uint64_t));
    }
    const uint8_t offset = d & 63;
    if (offset != 0) {
        const uint64_t mask_l = ((1ULL << offset) - 1) << (64 - offset);
        uint64_t tmp0 = (ret_ptr[0] & mask_l) >> (64 - offset),
                tmp1 = (ret_ptr[1] & mask_l) >> (64 - offset);
        ret_ptr[0] = (ret_ptr[0] << offset) | tmp1;
        ret_ptr[1] = (ret_ptr[1] << offset) | tmp0;
    }
    return ret;
}

inline __m128i rightRotate(__m128i x, uint8_t d) {
    d &= 127;
    return leftRotate(x, (128 - d) & 127);
}

inline __m256i leftRotate(__m256i x, uint8_t d) {
    __m256i ret;
    auto x_ptr = (uint64_t *) & x;
    auto ret_ptr = (uint64_t *) & ret;
    if (d < 64) {
        memcpy(ret_ptr, x_ptr, 4 * sizeof(uint64_t));
    }
    if (64 <= d && d < 128) {
        memcpy(ret_ptr, x_ptr + 3, sizeof(uint64_t));
        memcpy(ret_ptr + 1, x_ptr, 3 * sizeof(uint64_t));
    }
    if (128 <= d && d < 192) {
        memcpy(ret_ptr, x_ptr + 2, 2 * sizeof(uint64_t));
        memcpy(ret_ptr + 2, x_ptr, 2 * sizeof(uint64_t));
    }
    if (192 <= d) {
        memcpy(ret_ptr, x_ptr + 1, 3 * sizeof(uint64_t));
        memcpy(ret_ptr + 3, x_ptr, sizeof(uint64_t));
    }
    const uint8_t offset = d & 63;
    if (offset != 0) {
        const uint64_t mask_l = ((1ULL << offset) - 1) << (64 - offset);
        uint64_t tmp0 = (ret_ptr[0] & mask_l) >> (64 - offset),
                tmp1 = (ret_ptr[1] & mask_l) >> (64 - offset),
                tmp2 = (ret_ptr[2] & mask_l) >> (64 - offset),
                tmp3 = (ret_ptr[3] & mask_l) >> (64 - offset);
        ret_ptr[0] = (ret_ptr[0] << offset) | tmp3;
        ret_ptr[1] = (ret_ptr[1] << offset) | tmp0;
        ret_ptr[2] = (ret_ptr[2] << offset) | tmp1;
        ret_ptr[3] = (ret_ptr[3] << offset) | tmp2;
    }
    return ret;
}

inline __m256i rightRotate(__m256i x, uint8_t d) {
    return leftRotate(x, (256 - d) & 255);
}

template<typename T>
inline void elementwise_xor(const uint32_t len, const T * __restrict x, const T * __restrict y, T * __restrict z) {
    for (uint32_t i = 0; i < len; i++) {
        z[i] = (x[i] ^ y[i]);
    }
}

template<typename T>
inline void elementwise_xor(const uint32_t len, const T * __restrict x, const T y, T * __restrict z) {
    for (uint32_t i = 0; i < len; i++) {
        z[i] = (x[i] ^ y);
    }
}

template<typename T>
inline void elementwise_xor_inplace(const uint32_t len, T * __restrict x, const T y) {
    for (uint32_t i = 0; i < len; i++) {
        x[i] ^= y;
    }
}

template<typename T>
inline void elementwise_xor_inplace(const uint32_t len, T * __restrict x, const T * __restrict y) {
    for (uint32_t i = 0; i < len; i++) {
        x[i] ^= y[i];
    }
}

template<typename T>
inline void elementwise_and(const uint32_t len, const T * __restrict a, const T MOD_MASK, T * __restrict c) {
    for (uint32_t i = 0; i < len; i++)
        c[i] = a[i] & MOD_MASK;
}

template<typename T>
inline void elementwise_and(const uint32_t len, const T * __restrict a, const T * __restrict b, T * __restrict c) {
    for (uint32_t i = 0; i < len; i++)
        c[i] = a[i] & b[i];
}

template<typename T>
inline void elementwise_and_inplace(const uint32_t len, T * __restrict x, const T MOD_MASK) {
    for (uint32_t i = 0; i < len; i++) {
        x[i] &= MOD_MASK;
    }
}

template<typename T>
inline void elementwise_and_inplace(const uint32_t len, T * __restrict x, const T * __restrict y) {
    for (uint32_t i = 0; i < len; i++) {
        x[i] &= y[i];
    }
}

template<typename T>
inline void get_fand_z(const uint32_t dim, T * __restrict z, const uint8_t id,
                       T * __restrict d0, T * __restrict e0,
                       const T * __restrict mt_x, const T * __restrict mt_y, const T * __restrict mt_z) {
    if (id == 1)
        elementwise_and(dim, d0, e0, z);
    else
        memset(z, 0, dim);

    elementwise_and_inplace(dim, d0, mt_y);
    elementwise_and_inplace(dim, e0, mt_x);
    elementwise_xor_inplace(dim, z, d0);
    elementwise_xor_inplace(dim, z, e0);
    elementwise_xor_inplace(dim, z, mt_z);
//    for (uint32_t i = 0; i < dim; i++) {
//        z[i] = (id & d0[i] & e0[i]) ^ (d0[i] & mt_y[i]) ^ (e0[i] & mt_x[i]) ^ mt_z[i];
//    }
}

template<typename T1, typename T2>
inline void elementwise_copy(const uint32_t len, const T1 * __restrict x, T2 * __restrict y) {
    for (uint32_t i = 0; i < len; i++) {
        y[i] = x[i];
    }
}

template<typename T>
inline void elementwise_add(const uint32_t len, const T * __restrict a, const T * __restrict b, T * __restrict c) {
    for (uint32_t i = 0; i < len; i++) {
        c[i] = a[i] + b[i];
    }
}

template<typename T>
inline void elementwise_add_inplace(const uint32_t len, T * __restrict a, const T * __restrict b) {
    for (uint32_t i = 0; i < len; i++) {
        a[i] += b[i];
    }
}

template<typename T>
inline void elementwise_addmod(const uint32_t len, const T * __restrict a, const T * __restrict b, T * __restrict c, const T MOD_MASK) {
    for (uint32_t i = 0; i < len; i++) {
        c[i] = (a[i] + b[i]) & MOD_MASK;
    }
}

template<typename T>
inline void elementwise_addmod_inplace(const uint32_t len, T * __restrict a, const T * __restrict b, const T MOD_MASK) {
    for (uint32_t i = 0; i < len; i++) {
        a[i] = (a[i] + b[i]) & MOD_MASK;
    }
}

template<typename T>
inline void elementwise_mulmod_inplace(const uint32_t len, T * __restrict a, const T * __restrict b, const T MOD_MASK) {
    for (uint32_t i = 0; i < len; i++) {
        a[i] = (a[i] * b[i]) & MOD_MASK;
    }
}

template<typename T>
inline void elementwise_mulmod_inplace(const uint32_t len, T * __restrict a, const T b, const T MOD_MASK) {
    for (uint32_t i = 0; i < len; i++) {
        a[i] = (a[i] * b) & MOD_MASK;
    }
}

template<typename T>
inline void elementwise_mulmod(const uint32_t len, const T * __restrict a, const T * __restrict b, T * __restrict c, const T MOD_MASK) {
    for (uint32_t i = 0; i < len; i++) {
        c[i] = (a[i] * b[i]) & MOD_MASK;
    }
}

template<typename T>
inline void elementwise_sub(const uint32_t len, const T * __restrict a, const T * __restrict b, T * __restrict c) {
    for (uint32_t i = 0; i < len; i++) {
        c[i] = (a[i] - b[i]);
    }
}


template<typename T>
inline void elementwise_submod(const uint32_t len, const T * __restrict a, const T * __restrict b, T * __restrict c, const T MOD_MASK) {
    for (uint32_t i = 0; i < len; i++) {
        c[i] = (a[i] - b[i]) & MOD_MASK;
    }
}

template<typename T>
inline void elementwise_sub_inplace(const uint32_t len, T * __restrict a, const T * __restrict b) {
    for (uint32_t i = 0; i < len; i++) {
        a[i] = (a[i] - b[i]);
    }
}

template<typename T>
inline void elementwise_submod_inplace(const uint32_t len, T * __restrict a, const T b, const T MOD_MASK) {
    for (uint32_t i = 0; i < len; i++) {
        a[i] = (a[i] - b) & MOD_MASK;
    }
}

template<typename T>
inline void elementwise_submod_inplace(const uint32_t len, T * __restrict a, const T * __restrict b, const T MOD_MASK) {
    for (uint32_t i = 0; i < len; i++) {
        a[i] = (a[i] - b[i]) & MOD_MASK;
    }
}

inline void compress_bits_into_uint8(const bool * __restrict bits_ptr, uint8_t * __restrict data_ptr, uint32_t len) {
    const uint64_t mask = 0x0101010101010101ULL;
    uint64_t * bits_u64_ptr = (uint64_t *) bits_ptr;
    for (uint32_t i = 0; i < len; i++) {
        data_ptr[i] = _pext_u64(bits_u64_ptr[i], mask);
    }
}

inline void decompress_bits_from_uint8(const uint8_t * __restrict data_ptr, bool * __restrict bits_ptr, uint32_t len) {
    const uint64_t mask = 0x0101010101010101ULL;
    uint64_t * bits_u64_ptr = (uint64_t *) bits_ptr;
    for (uint32_t i = 0; i < len; i++) {
        bits_u64_ptr[i] = _pdep_u64((uint64_t)data_ptr[i], mask);
    }
}

void send_bool_vct(const bool * x, const uint32_t len, NetIO * empIO);

void recv_bool_vct(bool * x, const uint32_t len, NetIO * empIO);

void fake_LUT(const uint32_t party_id, const uint32_t len, const uint8_t * x, const uint64_t * y, uint64_t * z, const uint32_t input_bw, const uint32_t output_bw, NetIO * IO);

void send_u64_vct(const uint64_t * x, const uint32_t len, const uint32_t bw, NetIO * empIO);
void recv_u64_vct(uint64_t * x, const uint32_t len, const uint32_t bw, NetIO * empIO);

void send_uint8_vct(const uint8_t *  x, const uint32_t len, const uint32_t bw, NetIO * IO);
void recv_uint8_vct(uint8_t * x, const uint32_t len, const uint32_t bw, NetIO * IO);

void fake_matmul(const uint32_t party_id, const uint32_t M, const uint32_t N, const uint32_t K, const uint64_t * __restrict x, const uint64_t * __restrict y, uint64_t * __restrict z, NetIO * IO);
void fake_bole(const uint32_t party_id, const uint32_t N, const uint64_t * __restrict x, const uint64_t * __restrict y, uint64_t * __restrict z, NetIO * IO);

uint64_t mulmod(uint64_t x, uint64_t y, uint64_t mod);
uint64_t fast_pow(uint64_t base, uint64_t times, uint64_t mod);
uint64_t get_error(uint64_t x, uint64_t y);
#endif // HXY_COMMON_H