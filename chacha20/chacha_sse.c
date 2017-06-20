/*
 * Copyright (c) 2017, deadcafe.beef@gmail.com
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *   3. Neither the name of the project nor the names of its contributors
 *      may be used to endorse or promote products derived from this software
 *      without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <features.h>
#include <x86intrin.h>

#include "chacha.h"
#include "chacha_dbg.h"
/********************************************************************************
 * 128 vec (SSE)
 ********************************************************************************/
#define VEC_PLUS(a,b)		_mm_add_epi32(a, b)
#define VEC_XOR(a,b)		_mm_xor_si128(a, b)
#define VEC_ROTATE_LEFT_16(a)	_mm_shuffle_epi8(a, ROT16)
#define VEC_ROTATE_LEFT_12(a)	_mm_or_si128(_mm_slli_epi32(a, 12),  \
                                             _mm_srli_epi32(a, 20))
#define VEC_ROTATE_LEFT_8(a)	_mm_shuffle_epi8(a, ROT8)
#define VEC_ROTATE_LEFT_7(a)	_mm_or_si128(_mm_slli_epi32(a, 7), \
                                             _mm_srli_epi32(a, 25))
#define VEC_ROTATE_RIGHT_ALL(v0,v1,v2,v3)                       \
        do {                                                    \
                typeof(v1) _x, _y;                              \
                _x = _mm_srli_si128(v1, 4);                     \
                _y = _mm_slli_si128(v1, 12);                    \
                v1 = _mm_or_si128(_x, _y);                      \
                                                                \
                _x = _mm_srli_si128(v2, 8);                     \
                _y = _mm_slli_si128(v2, 8);                     \
                v2 = _mm_or_si128(_x, _y);                      \
                                                                \
                _x = _mm_srli_si128(v3, 12);                    \
                _y = _mm_slli_si128(v3, 4);                     \
                v3 = _mm_or_si128(_x, _y);                      \
        } while(0)

#define VEC_ROTATE_LEFT_ALL(v0,v1,v2,v3)                        \
        do {                                                    \
                typeof(v1) _x, _y;                              \
                _x = _mm_slli_si128(v1, 4);                     \
                _y = _mm_srli_si128(v1, 12);                    \
                v1 = _mm_or_si128(_x, _y);                      \
                                                                \
                _x = _mm_slli_si128(v2, 8);                     \
                _y = _mm_srli_si128(v2, 8);                     \
                v2 = _mm_or_si128(_x, _y);                      \
                                                                \
                _x = _mm_slli_si128(v3, 12);                    \
                _y = _mm_srli_si128(v3, 4);                     \
                v3 = _mm_or_si128(_x, _y);                      \
                                                                \
       } while(0)

/*
 *
 */
#define PLUS(a,b)		VEC_PLUS(a,b)
#define XOR(a,b)		VEC_XOR(a,b)
#define ROTATE_LEFT_16(a)	VEC_ROTATE_LEFT_16(a)
#define ROTATE_LEFT_12(a)	VEC_ROTATE_LEFT_12(a)
#define ROTATE_LEFT_8(a)	VEC_ROTATE_LEFT_8(a)
#define ROTATE_LEFT_7(a)	VEC_ROTATE_LEFT_7(a)

#include "chacha_round.h"


#define VEC_ADD_PERMUTE(a,b,c,d)                                \
        do {                                                    \
                v_##a = _mm_add_epi32(v_##a, c_##a);            \
                v_##b = _mm_add_epi32(v_##b, c_##b);            \
                v_##c = _mm_add_epi32(v_##c, c_##c);            \
                v_##d = _mm_add_epi32(v_##d, c_##d);            \
        } while (0)

#define	VEC_XOR_STORE(dst, src, off, r)                                 \
        do {                                                            \
                _mm_storeu_si128((__m128i *) (dst + off),               \
                                 _mm_xor_si128(v_##r, _mm_loadu_si128((const __m128i *) (src + off)))); \
        } while (0)

/*
 *
 */
static inline void
dump_reg(const char *msg,
         __m128i xmm)
{
        uint8_t __attribute__((aligned(16))) buff[16];

        _mm_store_si128((__m128i *) buff,  xmm);
        HEXDUMP(msg, buff, sizeof(buff));
}

static inline void
dump_ctx(const char *msg,
         __m128i xmm0,
         __m128i xmm1,
         __m128i xmm2,
         __m128i xmm3)
{
        uint8_t __attribute__((aligned(16))) buff[64];

        _mm_store_si128((__m128i *) &buff[0],  xmm0);
        _mm_store_si128((__m128i *) &buff[16], xmm1);
        _mm_store_si128((__m128i *) &buff[32], xmm2);
        _mm_store_si128((__m128i *) &buff[48], xmm3);

        HEXDUMP(msg, buff, sizeof(buff));
}

#if 0
# define DUMP_CTX(m,x0,x1,x2,x3)	dump_ctx("SSE ctx " m,x0,x1,x2,x3)
#else
# define DUMP_CTX(m,x0,x1,x2,x3)
#endif

/*
 *
 */
void
chacha_sse(uint8_t *dst,
           const uint8_t *src,
           size_t len,
           const uint8_t *key,
           const uint8_t *salt,
           const uint8_t *iv)
{
        uint32_t __attribute__((aligned(16))) ctr_salt_iv[4];

        ctr_salt_iv[0] = 0;
        ctr_salt_iv[1] = *((const uint32_t *) salt);
        ctr_salt_iv[2] = *((const uint32_t *) &iv[0]);
        ctr_salt_iv[3] = *((const uint32_t *) &iv[4]);

        const __m128i ROT16 = _mm_set_epi8(13, 12, 15, 14,
                                           9,  8, 11, 10,
                                           5,  4,  7,  6,
                                           1,  0,  3,  2);
        const __m128i ROT8  = _mm_set_epi8(14, 13, 12, 15,
                                           10,  9,  8, 11,
                                           6,  5,  4,  7,
                                           2,  1,  0,  3);
        const __m128i c_0 = _mm_set_epi8(0x6b, 0x20, 0x65, 0x74,
                                         0x79, 0x62, 0x2d, 0x32,
                                         0x33, 0x20, 0x64, 0x6e,
                                         0x61, 0x70, 0x78, 0x65);
        const __m128i c_1 = _mm_loadu_si128((const __m128i *) &key[0]);
        const __m128i c_2 = _mm_loadu_si128((const __m128i *) &key[16]);
        const __m128i c_4 = c_0;
        const __m128i c_5 = c_1;
        const __m128i c_6 = c_2;
        __m128i c_3, c_7;

        __m128i v_0, v_1, v_2, v_3;
        __m128i v_4, v_5, v_6, v_7;

        c_3 = _mm_load_si128((const __m128i *) ctr_salt_iv);
        c_3 = _mm_add_epi32(c_3, _mm_set_epi32(0, 0, 0, 1));

        /* parallel 2 blocks */
        while (len >= 128) {
                v_0 = c_0;
                v_1 = c_1;
                v_2 = c_2;
                v_3 = c_3;
                v_4 = c_4;
                v_5 = c_5;
                v_6 = c_6;
                v_7 = c_7 = _mm_add_epi32(c_3, _mm_set_epi32(0, 0, 0, 1));

                for (unsigned i = 0; i < 10; i++) {
                        VEC_DOUBLE_QUARTER_ROUND(0, 1, 2, 3);
                        VEC_DOUBLE_QUARTER_ROUND(4, 5, 6, 7);
                }
                DUMP_CTX("round", v_0, v_1, v_2, v_3);

                VEC_ADD_PERMUTE(0, 1, 2, 3);
                VEC_ADD_PERMUTE(4, 5, 6, 7);

                VEC_XOR_STORE(dst, src,   0, 0);
                VEC_XOR_STORE(dst, src,  16, 1);
                VEC_XOR_STORE(dst, src,  32, 2);
                VEC_XOR_STORE(dst, src,  48, 3);

                VEC_XOR_STORE(dst, src,  64, 4);
                VEC_XOR_STORE(dst, src,  80, 5);
                VEC_XOR_STORE(dst, src,  96, 6);
                VEC_XOR_STORE(dst, src, 112, 7);

                c_3 = _mm_add_epi32(c_3, _mm_set_epi32(0, 0, 0, 2));

                src += 128;
                dst += 128;
                len -= 128;
        }

        if (!len)
                return;

        if (len >= 64) {
                v_0 = c_0;
                v_1 = c_1;
                v_2 = c_2;
                v_3 = c_3;
                v_4 = c_4;
                v_5 = c_5;
                v_6 = c_6;
                v_7 = c_7 = _mm_add_epi32(c_3, _mm_set_epi32(0, 0, 0, 1));

                for (unsigned i = 0; i < 10; i++) {
                        VEC_DOUBLE_QUARTER_ROUND(0, 1, 2, 3);
                        VEC_DOUBLE_QUARTER_ROUND(4, 5, 6, 7);
                }
                DUMP_CTX("round", v_0, v_1, v_2, v_3);

                VEC_ADD_PERMUTE(0, 1, 2, 3);
                VEC_ADD_PERMUTE(4, 5, 6, 7);

                VEC_XOR_STORE(dst, src,   0, 0);
                VEC_XOR_STORE(dst, src,  16, 1);
                VEC_XOR_STORE(dst, src,  32, 2);
                VEC_XOR_STORE(dst, src,  48, 3);

                src += 64;
                dst += 64;
                len -= 64;

                v_0 = v_4;
                v_1 = v_5;
                v_2 = v_6;
                v_3 = v_7;
        } else {
                v_0 = c_0;
                v_1 = c_1;
                v_2 = c_2;
                v_3 = c_3;

                for (unsigned i = 0; i < 10; i++) {
                        VEC_DOUBLE_QUARTER_ROUND(0, 1, 2, 3);
                }
                DUMP_CTX("round", v_0, v_1, v_2, v_3);

                VEC_ADD_PERMUTE(0, 1, 2, 3);
        }

        if (len >= 48) {
                VEC_XOR_STORE(dst, src,  0, 0);
                VEC_XOR_STORE(dst, src, 16, 1);
                VEC_XOR_STORE(dst, src, 32, 2);

                src += 48;
                dst += 48;
                len -= 48;

                v_0 = v_3;
        } else if (len >= 32) {
                VEC_XOR_STORE(dst, src,  0, 0);
                VEC_XOR_STORE(dst, src, 16, 1);

                src += 32;
                dst += 32;
                len -= 32;

                v_0 = v_2;
        } else if (len >= 16) {
                VEC_XOR_STORE(dst, src,  0, 0);

                src += 16;
                dst += 16;
                len -= 16;

                v_0 = v_1;
        }

        if (len) {
                uint8_t __attribute__((aligned(16))) buf[16];

                _mm_store_si128((__m128i *) buf, v_0);
                for (unsigned i = 0; i < len; i++)
                        dst[i] = buf[i] ^ src[i];
        }
}
