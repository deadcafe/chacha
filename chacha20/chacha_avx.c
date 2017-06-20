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
 * 128 vec (AVX)
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

#define VEC_STORE_4BLOCKS(m,dst,src,off, a,b,c,d)                    \
        do {                                                         \
                __m128i _t0, _t1, _t2, _t3;                          \
                                                                     \
                v_##a = _mm_add_epi32(v_##a, c_##a);                 \
                v_##b = _mm_add_epi32(v_##b, c_##b);                 \
                v_##c = _mm_add_epi32(v_##c, c_##c);                 \
                v_##d = _mm_add_epi32(v_##d, c_##d);                 \
                                                                     \
                _t0 = _mm_unpacklo_epi32(v_##a, v_##b);              \
                _t1 = _mm_unpacklo_epi32(v_##c, v_##d);              \
                _t2 = _mm_unpackhi_epi32(v_##a, v_##b);              \
                _t3 = _mm_unpackhi_epi32(v_##c, v_##d);              \
                                                                     \
                v_##a = _mm_unpacklo_epi64(_t0, _t1);                \
                v_##b = _mm_unpackhi_epi64(_t0, _t1);                \
                v_##c = _mm_unpacklo_epi64(_t2, _t3);                \
                v_##d = _mm_unpackhi_epi64(_t2, _t3);                \
                                                                     \
                _t0 = _mm_xor_si128(v_##a, _mm_loadu_si128((const __m128i *) (src + off + 0))); \
                _mm_storeu_si128((__m128i *) (dst + off + 0), _t0);     \
                                                                        \
                _t1 = _mm_xor_si128(v_##b, _mm_loadu_si128((const __m128i *) (src + off + 64))); \
                _mm_storeu_si128((__m128i *) (dst + off + 64), _t1);    \
                                                                        \
                _t2 = _mm_xor_si128(v_##c, _mm_loadu_si128((const __m128i *) (src + off + 128))); \
                _mm_storeu_si128((__m128i *) (dst + off + 128), _t2);   \
                                                                        \
                _t3 = _mm_xor_si128(v_##d, _mm_loadu_si128((const __m128i *) (src + off + 192))); \
                _mm_storeu_si128((__m128i *) (dst + off + 192), _t3);   \
        } while (0)

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
         const __m128i xmm)
{
        uint8_t __attribute__((aligned(16))) buff[16];

        _mm_store_si128((__m128i *) buff,  xmm);
        HEXDUMP(msg, buff, sizeof(buff));
}

static inline void
dump_ctx(const char *msg,
         const __m128i xmm0,
         const __m128i xmm1,
         const __m128i xmm2,
         const __m128i xmm3)
{
        uint8_t __attribute__((aligned(16))) buff[64];

        _mm_store_si128((__m128i *) &buff[0],  xmm0);
        _mm_store_si128((__m128i *) &buff[16], xmm1);
        _mm_store_si128((__m128i *) &buff[32], xmm2);
        _mm_store_si128((__m128i *) &buff[48], xmm3);

        HEXDUMP(msg, buff, sizeof(buff));
}

#if 0
# define DUMP_CTX(m,x0,x1,x2,x3)	dump_ctx("AVX ctx " m,x0,x1,x2,x3)
#else
# define DUMP_CTX(m,x0,x1,x2,x3)
#endif

/*
 *
 */
void
chacha_avx(uint8_t *dst,
           const uint8_t *src,
           size_t len,
           const uint8_t *key,
           const uint8_t *salt,
           const uint8_t *iv)
{
        uint32_t __attribute__((aligned(16))) ctr_salt_iv[4];
        const __m128i ROT16 = _mm_set_epi8(13, 12, 15, 14,
                                           9,  8, 11, 10,
                                           5,  4,  7,  6,
                                           1,  0,  3,  2);

        const __m128i ROT8  = _mm_set_epi8(14, 13, 12, 15,
                                           10,  9,  8, 11,
                                           6,  5,  4,  7,
                                           2,  1,  0,  3);
        __m128i c_0, c_1, c_2, c_3;
        __m128i c_4, c_5, c_6, c_7;
        __m128i c_8, c_9, c_a, c_b;
        __m128i c_c, c_d, c_e, c_f;

        __m128i v_0, v_1, v_2, v_3;
        __m128i v_4, v_5, v_6, v_7;
        __m128i v_8, v_9, v_a, v_b;
        __m128i v_c, v_d, v_e, v_f;

        ctr_salt_iv[0] = 0;
        ctr_salt_iv[1] = *((const uint32_t *) salt);
        ctr_salt_iv[2] = *((const uint32_t *) &iv[0]);
        ctr_salt_iv[3] = *((const uint32_t *) &iv[4]);

        /* init parallel 4 blocks */
        if (len < 256) {
                /* set first counter */
                c_c = _mm_set_epi32(0, 0, 0, 1);
                c_f = c_e = c_d = _mm_xor_si128(c_d, c_d);
                
                goto PARALLEL_2;
        } else {
                __m128i tmp;

                /* "expand 32-byte k" */
                tmp = _mm_set_epi8(0x6b, 0x20, 0x65, 0x74,
                                   0x79, 0x62, 0x2d, 0x32,
                                   0x33, 0x20, 0x64, 0x6e,
                                   0x61, 0x70, 0x78, 0x65);
                c_0 = _mm_shuffle_epi32(tmp, 0);
                c_1 = _mm_shuffle_epi32(tmp, 0x55);
                c_2 = _mm_shuffle_epi32(tmp, 0xaa);
                c_3 = _mm_shuffle_epi32(tmp, 0xff);

                c_c = _mm_set_epi32(4, 3, 2, 1);

                tmp = _mm_loadu_si128((const __m128i *) &key[0]);
                c_4 = _mm_shuffle_epi32(tmp, 0);
                c_5 = _mm_shuffle_epi32(tmp, 0x55);
                c_6 = _mm_shuffle_epi32(tmp, 0xaa);
                c_7 = _mm_shuffle_epi32(tmp, 0xff);

                tmp = _mm_loadu_si128((const __m128i *) &key[16]);
                c_8 = _mm_shuffle_epi32(tmp, 0);
                c_9 = _mm_shuffle_epi32(tmp, 0x55);
                c_a = _mm_shuffle_epi32(tmp, 0xaa);
                c_b = _mm_shuffle_epi32(tmp, 0xff);

                tmp = _mm_loadu_si128((const __m128i *) ctr_salt_iv);
                c_d = _mm_shuffle_epi32(tmp, 0x55);
                c_e = _mm_shuffle_epi32(tmp, 0xaa);
                c_f = _mm_shuffle_epi32(tmp, 0xff);
        }

        DUMP_CTX("first", c_0, c_1, c_2, c_3);

        /* parallel 4 blocks */
        while (len >= 256) {
                v_0 = c_0;
                v_1 = c_1;
                v_2 = c_2;
                v_3 = c_3;

                v_4 = c_4;
                v_5 = c_5;
                v_6 = c_6;
                v_7 = c_7;

                v_8 = c_8;
                v_9 = c_9;
                v_a = c_a;
                v_b = c_b;

                v_c = c_c;
                v_d = c_d;
                v_e = c_e;
                v_f = c_f;

                DUMP_CTX("p4 0-3", c_0, c_1, c_2, c_3);
                DUMP_CTX("p4 4-7", c_4, c_5, c_6, c_7);
                DUMP_CTX("p4 8-b", c_8, c_9, c_a, c_b);
                DUMP_CTX("p4 c-f", c_c, c_d, c_e, c_f);

                for (unsigned i = 0; i < 10; i++) {
                        DOUBLE_ROUND(0, 1, 2, 3,
                                     4, 5, 6, 7,
                                     8, 9, a, b,
                                     c, d, e, f);
                }

                DUMP_CTX("p4 round 0-3", v_0, v_1, v_2, v_3);
                DUMP_CTX("p4 round 4-7", v_4, v_5, v_6, v_7);
                DUMP_CTX("p4 round 8-b", v_8, v_9, v_a, v_b);
                DUMP_CTX("p4 round c-f", v_c, v_d, v_e, v_f);

                VEC_STORE_4BLOCKS("avx LINE0 add", dst, src,  0, 0, 1, 2, 3);
                VEC_STORE_4BLOCKS("avx LINE1 add", dst, src, 16, 4, 5, 6, 7);
                VEC_STORE_4BLOCKS("avx LINE2 add", dst, src, 32, 8, 9, a, b);
                VEC_STORE_4BLOCKS("avx LINE3 add", dst, src, 48, c, d, e, f);

                const __m128i ctr_inc = _mm_set_epi32(4, 4, 4, 4);
                c_c = _mm_add_epi32(c_c, ctr_inc);

                src += 256;
                dst += 256;
                len -= 256;
        }

 PARALLEL_2:
        if (len) {
                /* parallel 2 blocks */
                v_0 = _mm_unpacklo_epi32(c_c, c_d);
                v_1 = _mm_unpacklo_epi32(c_e, c_f);
                v_3 = _mm_unpacklo_epi64(v_0, v_1);

                v_4 = _mm_load_si128((const __m128i *) ctr_salt_iv);
                v_3 = c_3 = _mm_or_si128(v_3, v_4);

                v_0 = c_0 =  _mm_set_epi8(0x6b, 0x20, 0x65, 0x74,
                                          0x79, 0x62, 0x2d, 0x32,
                                          0x33, 0x20, 0x64, 0x6e,
                                          0x61, 0x70, 0x78, 0x65);
                
                v_1 = c_1 = _mm_loadu_si128((const __m128i *) &key[0]);
                v_2 = c_2 = _mm_loadu_si128((const __m128i *) &key[16]);
                
        } else {
                return;
        }

        DUMP_CTX("continued 0-3", c_0, c_1, c_2, c_3);

        if (len >= 192) {
                v_4 = c_4 = c_0;
                v_5 = c_5 = c_1;
                v_6 = c_6 = c_2;
                v_7 = c_7 = _mm_add_epi32(c_3, _mm_set_epi32(0, 0, 0, 1));

                v_8 = c_8 = c_0;
                v_9 = c_9 = c_1;
                v_a = c_a = c_2;
                v_b = c_b = _mm_add_epi32(c_3, _mm_set_epi32(0, 0, 0, 2));

                v_c = c_c = c_0;
                v_d = c_d = c_1;
                v_e = c_e = c_2;
                v_f = c_f = _mm_add_epi32(c_3, _mm_set_epi32(0, 0, 0, 3));

                for (unsigned i = 0; i < 10; i++) {
                        VEC_DOUBLE_QUARTER_ROUND(0, 1, 2, 3);
                        VEC_DOUBLE_QUARTER_ROUND(4, 5, 6, 7);
                        VEC_DOUBLE_QUARTER_ROUND(8, 9, a, b);
                        VEC_DOUBLE_QUARTER_ROUND(c, d, e, f);
                }

                DUMP_CTX("round", v_0, v_1, v_2, v_3);

                VEC_ADD_PERMUTE(0, 1, 2, 3);
                VEC_ADD_PERMUTE(4, 5, 6, 7);
                VEC_ADD_PERMUTE(8, 9, a, b);
                VEC_ADD_PERMUTE(c, d, e, f);

                VEC_XOR_STORE(dst, src,   0, 0);
                VEC_XOR_STORE(dst, src,  16, 1);
                VEC_XOR_STORE(dst, src,  32, 2);
                VEC_XOR_STORE(dst, src,  48, 3);

                VEC_XOR_STORE(dst, src,  64, 4);
                VEC_XOR_STORE(dst, src,  80, 5);
                VEC_XOR_STORE(dst, src,  96, 6);
                VEC_XOR_STORE(dst, src, 112, 7);

                VEC_XOR_STORE(dst, src, 128, 8);
                VEC_XOR_STORE(dst, src, 144, 9);
                VEC_XOR_STORE(dst, src, 160, a);
                VEC_XOR_STORE(dst, src, 176, b);

                src += 192;
                dst += 192;
                len -= 192;

                v_0 = v_c;
                v_1 = v_d;
                v_2 = v_e;
                v_3 = v_f;
        } else if (len >= 128) {
                v_4 = c_4 = c_0;
                v_5 = c_5 = c_1;
                v_6 = c_6 = c_2;
                v_7 = c_7 = _mm_add_epi32(c_3, _mm_set_epi32(0, 0, 0, 1));

                v_8 = c_8 = c_0;
                v_9 = c_9 = c_1;
                v_a = c_a = c_2;
                v_b = c_b = _mm_add_epi32(c_3, _mm_set_epi32(0, 0, 0, 2));

                /*
                 * 2 blocks + a
                 */
                for (unsigned i = 0; i < 10; i++) {
                        VEC_DOUBLE_QUARTER_ROUND(0, 1, 2, 3);
                        VEC_DOUBLE_QUARTER_ROUND(4, 5, 6, 7);
                        VEC_DOUBLE_QUARTER_ROUND(8, 9, a, b);
                }

                VEC_ADD_PERMUTE(0, 1, 2, 3);
                VEC_ADD_PERMUTE(4, 5, 6, 7);
                VEC_ADD_PERMUTE(8, 9, a, b);

                VEC_XOR_STORE(dst, src,   0, 0);
                VEC_XOR_STORE(dst, src,  16, 1);
                VEC_XOR_STORE(dst, src,  32, 2);
                VEC_XOR_STORE(dst, src,  48, 3);

                VEC_XOR_STORE(dst, src,  64, 4);
                VEC_XOR_STORE(dst, src,  80, 5);
                VEC_XOR_STORE(dst, src,  96, 6);
                VEC_XOR_STORE(dst, src, 112, 7);

                src += 128;
                dst += 128;
                len -= 128;

                v_0 = v_8;
                v_1 = v_9;
                v_2 = v_a;
                v_3 = v_b;
        } else if (len >= 64) {
                v_4 = c_4 = c_0;
                v_5 = c_5 = c_1;
                v_6 = c_6 = c_2;
                v_7 = c_7 = _mm_add_epi32(c_3, _mm_set_epi32(0, 0, 0, 1));

                /*
                 * 1 block + a
                 */

                for (unsigned i = 0; i < 10; i++) {
                        VEC_DOUBLE_QUARTER_ROUND(0, 1, 2, 3);
                        VEC_DOUBLE_QUARTER_ROUND(4, 5, 6, 7);
                }

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
                /*
                 * 0 block + a
                 */
                for (unsigned i = 0; i < 10; i++) {
                        VEC_DOUBLE_QUARTER_ROUND(0, 1, 2, 3);
                }

                VEC_ADD_PERMUTE(0, 1, 2, 3);
        }

        DUMP_CTX("new 0-3", c_0, c_1, c_2, c_3);
        DUMP_CTX("new 4-7", c_4, c_5, c_6, c_7);
        DUMP_CTX("new 8-b", c_8, c_9, c_a, c_b);
        DUMP_CTX("new c-f", c_c, c_d, c_e, c_f);

        /*
         * 1 block
         */
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
