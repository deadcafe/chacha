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

#include "chacha.h"
#include "chacha_dbg.h"

#define ADD_XOR_ROT(a,b,c,r)	VEC256_ADD_XOR_ROT(a,b,c,r)
#define ROT_RIGHT(a,r)		VEC256_ROT_RIGHT(a,r)
#define ROT_LEFT(a,r)		VEC256_ROT_LEFT(a,r)

#include "chacha_round.h"

#define VEC8_ROT(a,imm) _mm256_or_si256(_mm256_slli_epi32(a,imm),_mm256_srli_epi32(a,(32-imm)))

#define VEC8_LINE1(a,b,c,d)                                             \
        do {                                                            \
                x_##a = _mm256_add_epi32(x_##a, x_##b); \
                x_##d = _mm256_shuffle_epi8(_mm256_xor_si256(x_##d, x_##a), rot16); \
        } while (0)

#define VEC8_LINE2(a,b,c,d)                                             \
        do {                                                            \
                x_##c = _mm256_add_epi32(x_##c, x_##d);                 \
                x_##b = VEC8_ROT(_mm256_xor_si256(x_##b, x_##c), 12);   \
        } while (0)

#define VEC8_LINE3(a,b,c,d)                                             \
        do {                                                            \
                x_##a = _mm256_add_epi32(x_##a, x_##b);                 \
                x_##d = _mm256_shuffle_epi8(_mm256_xor_si256(x_##d, x_##a), rot8); \
        } while (0)

#define VEC8_LINE4(a,b,c,d)                                             \
        do {                                                            \
                x_##c = _mm256_add_epi32(x_##c, x_##d);                 \
                x_##b = VEC8_ROT(_mm256_xor_si256(x_##b, x_##c), 7);    \
        } while (0)

#define VEC8_ROUND(a1,b1,c1,d1, a2,b2,c2,d2, a3,b3,c3,d3, a4,b4,c4,d4)  \
        do {                                                            \
                VEC8_LINE1(a1,b1,c1,d1);                                \
                VEC8_LINE1(a2,b2,c2,d2);                                \
                VEC8_LINE1(a3,b3,c3,d3);                                \
                VEC8_LINE1(a4,b4,c4,d4);                                \
                                                                        \
                VEC8_LINE2(a1,b1,c1,d1);                                \
                VEC8_LINE2(a2,b2,c2,d2);                                \
                VEC8_LINE2(a3,b3,c3,d3);                                \
                VEC8_LINE2(a4,b4,c4,d4);                                \
                                                                        \
                VEC8_LINE3(a1,b1,c1,d1);                                \
                VEC8_LINE3(a2,b2,c2,d2);                                \
                VEC8_LINE3(a3,b3,c3,d3);                                \
                VEC8_LINE3(a4,b4,c4,d4);                                \
                                                                        \
                VEC8_LINE4(a1,b1,c1,d1);                                \
                VEC8_LINE4(a2,b2,c2,d2);                                \
                VEC8_LINE4(a3,b3,c3,d3);                                \
                VEC8_LINE4(a4,b4,c4,d4);                                \
        } while (0)








/*
 *
 */
static inline void
dump_ctx(const char *msg,
         __m256i ymm0,
         __m256i ymm1,
         __m256i ymm2,
         __m256i ymm3)
{
        uint8_t __attribute__((aligned(32))) buff[128];

        _mm256_store_si256((__m256i *) &buff[0],  ymm0);
        _mm256_store_si256((__m256i *) &buff[32], ymm1);
        _mm256_store_si256((__m256i *) &buff[64], ymm2);
        _mm256_store_si256((__m256i *) &buff[96], ymm3);

        HEXDUMP(msg, buff, sizeof(buff));
}

#define PERMUTE2X128(d0,d1,d2,d3,s0,s1,s2,s3)                         \
        do {                                                          \
                d0 = _mm256_permute2x128_si256(s0, s1, 0x20);         \
                d2 = _mm256_permute2x128_si256(s0, s1, 0x31);         \
                d1 = _mm256_permute2x128_si256(s2, s3, 0x20);         \
                d3 = _mm256_permute2x128_si256(s2, s3, 0x31);         \
        } while (0)




/*
 *
 */
void
chacha_avx2(uint8_t *dst,
            const uint8_t *src,
            size_t len,
            const uint8_t *key,
            const uint8_t *salt,
            const uint8_t *iv)
{
        __m256i c_0;
        __m256i c_1;
        __m256i c_2;
        __m256i c_3;
        __m256i c_4;
        __m256i c_5;
        __m256i c_6;
        __m256i c_7;
        __m256i c_8;
        __m256i c_9;
        __m256i c_10;
        __m256i c_11;
        __m256i c_12;
        __m256i c_13;
        __m256i c_14;
        __m256i c_15;

        /* init */
        {
                const uint8_t __attribute__((aligned(32))) SIGMA[32] =
                        "expand 32-byte k""expand 32-byte k";
                uint32_t __attribute__((aligned(32))) ctr_salt_iv[8];
                __m256i x, y;

                ctr_salt_iv[0] = 1;
                ctr_salt_iv[1] = *((const uint32_t *) salt);
                ctr_salt_iv[2] = *((const uint32_t *) &iv[0]);
                ctr_salt_iv[3] = *((const uint32_t *) &iv[4]);
                ctr_salt_iv[4] = 2;
                ctr_salt_iv[5] = ctr_salt_iv[1];
                ctr_salt_iv[6] = ctr_salt_iv[2];
                ctr_salt_iv[7] = ctr_salt_iv[3];

                c_0 = _mm256_load_si256((const __m256i *) SIGMA);
                x   = _mm256_loadu_si256((const __m256i *) key);
                y   = _mm256_set_epi32(0, 1, 2, 3, 0, 1, 2, 3);
                c_1 = _mm256_permutevar8x32_epi32(x, y);
                y   = _mm256_set_epi32(4, 5, 6, 7, 4, 5, 6, 7);
                c_2 = _mm256_permutevar8x32_epi32(x, y);
                c_3 = _mm256_load_si256((const __m256i *) ctr_salt_iv);

                if (len > 384) {
                        c_12 = c_8 = c_4 = c_0;
                        c_13 = c_9 = c_5 = c_1;
                        c_14 = c_10= c_6 = c_2;

                        ctr_salt_iv[0] = 3;
                        ctr_salt_iv[4] = 4;
                        c_7 = _mm256_load_si256((const __m256i *) ctr_salt_iv);

                        ctr_salt_iv[0] = 5;
                        ctr_salt_iv[4] = 6;
                        c_11= _mm256_load_si256((const __m256i *) ctr_salt_iv);

                        ctr_salt_iv[0] = 7;
                        ctr_salt_iv[4] = 8;
                        c_15= _mm256_load_si256((const __m256i *) ctr_salt_iv);
                } else if (len > 256) {
                        c_8 = c_4 = c_0;
                        c_9 = c_5 = c_1;
                        c_10= c_6 = c_2;

                        ctr_salt_iv[0] = 3;
                        ctr_salt_iv[4] = 4;
                        c_7 = _mm256_load_si256((const __m256i *) ctr_salt_iv);

                        ctr_salt_iv[0] = 5;
                        ctr_salt_iv[4] = 6;
                        c_11= _mm256_load_si256((const __m256i *) ctr_salt_iv);
                 } else if (len > 128) {
                        c_4 = c_0;
                        c_5 = c_1;
                        c_6 = c_2;

                        ctr_salt_iv[0] = 3;
                        ctr_salt_iv[4] = 4;
                        c_7 = _mm256_load_si256((const __m256i *) ctr_salt_iv);
                }
        }
#if 0
        dump_ctx("avx2 ctx", c_0, c_1, c_2, c_3);
#endif

        while (len >= 512) {
                __m256i rot16 = _mm256_set_epi8(13,12,15,14, 9, 8,11,10,
                                                 5, 4, 7, 6, 1, 0, 3, 2,
                                                13,12,15,14, 9, 8,11,10,
                                                 5, 4, 7, 6, 1, 0, 3, 2);
                __m256i rot8  = _mm256_set_epi8(14,13,12,15,10, 9, 8,11,
                                                 6, 5, 4, 7, 2, 1, 0, 3,
                                                14,13,12,15,10, 9, 8,11,
                                                 6, 5, 4, 7, 2, 1, 0, 3);

                __m256i x_0 = c_0;
                __m256i x_1 = c_1;
                __m256i x_2 = c_2;
                __m256i x_3 = c_3;
                __m256i x_4 = c_4;
                __m256i x_5 = c_5;
                __m256i x_6 = c_6;
                __m256i x_7 = c_7;
                __m256i x_8 = c_8;
                __m256i x_9 = c_9;
                __m256i x_10= c_10;
                __m256i x_11= c_11;
                __m256i x_12= c_12;
                __m256i x_13= c_13;
                __m256i x_14= c_14;
                __m256i x_15= c_15;

#if 0
                for (unsigned i = 0; i < 10; i++)
                        DOUBLE_ROUNDS_X4(x_0,  x_1,  x_2,  x_3,
                                         x_4,  x_5,  x_6,  x_7,
                                         x_8,  x_9,  x_10, x_11,
                                         x_12, x_13, x_14, x_15);
#else
                for (unsigned i = 0; i < 10; i++) {
                        VEC8_ROUND( 0, 4, 8, 12, 1, 5,  9, 13, 2, 6, 10, 14, 3, 7, 11, 15);
                        VEC8_ROUND( 0, 5,10, 15, 1, 6, 11, 12, 2, 7,  8, 13, 3, 4,  9, 14);
                }
#endif

                __m256i t_0 = _mm256_add_epi32(c_0, x_0);
                __m256i t_1 = _mm256_add_epi32(c_1, x_1);
                __m256i t_2 = _mm256_add_epi32(c_2, x_2);
                __m256i t_3 = _mm256_add_epi32(c_3, x_3);
                __m256i t_4 = _mm256_add_epi32(c_4, x_4);
                __m256i t_5 = _mm256_add_epi32(c_5, x_5);
                __m256i t_6 = _mm256_add_epi32(c_6, x_6);
                __m256i t_7 = _mm256_add_epi32(c_7, x_7);
                __m256i t_8 = _mm256_add_epi32(c_8, x_8);
                __m256i t_9 = _mm256_add_epi32(c_9, x_9);
                __m256i t_10= _mm256_add_epi32(c_10,x_10);
                __m256i t_11= _mm256_add_epi32(c_11,x_11);
                __m256i t_12= _mm256_add_epi32(c_12,x_12);
                __m256i t_13= _mm256_add_epi32(c_13,x_13);
                __m256i t_14= _mm256_add_epi32(c_14,x_14);
                __m256i t_15= _mm256_add_epi32(c_15,x_15);

                __m256i ymm_inc = _mm256_set_epi32(8, 0, 0, 0, 8, 0, 0, 0);
                c_3 = _mm256_add_epi32(c_3,  ymm_inc);
                c_7 = _mm256_add_epi32(c_7,  ymm_inc);
                c_11= _mm256_add_epi32(c_11, ymm_inc);
                c_15= _mm256_add_epi32(c_15, ymm_inc);
                
                PERMUTE2X128(x_0,  x_1,  x_2,   x_3,  t_0, t_1,   t_2,  t_3);
                PERMUTE2X128(x_4,  x_5,  x_6,   x_7,  t_4, t_5,   t_6,  t_7);
                PERMUTE2X128(x_8,  x_9,  x_10, x_11,  t_8, t_9,  t_10, t_11);
                PERMUTE2X128(x_12, x_13, x_14, x_15, t_12, t_13, t_14, t_15);

                t_0 = _mm256_xor_si256(x_0, _mm256_loadu_si256((const __m256i *) (src +   0)));
                _mm256_storeu_si256((__m256i *) (dst + 0),   t_0);
                
                t_1 = _mm256_xor_si256(x_1, _mm256_loadu_si256((const __m256i *) (src +  32)));
                _mm256_storeu_si256((__m256i *) (dst + 32),  t_1);
                
                t_2 = _mm256_xor_si256(x_2, _mm256_loadu_si256((const __m256i *) (src +  64)));
                _mm256_storeu_si256((__m256i *) (dst + 64),  t_2);
                
                t_3 = _mm256_xor_si256(x_3, _mm256_loadu_si256((const __m256i *) (src +  96)));
                _mm256_storeu_si256((__m256i *) (dst + 96),  t_3);
                
                t_4 = _mm256_xor_si256(x_4, _mm256_loadu_si256((const __m256i *) (src + 128)));
                _mm256_storeu_si256((__m256i *) (dst + 128), t_4);
                
                t_5 = _mm256_xor_si256(x_5, _mm256_loadu_si256((const __m256i *) (src + 160)));
                _mm256_storeu_si256((__m256i *) (dst + 160), t_5);
                
                t_6 = _mm256_xor_si256(x_6, _mm256_loadu_si256((const __m256i *) (src + 192)));
                _mm256_storeu_si256((__m256i *) (dst + 192), t_6);

                t_7 = _mm256_xor_si256(x_7, _mm256_loadu_si256((const __m256i *) (src + 224)));
                _mm256_storeu_si256((__m256i *) (dst + 224), t_7);

                t_8 = _mm256_xor_si256(x_8, _mm256_loadu_si256((const __m256i *) (src + 256)));
                _mm256_storeu_si256((__m256i *) (dst + 256), t_8);

                t_9 = _mm256_xor_si256(x_9, _mm256_loadu_si256((const __m256i *) (src + 288)));
                _mm256_storeu_si256((__m256i *) (dst + 288), t_9);
                
                t_10= _mm256_xor_si256(x_10,_mm256_loadu_si256((const __m256i *) (src + 320)));
                _mm256_storeu_si256((__m256i *) (dst + 320), t_10);

                t_11= _mm256_xor_si256(x_11,_mm256_loadu_si256((const __m256i *) (src + 352)));
                _mm256_storeu_si256((__m256i *) (dst + 352), t_11);

                t_12= _mm256_xor_si256(x_12,_mm256_loadu_si256((const __m256i *) (src + 384)));
                _mm256_storeu_si256((__m256i *) (dst + 384), t_12);

                t_13= _mm256_xor_si256(x_13,_mm256_loadu_si256((const __m256i *) (src + 416)));
                _mm256_storeu_si256((__m256i *) (dst + 416), t_13);

                t_14= _mm256_xor_si256(x_14,_mm256_loadu_si256((const __m256i *) (src + 448)));
                _mm256_storeu_si256((__m256i *) (dst + 448), t_14);

                t_15= _mm256_xor_si256(x_15,_mm256_loadu_si256((const __m256i *) (src + 480)));
                _mm256_storeu_si256((__m256i *) (dst + 480), t_15);
                
                len -= 512;
                src += 512;
                dst += 512;
        }

        if (len >= 384) {
                __m256i ymm_inc = _mm256_set_epi32(6, 0, 0, 0, 6, 0, 0, 0);

                __m256i x_0 = c_0;
                __m256i x_1 = c_1;
                __m256i x_2 = c_2;
                __m256i x_3 = c_3;
                __m256i x_4 = c_4;
                __m256i x_5 = c_5;
                __m256i x_6 = c_6;
                __m256i x_7 = c_7;
                __m256i x_8 = c_8;
                __m256i x_9 = c_9;
                __m256i x_10= c_10;
                __m256i x_11= c_11;

                for (unsigned i = 0; i < 10; i++)
                        DOUBLE_ROUNDS_X3(x_0, x_1,  x_2,  x_3,
                                         x_4, x_5,  x_6,  x_7,
                                         x_8, x_9, x_10, x_11);

                __m256i t_0 = _mm256_add_epi32(c_0, x_0);
                __m256i t_1 = _mm256_add_epi32(c_1, x_1);
                __m256i t_2 = _mm256_add_epi32(c_2, x_2);
                __m256i t_3 = _mm256_add_epi32(c_3, x_3);
                __m256i t_4 = _mm256_add_epi32(c_4, x_4);
                __m256i t_5 = _mm256_add_epi32(c_5, x_5);
                __m256i t_6 = _mm256_add_epi32(c_6, x_6);
                __m256i t_7 = _mm256_add_epi32(c_7, x_7);
                __m256i t_8 = _mm256_add_epi32(c_8, x_8);
                __m256i t_9 = _mm256_add_epi32(c_9, x_9);
                __m256i t_10= _mm256_add_epi32(c_10,x_10);
                __m256i t_11= _mm256_add_epi32(c_11,x_11);

                PERMUTE2X128(x_0, x_1,  x_2,  x_3, t_0, t_1,   t_2,  t_3);
                PERMUTE2X128(x_4, x_5,  x_6,  x_7, t_4, t_5,   t_6,  t_7);
                PERMUTE2X128(x_8, x_9, x_10, x_11, t_8, t_9,  t_10, t_11);
                
                t_0 = _mm256_xor_si256(x_0, _mm256_loadu_si256((const __m256i *) (src +   0)));
                t_1 = _mm256_xor_si256(x_1, _mm256_loadu_si256((const __m256i *) (src +  32)));
                t_2 = _mm256_xor_si256(x_2, _mm256_loadu_si256((const __m256i *) (src +  64)));
                t_3 = _mm256_xor_si256(x_3, _mm256_loadu_si256((const __m256i *) (src +  96)));
                t_4 = _mm256_xor_si256(x_4, _mm256_loadu_si256((const __m256i *) (src + 128)));
                t_5 = _mm256_xor_si256(x_5, _mm256_loadu_si256((const __m256i *) (src + 160)));
                t_6 = _mm256_xor_si256(x_6, _mm256_loadu_si256((const __m256i *) (src + 192)));
                t_7 = _mm256_xor_si256(x_7, _mm256_loadu_si256((const __m256i *) (src + 224)));
                t_8 = _mm256_xor_si256(x_8, _mm256_loadu_si256((const __m256i *) (src + 256)));
                t_9 = _mm256_xor_si256(x_9, _mm256_loadu_si256((const __m256i *) (src + 288)));
                t_10= _mm256_xor_si256(x_10,_mm256_loadu_si256((const __m256i *) (src + 320)));
                t_11= _mm256_xor_si256(x_11,_mm256_loadu_si256((const __m256i *) (src + 352)));

                _mm256_storeu_si256((__m256i *) (dst + 0),   t_0);
                _mm256_storeu_si256((__m256i *) (dst + 32),  t_1);
                _mm256_storeu_si256((__m256i *) (dst + 64),  t_2);
                _mm256_storeu_si256((__m256i *) (dst + 96),  t_3);
                _mm256_storeu_si256((__m256i *) (dst + 128), t_4);
                _mm256_storeu_si256((__m256i *) (dst + 160), t_5);
                _mm256_storeu_si256((__m256i *) (dst + 192), t_6);
                _mm256_storeu_si256((__m256i *) (dst + 224), t_7);
                _mm256_storeu_si256((__m256i *) (dst + 256), t_8);
                _mm256_storeu_si256((__m256i *) (dst + 288), t_9);
                _mm256_storeu_si256((__m256i *) (dst + 320), t_10);
                _mm256_storeu_si256((__m256i *) (dst + 352), t_11);

                c_3 = _mm256_add_epi32(c_3,  ymm_inc);
                len -= 384;
                src += 384;
                dst += 384;
        } else if (len >= 256) {
                __m256i ymm_inc = _mm256_set_epi32(4, 0, 0, 0, 4, 0, 0, 0);

                __m256i x_0 = c_0;
                __m256i x_1 = c_1;
                __m256i x_2 = c_2;
                __m256i x_3 = c_3;
                __m256i x_4 = c_4;
                __m256i x_5 = c_5;
                __m256i x_6 = c_6;
                __m256i x_7 = c_7;

                for (unsigned i = 0; i < 10; i++)
                        DOUBLE_ROUNDS_X2(x_0, x_1, x_2, x_3,
                                         x_4, x_5, x_6, x_7);

                __m256i t_0 = _mm256_add_epi32(c_0, x_0);
                __m256i t_1 = _mm256_add_epi32(c_1, x_1);
                __m256i t_2 = _mm256_add_epi32(c_2, x_2);
                __m256i t_3 = _mm256_add_epi32(c_3, x_3);
                __m256i t_4 = _mm256_add_epi32(c_4, x_4);
                __m256i t_5 = _mm256_add_epi32(c_5, x_5);
                __m256i t_6 = _mm256_add_epi32(c_6, x_6);
                __m256i t_7 = _mm256_add_epi32(c_7, x_7);

                PERMUTE2X128(x_0, x_1, x_2, x_3, t_0, t_1, t_2, t_3);
                PERMUTE2X128(x_4, x_5, x_6, x_7, t_4, t_5, t_6, t_7);

                t_0 = _mm256_xor_si256(x_0, _mm256_loadu_si256((const __m256i *) (src +   0)));
                t_1 = _mm256_xor_si256(x_1, _mm256_loadu_si256((const __m256i *) (src +  32)));
                t_2 = _mm256_xor_si256(x_2, _mm256_loadu_si256((const __m256i *) (src +  64)));
                t_3 = _mm256_xor_si256(x_3, _mm256_loadu_si256((const __m256i *) (src +  96)));
                t_4 = _mm256_xor_si256(x_4, _mm256_loadu_si256((const __m256i *) (src + 128)));
                t_5 = _mm256_xor_si256(x_5, _mm256_loadu_si256((const __m256i *) (src + 160)));
                t_6 = _mm256_xor_si256(x_6, _mm256_loadu_si256((const __m256i *) (src + 192)));
                t_7 = _mm256_xor_si256(x_7, _mm256_loadu_si256((const __m256i *) (src + 224)));

                _mm256_storeu_si256((__m256i *) (dst + 0),   t_0);
                _mm256_storeu_si256((__m256i *) (dst + 32),  t_1);
                _mm256_storeu_si256((__m256i *) (dst + 64),  t_2);
                _mm256_storeu_si256((__m256i *) (dst + 96),  t_3);
                _mm256_storeu_si256((__m256i *) (dst + 128), t_4);
                _mm256_storeu_si256((__m256i *) (dst + 160), t_5);
                _mm256_storeu_si256((__m256i *) (dst + 192), t_6);
                _mm256_storeu_si256((__m256i *) (dst + 224), t_7);

                c_3 = _mm256_add_epi32(c_3, ymm_inc);
                len -= 256;
                src += 256;
                dst += 256;
        } else if (len >= 128) {
                __m256i ymm_inc = _mm256_set_epi32(2, 0, 0, 0, 2, 0, 0, 0);

                __m256i x_0 = c_0;
                __m256i x_1 = c_1;
                __m256i x_2 = c_2;
                __m256i x_3 = c_3;

                for (unsigned i = 0; i < 10; i++)
                        DOUBLE_ROUNDS(x_0, x_1, x_2, x_3);

                __m256i t_0 = _mm256_add_epi32(c_0, x_0);
                __m256i t_1 = _mm256_add_epi32(c_1, x_1);
                __m256i t_2 = _mm256_add_epi32(c_2, x_2);
                __m256i t_3 = _mm256_add_epi32(c_3, x_3);

                PERMUTE2X128(x_0, x_1, x_2, x_3, t_0, t_1,   t_2,  t_3);

                t_0 = _mm256_xor_si256(x_0, _mm256_loadu_si256((const __m256i *) (src +   0)));
                t_1 = _mm256_xor_si256(x_1, _mm256_loadu_si256((const __m256i *) (src +  32)));
                t_2 = _mm256_xor_si256(x_2, _mm256_loadu_si256((const __m256i *) (src +  64)));
                t_3 = _mm256_xor_si256(x_3, _mm256_loadu_si256((const __m256i *) (src +  96)));

                _mm256_storeu_si256((__m256i *) (dst +  0),  t_0);
                _mm256_storeu_si256((__m256i *) (dst + 32),  t_1);
                _mm256_storeu_si256((__m256i *) (dst + 64),  t_2);
                _mm256_storeu_si256((__m256i *) (dst + 96),  t_3);

                c_3 = _mm256_add_epi32(c_3, ymm_inc);
                len -= 128;
                src += 128;
                dst += 128;
        }

        if (len) {
                __m256i x_0 = c_0;
                __m256i x_1 = c_1;
                __m256i x_2 = c_2;
                __m256i x_3 = c_3;

                for (unsigned i = 0; i < 10; i++)
                        DOUBLE_ROUNDS(x_0, x_1, x_2, x_3);

                __m256i t_0 = _mm256_add_epi32(c_0, x_0);
                __m256i t_1 = _mm256_add_epi32(c_1, x_1);
                __m256i t_2 = _mm256_add_epi32(c_2, x_2);
                __m256i t_3 = _mm256_add_epi32(c_3, x_3);

                PERMUTE2X128(x_0, x_1, x_2, x_3, t_0, t_1, t_2, t_3);

                if (len >= 96) {
                        t_0 = _mm256_xor_si256(x_0, _mm256_loadu_si256((const __m256i *) (src +  0)));
                        t_1 = _mm256_xor_si256(x_1, _mm256_loadu_si256((const __m256i *) (src + 32)));
                        t_2 = _mm256_xor_si256(x_2, _mm256_loadu_si256((const __m256i *) (src + 64)));
                        
                        _mm256_storeu_si256((__m256i *) (dst +  0), t_0);
                        _mm256_storeu_si256((__m256i *) (dst + 32), t_1);
                        _mm256_storeu_si256((__m256i *) (dst + 64), t_2);
                        
                        len -= 96;
                        src += 96;
                        dst += 96;

                        t_0 = t_3;
                        x_0 = x_3;
                } else if (len >= 64) {
                        t_0 = _mm256_xor_si256(x_0, _mm256_loadu_si256((const __m256i *) (src +  0)));
                        t_1 = _mm256_xor_si256(x_1, _mm256_loadu_si256((const __m256i *) (src + 32)));

                        _mm256_storeu_si256((__m256i *) (dst +  0), t_0);
                        _mm256_storeu_si256((__m256i *) (dst + 32), t_1);

                        len -= 64;
                        src += 64;
                        dst += 64;

                        t_0 = t_2;
                        x_0 = x_2;
                } else if (len >= 32) {
                        t_0 = _mm256_xor_si256(x_0, _mm256_loadu_si256((const __m256i *) (src +  0)));

                        _mm256_storeu_si256((__m256i *) (dst + 0), t_0);

                        len -= 32;
                        src += 32;
                        dst += 32;

                        t_0 = t_1;
                        x_0 = x_1;
                }

                if (len) {
                        uint8_t __attribute__((aligned(32))) buf[32];
                        
                        _mm256_store_si256((__m256i *) buf, x_0);
                        
                        for (unsigned i = 0; i < len; i++)
                                dst[i] = buf[i] ^ src[i];
                }
        }
}

