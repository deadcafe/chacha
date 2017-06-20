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
#include <assert.h>
#include <x86intrin.h>

#include "chacha.h"
#include "chacha_dbg.h"


/********************************************************************************
 * 256 vec (AVX2)
 ********************************************************************************/
#define VEC_PLUS(a,b)		_mm256_add_epi32(a, b)
#define VEC_XOR(a,b)		_mm256_xor_si256(a, b)
#define VEC_ROTATE_LEFT_16(a)	_mm256_shuffle_epi8(a, ROT16)
#define VEC_ROTATE_LEFT_12(a)	_mm256_or_si256(_mm256_slli_epi32(a, 12), \
                                                _mm256_srli_epi32(a, 20))
#define VEC_ROTATE_LEFT_8(a)	_mm256_shuffle_epi8(a, ROT8)
#define VEC_ROTATE_LEFT_7(a)	_mm256_or_si256(_mm256_slli_epi32(a, 7), \
                                                _mm256_srli_epi32(a, 25))
#define VEC_ROTATE_RIGHT_ALL(v0,v1,v2,v3)                       \
        do {                                                    \
                typeof(v1) _x, _y;                              \
                _x = _mm256_srli_si256(v1, 4);                  \
                _y = _mm256_slli_si256(v1, 12);                 \
                v1 = _mm256_or_si256(_x, _y);                   \
                                                                \
                _x = _mm256_srli_si256(v2, 8);                  \
                _y = _mm256_slli_si256(v2, 8);                  \
                v2 = _mm256_or_si256(_x, _y);                   \
                                                                \
                _x = _mm256_srli_si256(v3, 12);                 \
                _y = _mm256_slli_si256(v3, 4);                  \
                v3 = _mm256_or_si256(_x, _y);                   \
        } while(0)

#define VEC_ROTATE_LEFT_ALL(v0,v1,v2,v3)                        \
        do {                                                    \
                typeof(v1) _x, _y;                              \
                _x = _mm256_slli_si256(v1, 4);                  \
                _y = _mm256_srli_si256(v1, 12);                 \
                v1 = _mm256_or_si256(_x, _y);                   \
                                                                \
                _x = _mm256_slli_si256(v2, 8);                  \
                _y = _mm256_srli_si256(v2, 8);                  \
                v2 = _mm256_or_si256(_x, _y);                   \
                                                                \
                _x = _mm256_slli_si256(v3, 12);                 \
                _y = _mm256_srli_si256(v3, 4);                  \
                v3 = _mm256_or_si256(_x, _y);                   \
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

/*
 *
 */
#define VEC_STORE_8BLOCKS(m, dst,src,off, a,b,c,d)                      \
        do {                                                            \
                __m128i _t0, _t1, _t2, _t3;                             \
                __m256i _ta, _tb, _tc, _td;                             \
                                                                        \
                v_##a = _mm256_add_epi32(v_##a, c_##a);                 \
                v_##b = _mm256_add_epi32(v_##b, c_##b);                 \
                v_##c = _mm256_add_epi32(v_##c, c_##c);                 \
                v_##d = _mm256_add_epi32(v_##d, c_##d);                 \
                                                                        \
                _ta = _mm256_unpacklo_epi32(v_##a, v_##b);              \
                _tb = _mm256_unpacklo_epi32(v_##c, v_##d);              \
                _tc = _mm256_unpackhi_epi32(v_##a, v_##b);              \
                _td = _mm256_unpackhi_epi32(v_##c, v_##d);              \
                                                                        \
                v_##a = _mm256_unpacklo_epi64(_ta, _tb);                \
                v_##b = _mm256_unpackhi_epi64(_ta, _tb);                \
                v_##c = _mm256_unpacklo_epi64(_tc, _td);                \
                v_##d = _mm256_unpackhi_epi64(_tc, _td);                \
                                                                        \
                _t0 = _mm_xor_si128(_mm256_extracti128_si256(v_##a, 0), \
                                   _mm_loadu_si128((const __m128i *) (src + off + 0))); \
                _mm_storeu_si128((__m128i*) (dst + off + 0), _t0);      \
                                                                        \
                _t1 = _mm_xor_si128(_mm256_extracti128_si256(v_##b, 0), \
                                   _mm_loadu_si128((const __m128i *) (src + off + 64))); \
                _mm_storeu_si128((__m128i*) (dst + off + 64), _t1);     \
                                                                        \
                _t2 = _mm_xor_si128(_mm256_extracti128_si256(v_##c, 0), \
                                   _mm_loadu_si128((const __m128i *) (src + off + 128))); \
                _mm_storeu_si128((__m128i*) (dst + off + 128), _t2);    \
                                                                        \
                _t3 = _mm_xor_si128(_mm256_extracti128_si256(v_##d, 0), \
                                   _mm_loadu_si128((const __m128i *) (src + off + 192))); \
                _mm_storeu_si128((__m128i*) (dst + off + 192), _t3);    \
                                                                        \
                _t0 = _mm_xor_si128(_mm256_extracti128_si256(v_##a, 1), \
                                   _mm_loadu_si128((const __m128i *) (src + off + 256))); \
                _mm_storeu_si128((__m128i*) (dst + off + 256), _t0);    \
                                                                        \
                _t1 = _mm_xor_si128(_mm256_extracti128_si256(v_##b, 1), \
                                   _mm_loadu_si128((const __m128i *) (src + off + 320))); \
                _mm_storeu_si128((__m128i*) (dst + off + 320), _t1);    \
                                                                        \
                _t2 = _mm_xor_si128(_mm256_extracti128_si256(v_##c, 1), \
                                   _mm_loadu_si128((const __m128i *) (src + off + 384))); \
                _mm_storeu_si128((__m128i*) (dst + off + 384), _t2);    \
                                                                        \
                _t3 = _mm_xor_si128(_mm256_extracti128_si256(v_##d, 1), \
                                   _mm_loadu_si128((const __m128i *) (src + off + 448))); \
                _mm_storeu_si128((__m128i*) (dst + off + 448), _t3);    \
        } while (0)

#define VEC_ADD_PERMUTE(a,b,c,d)                                \
        do {                                                    \
                __m256i _t0, _t1, _t2, _t3;                     \
                                                                \
                _t0 = _mm256_add_epi32(v_##a, c_##a);                   \
                _t1 = _mm256_add_epi32(v_##b, c_##b);                   \
                _t2 = _mm256_add_epi32(v_##c, c_##c);                   \
                _t3 = _mm256_add_epi32(v_##d, c_##d);                   \
                                                                        \
                v_##a = _mm256_permute2x128_si256(_t0, _t1, 0x20);      \
                v_##c = _mm256_permute2x128_si256(_t0, _t1, 0x31);      \
                v_##b = _mm256_permute2x128_si256(_t2, _t3, 0x20);      \
                v_##d = _mm256_permute2x128_si256(_t2, _t3, 0x31);      \
        } while (0)

/*
 *
 */
#define	VEC_XOR_STORE(dst, src, off, r)                                 \
        do {                                                            \
                _mm256_storeu_si256((__m256i *) (dst + off),            \
                                    _mm256_xor_si256(v_##r, _mm256_loadu_si256((const __m256i *) (src + off)))); \
        } while (0)



/*
 *
 */
static inline void
dump_reg(const char *msg,
         const __m256i ymm)
{
        uint8_t __attribute__((aligned(32))) buff[32];

        _mm256_store_si256((__m256i *) buff,  ymm);
        HEXDUMP(msg, buff, sizeof(buff));
}

/*
 *
 */
static inline void
dump_ctx(const char *msg,
         const __m256i ymm0,
         const __m256i ymm1,
         const __m256i ymm2,
         const __m256i ymm3)
{
        uint8_t __attribute__((aligned(32))) buff[128];

        _mm256_store_si256((__m256i *) &buff[0],  ymm0);
        _mm256_store_si256((__m256i *) &buff[32], ymm1);
        _mm256_store_si256((__m256i *) &buff[64], ymm2);
        _mm256_store_si256((__m256i *) &buff[96], ymm3);

        HEXDUMP(msg, buff, sizeof(buff));
}

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
        const __m256i ROT16 = _mm256_set_epi8(13,12,15,14, 9, 8,11,10,
                                              5, 4, 7, 6, 1, 0, 3, 2,
                                              13,12,15,14, 9, 8,11,10,
                                              5, 4, 7, 6, 1, 0, 3, 2);
        const __m256i ROT8  = _mm256_set_epi8(14,13,12,15,10, 9, 8,11,
                                              6, 5, 4, 7, 2, 1, 0, 3,
                                              14,13,12,15,10, 9, 8,11,
                                              6, 5, 4, 7, 2, 1, 0, 3);
        uint32_t __attribute__((aligned(32))) ctr_salt_iv[4];
        /* ctx */
        __m256i c_0, c_1, c_2, c_3;
        __m256i c_4, c_5, c_6, c_7;
        __m256i c_8, c_9, c_a, c_b;
        __m256i c_c, c_d, c_e, c_f;

        /* block vector */
        __m256i v_0, v_1, v_2, v_3;
        __m256i v_4, v_5, v_6, v_7;
        __m256i v_8, v_9, v_a, v_b;
        __m256i v_c, v_d, v_e, v_f;

        ctr_salt_iv[0] = 0;
        ctr_salt_iv[1] = *((const uint32_t *) salt);
        ctr_salt_iv[2] = *((const uint32_t *) &iv[0]);
        ctr_salt_iv[3] = *((const uint32_t *) &iv[4]);

        /* init parallel 8 blocks */
        if (len < 512) {
                /* set first counter */
                c_c = _mm256_set_epi32(0, 0, 0, 0, 0, 0, 0, 1);
                goto PARALLEL_4;
        } else {
                __m128i tmp;

                /* "expand 32-byte k" */
                tmp = _mm_set_epi8(0x6b, 0x20, 0x65, 0x74,
                                   0x79, 0x62, 0x2d, 0x32,
                                   0x33, 0x20, 0x64, 0x6e,
                                   0x61, 0x70, 0x78, 0x65);
                c_0 = _mm256_broadcastsi128_si256(_mm_shuffle_epi32(tmp, 0));
                c_1 = _mm256_broadcastsi128_si256(_mm_shuffle_epi32(tmp, 0x55));
                c_2 = _mm256_broadcastsi128_si256(_mm_shuffle_epi32(tmp, 0xaa));
                c_3 = _mm256_broadcastsi128_si256(_mm_shuffle_epi32(tmp, 0xff));

                c_c =  _mm256_set_epi32(8, 7, 6, 5, 4, 3, 2, 1);

                tmp = _mm_loadu_si128((const __m128i *) &key[0]);
                c_4 = _mm256_broadcastsi128_si256(_mm_shuffle_epi32(tmp, 0));
                c_5 = _mm256_broadcastsi128_si256(_mm_shuffle_epi32(tmp, 0x55));
                c_6 = _mm256_broadcastsi128_si256(_mm_shuffle_epi32(tmp, 0xaa));
                c_7 = _mm256_broadcastsi128_si256(_mm_shuffle_epi32(tmp, 0xff));

                tmp = _mm_loadu_si128((const __m128i *) &key[16]);
                c_8 = _mm256_broadcastsi128_si256(_mm_shuffle_epi32(tmp, 0));
                c_9 = _mm256_broadcastsi128_si256(_mm_shuffle_epi32(tmp, 0x55));
                c_a = _mm256_broadcastsi128_si256(_mm_shuffle_epi32(tmp, 0xaa));
                c_b = _mm256_broadcastsi128_si256(_mm_shuffle_epi32(tmp, 0xff));

                tmp = _mm_loadu_si128((const __m128i *) ctr_salt_iv);
                c_d = _mm256_broadcastsi128_si256(_mm_shuffle_epi32(tmp, 0x55));
                c_e = _mm256_broadcastsi128_si256(_mm_shuffle_epi32(tmp, 0xaa));
                c_f = _mm256_broadcastsi128_si256(_mm_shuffle_epi32(tmp, 0xff));
        }
#if 0
        dump_ctx("avx2 ctx", c_0, c_1, c_2, c_3);
#endif

        /* parallel 8 blocks (64 x 8) */
        while (len >= 512) {
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
#if 0
                dump_reg("avx2 ctx c_0", c_0);
                dump_reg("avx2 ctx c_1", c_1);
                dump_reg("avx2 ctx c_2", c_2);
                dump_reg("avx2 ctx c_3", c_3);

                dump_reg("avx2 ctx c_4", c_4);
                dump_reg("avx2 ctx c_5", c_5);
                dump_reg("avx2 ctx c_6", c_6);
                dump_reg("avx2 ctx c_7", c_7);

                dump_reg("avx2 ctx c_8", c_8);
                dump_reg("avx2 ctx c_9", c_9);
                dump_reg("avx2 ctx c_a", c_a);
                dump_reg("avx2 ctx c_b", c_b);

                dump_reg("avx2 ctx c_c", c_c);
                dump_reg("avx2 ctx c_d", c_d);
                dump_reg("avx2 ctx c_e", c_e);
                dump_reg("avx2 ctx c_f", c_f);
#endif

                for (unsigned i = 0; i < 10; i++) {
                        DOUBLE_ROUND(0, 1, 2, 3,
                                     4, 5, 6, 7,
                                     8, 9, a, b,
                                     c, d, e, f);
                }

                VEC_STORE_8BLOCKS("avx2 LINE0 add", dst, src,  0, 0, 1, 2, 3);
                VEC_STORE_8BLOCKS("avx2 LINE1 add", dst, src, 16, 4, 5, 6, 7);
                VEC_STORE_8BLOCKS("avx2 LINE2 add", dst, src, 32, 8, 9, a, b);
                VEC_STORE_8BLOCKS("avx2 LINE3 add", dst, src, 48, c, d, e, f);

                __m256i ymm_inc = _mm256_set_epi32(8, 8, 8, 8, 8, 8, 8, 8);
                c_c = _mm256_add_epi32(c_c,  ymm_inc);

                src += 512;
                dst += 512;
                len -= 512;
        }

 PARALLEL_4:
        //        const __m256i ymm_inc = _mm256_set_epi32(0, 0, 0, 2, 0, 0, 0, 2);

        if (len) {
                /* parallel 4 blocks (256 x 2) */
                __m128i tmp0, tmp1;
                const __m256i ymm_inc1 = _mm256_set_epi32(0, 0, 0, 1, 0, 0, 0, 0);

                ctr_salt_iv[0] = _mm_extract_epi32(_mm256_extracti128_si256(c_c, 0), 0);
#if 0
                HEXDUMP("ctr_salt_iv", ctr_salt_iv, sizeof(ctr_salt_iv));
#endif
                /* "expand 32-byte k" */
                tmp0 = _mm_set_epi8(0x6b, 0x20, 0x65, 0x74,
                                    0x79, 0x62, 0x2d, 0x32,
                                    0x33, 0x20, 0x64, 0x6e,
                                    0x61, 0x70, 0x78, 0x65);
                c_0 = _mm256_broadcastsi128_si256(tmp0);

                tmp0 = _mm_loadu_si128((const __m128i *) &key[0]);
                tmp1 = _mm_loadu_si128((const __m128i *) &key[16]);
                c_1 = _mm256_broadcastsi128_si256(tmp0);
                c_2 = _mm256_broadcastsi128_si256(tmp1);

                tmp0 = _mm_loadu_si128((const __m128i *) ctr_salt_iv);
                c_3 = _mm256_broadcastsi128_si256(tmp0);

                c_3 = _mm256_add_epi32(c_3, ymm_inc1);
        } else {
                return;
        }

        v_0 = c_0;
        v_1 = c_1;
        v_2 = c_2;
        v_3 = c_3;

        if (len >= 384) {
                v_4 = c_4 = c_0;
                v_5 = c_5 = c_1;
                v_6 = c_6 = c_2;
                v_7 = c_7 = _mm256_add_epi32(c_3, _mm256_set_epi32(0, 0, 0, 2, 0, 0, 0, 2));

                v_8 = c_8 = c_0;
                v_9 = c_9 = c_1;
                v_a = c_a = c_2;
                v_b = c_b = _mm256_add_epi32(c_7, _mm256_set_epi32(0, 0, 0, 2, 0, 0, 0, 2));

                v_c = c_c = c_0;
                v_d = c_d = c_1;
                v_e = c_e = c_2;
                v_f = c_f = _mm256_add_epi32(c_b, _mm256_set_epi32(0, 0, 0, 2, 0, 0, 0, 2));

                /*
                 * 3 blocks + a
                 */
                for (unsigned i = 0; i < 10; i++) {
                        VEC_DOUBLE_QUARTER_ROUND(0, 1, 2, 3);
                        VEC_DOUBLE_QUARTER_ROUND(4, 5, 6, 7);
                        VEC_DOUBLE_QUARTER_ROUND(8, 9, a, b);
                        VEC_DOUBLE_QUARTER_ROUND(c, d, e, f);
                }

                VEC_ADD_PERMUTE(0, 1, 2, 3);
                VEC_ADD_PERMUTE(4, 5, 6, 7);
                VEC_ADD_PERMUTE(8, 9, a, b);
                VEC_ADD_PERMUTE(c, d, e, f);

                VEC_XOR_STORE(dst, src,   0, 0);
                VEC_XOR_STORE(dst, src,  32, 1);
                VEC_XOR_STORE(dst, src,  64, 2);
                VEC_XOR_STORE(dst, src,  96, 3);

                VEC_XOR_STORE(dst, src, 128, 4);
                VEC_XOR_STORE(dst, src, 160, 5);
                VEC_XOR_STORE(dst, src, 192, 6);
                VEC_XOR_STORE(dst, src, 224, 7);

                VEC_XOR_STORE(dst, src, 256, 8);
                VEC_XOR_STORE(dst, src, 288, 9);
                VEC_XOR_STORE(dst, src, 320, a);
                VEC_XOR_STORE(dst, src, 352, b);

                src += 384;
                dst += 384;
                len -= 384;

                v_0 = v_c;
                v_1 = v_d;
                v_2 = v_e;
                v_3 = v_f;
        } else if (len >= 256) {
                v_4 = c_4 = c_0;
                v_5 = c_5 = c_1;
                v_6 = c_6 = c_2;
                v_7 = c_7 = _mm256_add_epi32(c_3, _mm256_set_epi32(0, 0, 0, 2, 0, 0, 0, 2));

                v_8 = c_8 = c_0;
                v_9 = c_9 = c_1;
                v_a = c_a = c_2;
                v_b = c_b = _mm256_add_epi32(c_7, _mm256_set_epi32(0, 0, 0, 2, 0, 0, 0, 2));

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
                VEC_XOR_STORE(dst, src,  32, 1);
                VEC_XOR_STORE(dst, src,  64, 2);
                VEC_XOR_STORE(dst, src,  96, 3);

                VEC_XOR_STORE(dst, src, 128, 4);
                VEC_XOR_STORE(dst, src, 160, 5);
                VEC_XOR_STORE(dst, src, 192, 6);
                VEC_XOR_STORE(dst, src, 224, 7);

                src += 256;
                dst += 256;
                len -= 256;

                v_0 = v_8;
                v_1 = v_9;
                v_2 = v_a;
                v_3 = v_b;
        } else if (len >= 128) {
                v_4 = c_4 = c_0;
                v_5 = c_5 = c_1;
                v_6 = c_6 = c_2;
                v_7 = c_7 = _mm256_add_epi32(c_3, _mm256_set_epi32(0, 0, 0, 2, 0, 0, 0, 2));

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
                VEC_XOR_STORE(dst, src,  32, 1);
                VEC_XOR_STORE(dst, src,  64, 2);
                VEC_XOR_STORE(dst, src,  96, 3);

                src += 128;
                dst += 128;
                len -= 128;

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

#if 0
        dump_reg("avx2 p4 ctx c_0", c_0);
        dump_reg("avx2 p4 ctx c_1", c_1);
        dump_reg("avx2 p4 ctx c_2", c_2);
        dump_reg("avx2 p4 ctx c_3", c_3);

        dump_reg("avx2 p4 ctx c_4", c_4);
        dump_reg("avx2 p4 ctx c_5", c_5);
        dump_reg("avx2 p4 ctx c_6", c_6);
        dump_reg("avx2 p4 ctx c_7", c_7);

        dump_reg("avx2 p4 ctx c_8", c_8);
        dump_reg("avx2 p4 ctx c_9", c_9);
        dump_reg("avx2 p4 ctx c_a", c_a);
        dump_reg("avx2 p4 ctx c_b", c_b);

        dump_reg("avx2 p4 ctx c_c", c_c);
        dump_reg("avx2 p4 ctx c_d", c_d);
        dump_reg("avx2 p4 ctx c_e", c_e);
        dump_reg("avx2 p4 ctx c_f", c_f);
#endif

        if (len >= 96) {
                VEC_XOR_STORE(dst, src,  0, 0);
                VEC_XOR_STORE(dst, src, 32, 1);
                VEC_XOR_STORE(dst, src, 64, 2);

                src += 96;
                dst += 96;
                len -= 96;

                v_0 = v_3;
        } else if (len >= 64) {
                VEC_XOR_STORE(dst, src,  0, 0);
                VEC_XOR_STORE(dst, src, 32, 1);

                src += 64;
                dst += 64;
                len -= 64;

                v_0 = v_2;
        } else if (len >= 32) {
                VEC_XOR_STORE(dst, src, 0, 0);

                src += 32;
                dst += 32;
                len -= 32;

                v_0 = v_1;
        }

        if (len) {
                uint8_t __attribute__((aligned(32))) buf[32];

                _mm256_store_si256((__m256i *) buf, v_0);
                for (unsigned i = 0; i < len; i++)
                        dst[i] = buf[i] ^ src[i];
        }
}

