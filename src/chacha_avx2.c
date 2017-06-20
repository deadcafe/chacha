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

#define PERMUTE2X128(r0,r1,r2,r3)                                     \
        do {                                                          \
                typeof(r0) _x, _y;                                    \
                _x = _mm256_permute2x128_si256(r0, r1, 0x20);         \
                _y = _mm256_permute2x128_si256(r0, r1, 0x31);         \
                r0 = _x;                                              \
                r1 = _y;                                              \
                _x = _mm256_permute2x128_si256(r2, r3, 0x20);         \
                _y = _mm256_permute2x128_si256(r2, r3, 0x31);         \
                r2 = _x;                                              \
                r3 = _y;                                              \
                _x = r1;                                              \
                r1 = r2;                                              \
                r2 = _x;                                              \
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
        __m256i ctx[16];

        /* init */
        {
                const uint32_t __attribute__((aligned(32))) PERMUTE_LO[] = {
                        0, 1, 2, 3, 0, 1, 2, 3,
                };
                const uint32_t __attribute__((aligned(32))) PERMUTE_HI[] = {
                        4, 5, 6, 7, 4, 5, 6, 7,
                };
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

                ctx[0] = _mm256_load_si256((const __m256i *) SIGMA);
                x = _mm256_loadu_si256((const __m256i *) key);
                y = _mm256_load_si256((const __m256i *) PERMUTE_LO);
                ctx[1] = _mm256_permutevar8x32_epi32(x, y);
                y  = _mm256_load_si256((const __m256i *) PERMUTE_HI);
                ctx[2] = _mm256_permutevar8x32_epi32(x, y);
                ctx[3] = _mm256_load_si256((const __m256i *) ctr_salt_iv);

                if (len > 384) {
                        ctx[12] = ctx[8] = ctx[4] = ctx[0];
                        ctx[13] = ctx[9] = ctx[5] = ctx[1];
                        ctx[14] = ctx[10]= ctx[6] = ctx[2];

                        ctr_salt_iv[0] = 3;
                        ctr_salt_iv[4] = 4;
                        ctx[7] = _mm256_load_si256((const __m256i *) ctr_salt_iv);

                        ctr_salt_iv[0] = 5;
                        ctr_salt_iv[4] = 6;
                        ctx[11]= _mm256_load_si256((const __m256i *) ctr_salt_iv);

                        ctr_salt_iv[0] = 7;
                        ctr_salt_iv[4] = 8;
                        ctx[15]= _mm256_load_si256((const __m256i *) ctr_salt_iv);
                } else if (len > 256) {
                        ctx[8] = ctx[4] = ctx[0];
                        ctx[9] = ctx[5] = ctx[1];
                        ctx[10]= ctx[6] = ctx[2];

                        ctr_salt_iv[0] = 3;
                        ctr_salt_iv[4] = 4;
                        ctx[7] = _mm256_load_si256((const __m256i *) ctr_salt_iv);

                        ctr_salt_iv[0] = 5;
                        ctr_salt_iv[4] = 6;
                        ctx[11]= _mm256_load_si256((const __m256i *) ctr_salt_iv);
                 } else if (len > 128) {
                        ctx[4] = ctx[0];
                        ctx[5] = ctx[1];
                        ctx[6] = ctx[2];

                        ctr_salt_iv[0] = 3;
                        ctr_salt_iv[4] = 4;
                        ctx[7] = _mm256_load_si256((const __m256i *) ctr_salt_iv);
                }
        }
#if 0
        dump_ctx("avx2 ctx", ctx[0], ctx[1], ctx[2], ctx[3]);
#endif

        while (len) {
                size_t size;
                __m256i block[16];
                unsigned n = 10;

                size = sizeof(block) > len ? len : sizeof(block);
                len -= size;

                if (size > 384) {
                        const uint32_t __attribute__((aligned(32))) CNT_INC[] = {
                                8, 0, 0, 0, 8, 0, 0, 0,
                        };
                        __m256i ymm_inc = _mm256_load_si256((const __m256i *) CNT_INC);

                        for (unsigned i = 0; i < 16; i++)
                                block[i] = ctx[i];

                        DOUBLE_ROUNDS_X4(n,
                                         block[0], block[1], block[2], block[3],
                                         block[4], block[5], block[6], block[7],
                                         block[8], block[9], block[10], block[11],
                                         block[12], block[13], block[14], block[15]);

                        for (unsigned i = 0; i < 16; i++)
                                block[i] = _mm256_add_epi32(ctx[i], block[i]);

                        PERMUTE2X128(block[0], block[1], block[2], block[3]);
                        PERMUTE2X128(block[4], block[5], block[6], block[7]);
                        PERMUTE2X128(block[8], block[9], block[10], block[11]);
                        PERMUTE2X128(block[12], block[13], block[14], block[15]);

                        ctx[3] = _mm256_add_epi32(ctx[3], ymm_inc);
                        ctx[7] = _mm256_add_epi32(ctx[7], ymm_inc);
                        ctx[11]= _mm256_add_epi32(ctx[11], ymm_inc);
                        ctx[15]= _mm256_add_epi32(ctx[15], ymm_inc);
                } else if (size > 256) {
                        for (unsigned i = 0; i < 12; i++)
                                block[i] = ctx[i];

                        DOUBLE_ROUNDS_X3(n,
                                         block[0], block[1], block[2], block[3],
                                         block[4], block[5], block[6], block[7],
                                         block[8], block[9], block[10], block[11]);

                        for (unsigned i = 0; i < 12; i++)
                                block[i] = _mm256_add_epi32(ctx[i], block[i]);

                        PERMUTE2X128(block[0], block[1], block[2], block[3]);
                        PERMUTE2X128(block[4], block[5], block[6], block[7]);
                        PERMUTE2X128(block[8], block[9], block[10], block[11]);
                } else if (size > 128) {
                        for (unsigned i = 0; i < 8; i++)
                                block[i] = ctx[i];

                        DOUBLE_ROUNDS_X2(n,
                                         block[0], block[1], block[2], block[3],
                                         block[4], block[5], block[6], block[7]);

                        for (unsigned i = 0; i < 8; i++)
                                block[i] = _mm256_add_epi32(ctx[i], block[i]);

                        PERMUTE2X128(block[0], block[1], block[2], block[3]);
                        PERMUTE2X128(block[4], block[5], block[6], block[7]);
                } else {
                        for (unsigned i = 0; i < 4; i++)
                                block[i] = ctx[i];

                        DOUBLE_ROUNDS(n,
                                      block[0], block[1], block[2], block[3]);

                        for (unsigned i = 0; i < 4; i++)
                                block[i] = _mm256_add_epi32(ctx[i], block[i]);

                        PERMUTE2X128(block[0], block[1], block[2], block[3]);
                }

                n = 0;
                while (size >= 32) {
                        __m256i x;

                        x = _mm256_loadu_si256((const __m256i *) src);
                        x = _mm256_xor_si256(x, block[n]);
                        _mm256_storeu_si256((__m256i *) dst, x);

                        n++;
                        src += 32;
                        dst += 32;
                        size -= 32;
                }

                if (size) {
                        uint8_t __attribute__((aligned(32))) buf[32];
                        __m256i x;

                        x = _mm256_loadu_si256((const __m256i *) src);	/* XXX: overrun */
                        x = _mm256_xor_si256(x, block[n]);
                        _mm256_store_si256((__m256i *) buf, x);

                        for (unsigned i = 0; i < size; i++)
                                dst[i] = buf[i];
                }
        }
}
