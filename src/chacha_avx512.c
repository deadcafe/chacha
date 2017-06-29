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


/* XXX: not yet, sorry */


#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <features.h>

#include "chacha.h"
#include "chacha_dbg.h"

#define ADD_XOR_ROT(a,b,c,r)	VEC512_ADD_XOR_ROT(a,b,c,r)
#define ROT_RIGHT(a,r)		VEC512_ROT_RIGHT(a,r)
#define ROT_LEFT(a,r)		VEC512_ROT_LEFT(a,r)

#include "chacha_round.h"

/*
 *
 */
static inline void
dump_ctx(const char *msg,
         __m512i zmm0,
         __m512i zmm1,
         __m512i zmm2,
         __m512i zmm3)
{
        uint8_t __attribute__((aligned(64))) buff[256];

        _mm512_store_si512((__m512i *) &buff[0],  zmm0);
        _mm512_store_si512((__m512i *) &buff[32], zmm1);
        _mm512_store_si512((__m512i *) &buff[64], zmm2);
        _mm512_store_si512((__m512i *) &buff[96], zmm3);

        HEXDUMP(msg, buff, sizeof(buff));
}

#if 0
#define PERMUTE4X128(r0,r1,r2,r3)                                     \
        do {                                                          \
                typeof(r0) _x, _y;                                    \
                _x = _mm512_permute4f128_si32(r0, r1, 0x20);          \
                _y = _mm512_permute4d128_si32(r0, r1, 0x31);          \
                r0 = _x;                                              \
                r1 = _y;                                              \
                _x = _mm512_permute4x128_si32(r2, r3, 0x20);          \
                _y = _mm512_permute4x128_si32(r2, r3, 0x31);          \
                r2 = _x;                                              \
                r3 = _y;                                              \
                _x = r1;                                              \
                r1 = r2;                                              \
                r2 = _x;                                              \
        } while (0)
#else
#define PERMUTE4X128(r0,r1,r2,r3)
#endif

#define PERMUTE8X32(r0,r1)	r0


/*
 * not yet
 */
void
chacha_avx512(uint8_t *dst,
              const uint8_t *src,
              size_t len,
              const uint8_t *key,
              const uint8_t *salt,
              const uint8_t *iv)
{
        __m512i ctx[16];

        /* init */
        {
                const uint32_t __attribute__((aligned(64))) PERMUTE_LO[] = {
                        0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3,
                };
                const uint32_t __attribute__((aligned(64))) PERMUTE_HI[] = {
                        4, 5, 6, 7, 4, 5, 6, 7, 4, 5, 6, 7, 4, 5, 6, 7,
                };
                const uint8_t __attribute__((aligned(64))) SIGMA[64] =
                        "expand 32-byte k""expand 32-byte k"
                        "expand 32-byte k""expand 32-byte k";
                uint32_t __attribute__((aligned(64))) ctr_salt_iv[16];
                __m512i x, y;

                (void) y;
                ctr_salt_iv[0] = 1;
                ctr_salt_iv[1] = *((const uint32_t *) salt);
                ctr_salt_iv[2] = *((const uint32_t *) &iv[0]);
                ctr_salt_iv[3] = *((const uint32_t *) &iv[4]);
                ctr_salt_iv[4] = 2;
                ctr_salt_iv[5] = ctr_salt_iv[1];
                ctr_salt_iv[6] = ctr_salt_iv[2];
                ctr_salt_iv[7] = ctr_salt_iv[3];
                ctr_salt_iv[8] = 3;
                ctr_salt_iv[9] = *((const uint32_t *) salt);
                ctr_salt_iv[10]= *((const uint32_t *) &iv[0]);
                ctr_salt_iv[11]= *((const uint32_t *) &iv[4]);
                ctr_salt_iv[12]= 4;
                ctr_salt_iv[13]= ctr_salt_iv[1];
                ctr_salt_iv[14]= ctr_salt_iv[2];
                ctr_salt_iv[15]= ctr_salt_iv[3];

                ctx[0] = _mm512_load_si512((const __m512i *) SIGMA);

                x = _mm512_loadu_si512((const __m512i *) key);
                y = _mm512_load_si512((const __m512i *) PERMUTE_LO);
                ctx[1] = PERMUTE8X32(x, y);

                y  = _mm512_load_si512((const __m512i *) PERMUTE_HI);
                ctx[2] = PERMUTE8X32(x, y);

                ctx[3] = _mm512_load_si512((const __m512i *) ctr_salt_iv);

                if (len > 768) {
                        ctx[12] = ctx[8] = ctx[4] = ctx[0];
                        ctx[13] = ctx[9] = ctx[5] = ctx[1];
                        ctx[14] = ctx[10]= ctx[6] = ctx[2];

                        ctr_salt_iv[0] = 5;
                        ctr_salt_iv[4] = 6;
                        ctr_salt_iv[8] = 7;
                        ctr_salt_iv[12]= 8;
                        ctx[7] = _mm512_load_si512((const __m512i *) ctr_salt_iv);

                        ctr_salt_iv[0] = 9;
                        ctr_salt_iv[4] = 10;
                        ctr_salt_iv[8] = 11;
                        ctr_salt_iv[12]= 12;
                        ctx[11]= _mm512_load_si512((const __m512i *) ctr_salt_iv);

                        ctr_salt_iv[0] = 13;
                        ctr_salt_iv[4] = 14;
                        ctr_salt_iv[0] = 15;
                        ctr_salt_iv[4] = 16;
                        ctx[15]= _mm512_load_si512((const __m512i *) ctr_salt_iv);
                } else if (len > 512) {
                        ctx[8] = ctx[4] = ctx[0];
                        ctx[9] = ctx[5] = ctx[1];
                        ctx[10]= ctx[6] = ctx[2];

                        ctr_salt_iv[0] = 5;
                        ctr_salt_iv[4] = 6;
                        ctr_salt_iv[8] = 7;
                        ctr_salt_iv[12]= 8;
                        ctx[7] = _mm512_load_si512((const __m512i *) ctr_salt_iv);

                        ctr_salt_iv[0] = 9;
                        ctr_salt_iv[4] = 10;
                        ctr_salt_iv[8] = 11;
                        ctr_salt_iv[12]= 12;
                        ctx[11]= _mm512_load_si512((const __m512i *) ctr_salt_iv);
                 } else if (len > 256) {
                        ctx[4] = ctx[0];
                        ctx[5] = ctx[1];
                        ctx[6] = ctx[2];

                        ctr_salt_iv[0] = 5;
                        ctr_salt_iv[4] = 6;
                        ctr_salt_iv[8] = 7;
                        ctr_salt_iv[12]= 8;
                        ctx[7] = _mm512_load_si512((const __m512i *) ctr_salt_iv);
                }
        }
#if 0
        dump_ctx("avx2 ctx", ctx[0], ctx[1], ctx[2], ctx[3]);
#endif

        while (len) {
                size_t size;
                __m512i block[16];
                unsigned n = 10;

                size = sizeof(block) > len ? len : sizeof(block);
                len -= size;

                if (size > 768) {
                        const uint32_t __attribute__((aligned(64))) CNT_INC[] = {
                                16, 0, 0, 0, 16, 0, 0, 0, 16, 0, 0, 0, 16, 0, 0, 0,
                        };
                        __m512i zmm_inc = _mm512_load_si512((const __m512i *) CNT_INC);

                        for (unsigned i = 0; i < 16; i++)
                                block[i] = ctx[i];

                        for (unsigned i = 0; i < 10; i++)
                                DOUBLE_ROUNDS_X4(block[0], block[1], block[2], block[3],
                                                 block[4], block[5], block[6], block[7],
                                                 block[8], block[9], block[10], block[11],
                                                 block[12], block[13], block[14], block[15]);

                        for (unsigned i = 0; i < 16; i++)
                                block[i] = _mm512_add_epi32(ctx[i], block[i]);

                        PERMUTE4X128(block[0], block[1], block[2], block[3]);
                        PERMUTE4X128(block[4], block[5], block[6], block[7]);
                        PERMUTE4X128(block[8], block[9], block[10], block[11]);
                        PERMUTE4X128(block[12], block[13], block[14], block[15]);

                        ctx[3] = _mm512_add_epi32(ctx[3], zmm_inc);
                        ctx[7] = _mm512_add_epi32(ctx[7], zmm_inc);
                        ctx[11]= _mm512_add_epi32(ctx[11], zmm_inc);
                        ctx[15]= _mm512_add_epi32(ctx[15], zmm_inc);
                } else if (size > 512) {
                        for (unsigned i = 0; i < 12; i++)
                                block[i] = ctx[i];

                        for (unsigned i = 0; i < 10; i++)
                                DOUBLE_ROUNDS_X3(block[0], block[1], block[2], block[3],
                                                 block[4], block[5], block[6], block[7],
                                                 block[8], block[9], block[10], block[11]);

                        for (unsigned i = 0; i < 12; i++)
                                block[i] = _mm512_add_epi32(ctx[i], block[i]);

                        PERMUTE4X128(block[0], block[1], block[2], block[3]);
                        PERMUTE4X128(block[4], block[5], block[6], block[7]);
                        PERMUTE4X128(block[8], block[9], block[10], block[11]);
                } else if (size > 256) {
                        for (unsigned i = 0; i < 8; i++)
                                block[i] = ctx[i];

                        for (unsigned i = 0; i < 10; i++)
                                DOUBLE_ROUNDS_X2(block[0], block[1], block[2], block[3],
                                                 block[4], block[5], block[6], block[7]);

                        for (unsigned i = 0; i < 8; i++)
                                block[i] = _mm512_add_epi32(ctx[i], block[i]);

                        PERMUTE4X128(block[0], block[1], block[2], block[3]);
                        PERMUTE4X128(block[4], block[5], block[6], block[7]);
                } else {
                        for (unsigned i = 0; i < 4; i++)
                                block[i] = ctx[i];

                        for (unsigned i = 0; i < 10; i++)
                                DOUBLE_ROUNDS(block[0], block[1], block[2], block[3]);

                        for (unsigned i = 0; i < 4; i++)
                                block[i] = _mm512_add_epi32(ctx[i], block[i]);

                        PERMUTE4X128(block[0], block[1], block[2], block[3]);
                }

                len -= size;
                n = 0;
                while (size >= 64) {
                        __m512i x;

                        x = _mm512_loadu_si512((const __m512i *) src);
                        x = _mm512_xor_si512(x, block[n]);
                        _mm512_storeu_si512((__m512i *) dst, x);

                        n++;
                        src += 64;
                        dst += 64;
                        size -= 64;
                }

                if (size) {
                        uint8_t __attribute__((aligned(64))) buf[64];
                        __m512i x;

                        x = _mm512_loadu_si512((const __m512i *) src);	/* XXX: overrun */
                        x = _mm512_xor_si512(x, block[n]);
                        _mm512_store_si512((__m512i *) buf, x);

                        for (unsigned i = 0; i < size; i++)
                                dst[i] = buf[i];
                }
        }
}
