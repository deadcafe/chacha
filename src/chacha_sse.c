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

#define ADD_XOR_ROT(a,b,c,r)	VEC128_ADD_XOR_ROT(a,b,c,r)
#define ROT_RIGHT(a,r)		VEC128_ROT_RIGHT(a,r)
#define ROT_LEFT(a,r)		VEC128_ROT_LEFT(a,r)

#include "chacha_round.h"

/*
 *
 */
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
        __m128i ctx[8];

/* init */
        {
                const uint8_t __attribute__((aligned(16))) SIGMA[16] =
                        "expand 32-byte k";
                uint32_t __attribute__((aligned(16))) ctr_salt_iv[4];

                ctr_salt_iv[0] = 1;
                ctr_salt_iv[1] = *((const uint32_t *) salt);
                ctr_salt_iv[2] = *((const uint32_t *) &iv[0]);
                ctr_salt_iv[3] = *((const uint32_t *) &iv[4]);

                ctx[0] = _mm_load_si128((const __m128i *) SIGMA);
                ctx[1] = _mm_loadu_si128((const __m128i *) &key[0]);
                ctx[2] = _mm_loadu_si128((const __m128i *) &key[16]);
                ctx[3] = _mm_load_si128((const __m128i *) ctr_salt_iv);

                if (len > 64) {
                        ctx[4] = ctx[0];
                        ctx[5] = ctx[1];
                        ctx[6] = ctx[2];
                        ctr_salt_iv[0] = 2;
                        ctx[7] = _mm_load_si128((const __m128i *) ctr_salt_iv);
                }
        }

        while (len) {
                size_t size;
                __m128i block[8];
                unsigned n = 10;

                size = (CHACHA_BLOCK_LEN * 2) > len ? len : (CHACHA_BLOCK_LEN * 2);
                len -= size;

                if (size > 64) {
                        const uint32_t __attribute__((aligned(16))) CNT_INC[] = {
                                2, 0, 0, 0,
                        };
                        __m128i xmm_inc = _mm_load_si128((const __m128i *) CNT_INC);

                        for (unsigned i = 0; i < 8; i++)
                                block[i] = ctx[i];

                        for (unsigned i = 0; i < 10; i++)
                                DOUBLE_ROUNDS_X2(block[0], block[1], block[2], block[3],
                                                 block[4], block[5], block[6], block[7]);

                        for (unsigned i = 0; i < 8; i++)
                                block[i] = _mm_add_epi32(ctx[i], block[i]);

                        ctx[3] = _mm_add_epi32(ctx[3], xmm_inc);
                        ctx[7] = _mm_add_epi32(ctx[7], xmm_inc);
                } else {
                        for (unsigned i = 0; i < 4; i++)
                                block[i] = ctx[i];

                        for (unsigned i = 0; i < 10; i++)
                                DOUBLE_ROUNDS(block[0], block[1], block[2], block[3]);

                        for (unsigned i = 0; i < 4; i++)
                                block[i] = _mm_add_epi32(ctx[i], block[i]);
                }

                n = 0;
                while (size >= 16) {
                        __m128i x;

                        x = _mm_loadu_si128((const __m128i *) src);
                        x = _mm_xor_si128(x, block[n]);
                        _mm_storeu_si128((__m128i *) dst, x);

                        n++;
                        src += 16;
                        dst += 16;
                        size -= 16;
                }

                if (size) {
                        uint8_t __attribute__((aligned(16))) buf[16];
                        __m128i x;

                        x = _mm_loadu_si128((const __m128i *) src);	/* XXX: overrun */
                        x = _mm_xor_si128(x, block[n]);
                        _mm_store_si128((__m128i *) buf, x);

                        for (unsigned i = 0; i < size; i++)
                                dst[i] = buf[i];
                }
        }
}
