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

#include "chacha.h"
#include "chacha_dbg.h"

#define U8V(v)  ((uint8_t)  (v) & UINT8_C(0xFF))
#define U32V(v) ((uint32_t) (v) & UINT32_C(0xFFFFFFFF))
#define ROTL32(v,n)     (U32V((v) << (n)) | ((v) >> (32 - (n))))
#define ROTATE(v,c)     (ROTL32((v), (c)))
#define XOR(v,w)        ((v) ^ (w))
#define PLUS(v,w)       (U32V((v) + (w)))
#define PLUSONE(v)      (PLUS((v), 1))

#define QUARTER_ROUND(v0,v1,v2,v3)                                      \
        do {                                                            \
                (v0) = PLUS((v0),(v1));                                 \
                (v3) = ROTATE(XOR((v3),(v0)),16);                       \
                                                                        \
                (v2) = PLUS((v2),(v3));                                 \
                (v1) = ROTATE(XOR((v1),(v2)),12);                       \
                                                                        \
                (v0) = PLUS((v0),(v1));                                 \
                (v3) = ROTATE(XOR((v3),(v0)), 8);                       \
                                                                        \
                (v2) = PLUS((v2),(v3));                                 \
                (v1) = ROTATE(XOR((v1),(v2)), 7);                       \
        } while (0)

/*****************************************************************************
 *
 *****************************************************************************/
static inline void
double_round(struct chacha_ctx_s *st)
{
        QUARTER_ROUND(st->v32[0], st->v32[4], st->v32[8],  st->v32[12]);
        QUARTER_ROUND(st->v32[1], st->v32[5], st->v32[9],  st->v32[13]);
        QUARTER_ROUND(st->v32[2], st->v32[6], st->v32[10], st->v32[14]);
        QUARTER_ROUND(st->v32[3], st->v32[7], st->v32[11], st->v32[15]);

        QUARTER_ROUND(st->v32[0], st->v32[5], st->v32[10], st->v32[15]);
        QUARTER_ROUND(st->v32[1], st->v32[6], st->v32[11], st->v32[12]);
        QUARTER_ROUND(st->v32[2], st->v32[7], st->v32[8],  st->v32[13]);
        QUARTER_ROUND(st->v32[3], st->v32[4], st->v32[9],  st->v32[14]);
}

/*
 *
 */
static inline void
chacha_rounds(struct chacha_ctx_s *block,
              const struct chacha_ctx_s *ctx,
              unsigned num_rounds)
{
        memcpy(block, ctx, sizeof(*block));

        while (num_rounds) {
                double_round(block);
                num_rounds -= 2;
        }
#if 1
        HEXDUMP("gen double", block, sizeof(*block));
#endif

        for (unsigned i = 0; i < 16; ++i)
                block->v32[i] = PLUS(block->v32[i], ctx->v32[i]);

}

/*
 *
 */
static inline void
chacha_block(const struct chacha_ctx_s *ctx,
             uint8_t *dst,
             const uint8_t *src,
             size_t len)
{
        struct chacha_ctx_s block __attribute__((aligned(64)));
        uint8_t *p = (uint8_t *) &block;

        chacha_rounds(&block, ctx, 20);

#if 1
        HEXDUMP("gen rounds", &block, sizeof(block));
#endif

        for (unsigned i = 0; i < len; i++)
                dst[i] = src[i] ^ p[i];
}

/*
 *
 */
static inline void
chacha_init(struct chacha_ctx_s *ctx,
            const uint8_t *key,
            const uint8_t *salt,
            const uint8_t *iv)
{
        const uint8_t SIGMA[16] = "expand 32-byte k";

        memcpy(&ctx->v32[0], SIGMA, 16);
        memcpy(&ctx->v32[4], key, 32);
        memcpy(&ctx->v32[13], salt, 4);
        memcpy(&ctx->v32[14], iv, 8);

        ctx->v32[12] = 1;

#if 1
        HEXDUMP("gen ctx", ctx, sizeof(*ctx));
#endif
}

/*
 *
 */
void
chacha_gen(uint8_t *dst,
           const uint8_t *src,
           size_t len,
           const uint8_t *key,
           const uint8_t *salt,
           const uint8_t *iv)
{
        struct chacha_ctx_s ctx __attribute__((aligned(64)));

        chacha_init(&ctx, key, salt, iv);

        while (len) {
                size_t size;

                size = CHACHA_BLOCK_LEN > len ? len : CHACHA_BLOCK_LEN;
                chacha_block(&ctx, dst, src, size);

                ctx.v32[12] += 1;
                dst += size;
                src += size;
                len -= size;
        }
}
