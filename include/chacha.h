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

#ifndef _CHACHA_H_
#define _CHACHA_H_

#include <stdint.h>
#include <stddef.h>

/* length in bytes */
#define CHACHA_KEY_LEN		32
#define CHACHA_SALT_LEN		4
#define CHACHA_IV_LEN		8
#define CHACHA_BLOCK_LEN	64

#define CHACHA_BLOCK_MASK	(CHACHA_BLOCK_LEN - 1)

struct chacha_ctx_s {
        uint32_t v32[16];
};

/*
 * generic
 */
extern void chacha_gen(uint8_t *dst,
                       const uint8_t *src,
                       size_t len,
                       const uint8_t *key,
                       const uint8_t *salt,
                       const uint8_t *iv);

/*
 * SSE4.2
 */
extern void chacha_sse(uint8_t *dst,
                       const uint8_t *src,
                       size_t len,
                       const uint8_t *key,
                       const uint8_t *salt,
                       const uint8_t *iv);

/*
 * AVX
 */
extern void chacha_avx(uint8_t *dst,
                       const uint8_t *src,
                       size_t len,
                       const uint8_t *key,
                       const uint8_t *salt,
                       const uint8_t *iv);

/*
 * AVX2
 */
extern void chacha_avx2(uint8_t *dst,
                        const uint8_t *src,
                        size_t len,
                        const uint8_t *key,
                        const uint8_t *salt,
                        const uint8_t *iv);
/*
 * AVX512
 */
extern void chacha_avx512(uint8_t *dst,
                          const uint8_t *src,
                          size_t len,
                          const uint8_t *key,
                          const uint8_t *salt,
                          const uint8_t *iv);

#endif /* !_CHACHA_H_ */
