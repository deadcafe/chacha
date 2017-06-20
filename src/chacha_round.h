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

#ifndef _CHACHA_ROUND_H_
#define _CHACHA_ROUND_H_

#include <x86intrin.h>

/*
 * 128 vec
 */
#define VEC128_ADD_XOR_ROT(a,b,c,r)             \
        do {                                    \
                typeof(a) _x;                   \
                a = _mm_add_epi32(a, b);        \
                c = _mm_xor_si128(c, a);        \
                _x  = _mm_slli_epi32(c, r);     \
                c = _mm_srli_epi32(c, 32 - r);  \
                c = _mm_or_si128(c, _x);        \
        } while (0)

#define VEC128_ROT_RIGHT(a, r)                          \
        do {                                            \
                typeof(a) _x;                           \
                _x  = _mm_srli_si128(a, r / 8);         \
                a   = _mm_slli_si128(a, (128 - r) / 8); \
                a   = _mm_or_si128(a, _x);              \
        } while(0)

#define VEC128_ROT_LEFT(a, r)                           \
        do {                                            \
                typeof(a) _x;                           \
                _x  = _mm_slli_si128(a, r / 8);         \
                a   = _mm_srli_si128(a, (128 - r) / 8); \
                a   = _mm_or_si128(a, _x);              \
        } while(0)

/*
 * 256 vec
 */
#define VEC256_ADD_XOR_ROT(a,b,c,r)                 \
        do {                                        \
                typeof(a) _x;                       \
                a  = _mm256_add_epi32(a, b);        \
                c  = _mm256_xor_si256(c, a);        \
                _x = _mm256_slli_epi32(c, r);       \
                c  = _mm256_srli_epi32(c, 32 - r);  \
                c  = _mm256_or_si256(c, _x);        \
        } while (0)

#define VEC256_ROT_RIGHT(a, r)                                  \
        do {                                                    \
                typeof(a) _x;                                   \
                _x  = _mm256_srli_si256(a, r / 8);              \
                a   = _mm256_slli_si256(a, (128 - r) / 8);      \
                a   = _mm256_or_si256(a, _x);                   \
        } while(0)

#define VEC256_ROT_LEFT(a, r)                                   \
        do {                                                    \
                typeof(a) _x;                                   \
                _x  = _mm256_slli_si256(a, r / 8);              \
                a   = _mm256_srli_si256(a, (128 - r) / 8);      \
                a   = _mm256_or_si256(a, _x);                   \
        } while(0)

/*
 * 512 vec(not yet)
 */
#if 0
#define VEC512_ADD_XOR_ROT(a,b,c,r)                 \
        do {                                        \
                typeof(a) _x;                       \
                a  = _mm512_add_epi32(a, b);        \
                c  = _mm512_xor_si512(c, a);        \
                _x = _mm512_slli_epi32(c, r);       \
                c  = _mm512_srli_epi32(c, 32 - r);  \
                c  = _mm512_or_si512(c, _x);        \
        } while (0)

#define VEC512_ROT_RIGHT(a, r)                                  \
        do {                                                    \
                typeof(a) _x;                                   \
                _x  = _mm512_srli_si512(a, r / 8);              \
                a   = _mm512_slli_si512(a, (128 - r) / 8);      \
                a   = _mm512_or_si512(a, _x);                   \
        } while(0)

#define VEC512_ROT_LEFT(a, r)                                   \
        do {                                                    \
                typeof(a) _x;                                   \
                _x  = _mm512_slli_si512(a, r / 8);              \
                a   = _mm512_srli_si512(a, (128 - r) / 8);      \
                a   = _mm512_or_si512(a, _x);                   \
        } while(0)
#else
#define VEC512_ADD_XOR_ROT(a,b,c,r)
#define VEC512_ROT_RIGHT(a, r)
#define VEC512_ROT_LEFT(a, r)
#endif


#if !defined(ADD_XOR_ROT) || !defined(ROT_RIGHT) || !defined(ROT_LEFT)
# error invalid
#endif

#define DOUBLE_ROUNDS(rounds,v0,v1,v2,v3)       \
do {                                            \
        /*                                      \
         * v0 += v1;                            \
         * v3 ^= v0;                            \
         * v3 <<<= (16, 16, 16, 16);            \
         */                                     \
        ADD_XOR_ROT(v0, v1, v3, 16);            \
                                                \
        /*                                      \
         * v2 += v3;                            \
         * v1 ^= v2;                            \
         * v1 <<<= (12, 12, 12, 12);            \
         */                                     \
        ADD_XOR_ROT(v2, v3, v1, 12);            \
                                                \
        /*                                      \
         * v0 += v1;                            \
         * v3 ^= v0;                            \
         * v3 <<<= ( 8,  8,  8,  8);            \
         */                                     \
        ADD_XOR_ROT(v0, v1, v3, 8);             \
                                                \
        /*                                      \
         * v2 += v3;                            \
         * v1 ^= v2;                            \
         * v1 <<<= ( 7,  7,  7,  7);            \
         */                                     \
        ADD_XOR_ROT(v2, v3, v1, 7);             \
                                                \
        /*                                      \
         * v1 >>>= 32;                          \
         * v2 >>>= 64;                          \
         * v3 >>>= 96;                          \
         */                                     \
        ROT_RIGHT(v1, 32);                      \
        ROT_RIGHT(v2, 64);                      \
        ROT_RIGHT(v3, 96);                      \
                                                \
        /*                                      \
         * v0 += v1;                            \
         * v3 ^= v0;                            \
         * v3 <<<= (16, 16, 16, 16);            \
         */                                     \
        ADD_XOR_ROT(v0, v1, v3, 16);            \
                                                \
        /*                                      \
         * v2 += v3;                            \
         * v1 ^= v2;                            \
         * v1 <<<= (12, 12, 12, 12);            \
         */                                     \
        ADD_XOR_ROT(v2, v3, v1, 12);            \
                                                \
        /*                                      \
         * v0 += v1;                            \
         * v3 ^= v0;                            \
         * v3 <<<= ( 8,  8,  8,  8);            \
         */                                     \
        ADD_XOR_ROT(v0, v1, v3, 8);             \
                                                \
        /*                                      \
         * v2 += v3;                            \
         * v1 ^= v2;                            \
         * v1 <<<= ( 7,  7,  7,  7);            \
         */                                     \
        ADD_XOR_ROT(v2, v3, v1, 7);             \
                                                \
        /*                                      \
         * v1 <<<= 32;                          \
         * v2 <<<= 64;                          \
         * v3 <<<= 96;                          \
         */                                     \
        ROT_LEFT(v1, 32);                       \
        ROT_LEFT(v2, 64);                       \
        ROT_LEFT(v3, 96);                       \
 } while (--(rounds))


#define DOUBLE_ROUNDS_X2(rounds,v0,v1,v2,v3,n0,n1,n2,n3)        \
do {                                            \
        /*                                      \
         * v0 += v1;                            \
         * v3 ^= v0;                            \
         * v3 <<<= (16, 16, 16, 16);            \
         */                                     \
        ADD_XOR_ROT(v0, v1, v3, 16);            \
        ADD_XOR_ROT(n0, n1, n3, 16);            \
                                                \
        /*                                      \
         * v2 += v3;                            \
         * v1 ^= v2;                            \
         * v1 <<<= (12, 12, 12, 12);            \
         */                                     \
        ADD_XOR_ROT(v2, v3, v1, 12);            \
        ADD_XOR_ROT(n2, n3, n1, 12);            \
                                                \
        /*                                      \
         * v0 += v1;                            \
         * v3 ^= v0;                            \
         * v3 <<<= ( 8,  8,  8,  8);            \
         */                                     \
        ADD_XOR_ROT(v0, v1, v3, 8);             \
        ADD_XOR_ROT(n0, n1, n3, 8);             \
                                                \
        /*                                      \
         * v2 += v3;                            \
         * v1 ^= v2;                            \
         * v1 <<<= ( 7,  7,  7,  7);            \
         */                                     \
        ADD_XOR_ROT(v2, v3, v1, 7);             \
        ADD_XOR_ROT(n2, n3, n1, 7);             \
                                                \
        /*                                      \
         * v1 >>>= 32;                          \
         * v2 >>>= 64;                          \
         * v3 >>>= 96;                          \
         */                                     \
        ROT_RIGHT(v1, 32);                      \
        ROT_RIGHT(n1, 32);                      \
        ROT_RIGHT(v2, 64);                      \
        ROT_RIGHT(n2, 64);                      \
        ROT_RIGHT(v3, 96);                      \
        ROT_RIGHT(n3, 96);                      \
                                                \
        /*                                      \
         * v0 += v1;                            \
         * v3 ^= v0;                            \
         * v3 <<<= (16, 16, 16, 16);            \
         */                                     \
        ADD_XOR_ROT(v0, v1, v3, 16);            \
        ADD_XOR_ROT(n0, n1, n3, 16);            \
                                                \
        /*                                      \
         * v2 += v3;                            \
         * v1 ^= v2;                            \
         * v1 <<<= (12, 12, 12, 12);            \
         */                                     \
        ADD_XOR_ROT(v2, v3, v1, 12);            \
        ADD_XOR_ROT(n2, n3, n1, 12);            \
                                                \
        /*                                      \
         * v0 += v1;                            \
         * v3 ^= v0;                            \
         * v3 <<<= ( 8,  8,  8,  8);            \
         */                                     \
        ADD_XOR_ROT(v0, v1, v3, 8);             \
        ADD_XOR_ROT(n0, n1, n3, 8);             \
                                                \
        /*                                      \
         * v2 += v3;                            \
         * v1 ^= v2;                            \
         * v1 <<<= ( 7,  7,  7,  7);            \
         */                                     \
        ADD_XOR_ROT(v2, v3, v1, 7);             \
        ADD_XOR_ROT(n2, n3, n1, 7);             \
                                                \
        /*                                      \
         * v1 <<<= 32;                          \
         * v2 <<<= 64;                          \
         * v3 <<<= 96;                          \
         */                                     \
        ROT_LEFT(v1, 32);                       \
        ROT_LEFT(n1, 32);                       \
        ROT_LEFT(v2, 64);                       \
        ROT_LEFT(n2, 64);                       \
        ROT_LEFT(v3, 96);                       \
        ROT_LEFT(n3, 96);                       \
 } while (--(rounds))

#define DOUBLE_ROUNDS_X3(rounds,v0,v1,v2,v3,n0,n1,n2,n3,m0,m1,m2,m3)    \
do {                                            \
        /*                                      \
         * v0 += v1;                            \
         * v3 ^= v0;                            \
         * v3 <<<= (16, 16, 16, 16);            \
         */                                     \
        ADD_XOR_ROT(v0, v1, v3, 16);            \
        ADD_XOR_ROT(n0, n1, n3, 16);            \
        ADD_XOR_ROT(m0, m1, m3, 16);            \
                                                \
        /*                                      \
         * v2 += v3;                            \
         * v1 ^= v2;                            \
         * v1 <<<= (12, 12, 12, 12);            \
         */                                     \
        ADD_XOR_ROT(v2, v3, v1, 12);            \
        ADD_XOR_ROT(n2, n3, n1, 12);            \
        ADD_XOR_ROT(m2, m3, m1, 12);            \
                                                \
        /*                                      \
         * v0 += v1;                            \
         * v3 ^= v0;                            \
         * v3 <<<= ( 8,  8,  8,  8);            \
         */                                     \
        ADD_XOR_ROT(v0, v1, v3, 8);             \
        ADD_XOR_ROT(n0, n1, n3, 8);             \
        ADD_XOR_ROT(m0, m1, m3, 8);             \
                                                \
        /*                                      \
         * v2 += v3;                            \
         * v1 ^= v2;                            \
         * v1 <<<= ( 7,  7,  7,  7);            \
         */                                     \
        ADD_XOR_ROT(v2, v3, v1, 7);             \
        ADD_XOR_ROT(n2, n3, n1, 7);             \
        ADD_XOR_ROT(m2, m3, m1, 7);             \
                                                \
        /*                                      \
         * v1 >>>= 32;                          \
         * v2 >>>= 64;                          \
         * v3 >>>= 96;                          \
         */                                     \
        ROT_RIGHT(v1, 32);                      \
        ROT_RIGHT(n1, 32);                      \
        ROT_RIGHT(m1, 32);                      \
                                                \
        ROT_RIGHT(v2, 64);                      \
        ROT_RIGHT(n2, 64);                      \
        ROT_RIGHT(m2, 64);                      \
                                                \
        ROT_RIGHT(v3, 96);                      \
        ROT_RIGHT(n3, 96);                      \
        ROT_RIGHT(m3, 96);                      \
                                                \
        /*                                      \
         * v0 += v1;                            \
         * v3 ^= v0;                            \
         * v3 <<<= (16, 16, 16, 16);            \
         */                                     \
        ADD_XOR_ROT(v0, v1, v3, 16);            \
        ADD_XOR_ROT(n0, n1, n3, 16);            \
        ADD_XOR_ROT(m0, m1, m3, 16);            \
                                                \
        /*                                      \
         * v2 += v3;                            \
         * v1 ^= v2;                            \
         * v1 <<<= (12, 12, 12, 12);            \
         */                                     \
        ADD_XOR_ROT(v2, v3, v1, 12);            \
        ADD_XOR_ROT(n2, n3, n1, 12);            \
        ADD_XOR_ROT(m2, m3, m1, 12);            \
                                                \
        /*                                      \
         * v0 += v1;                            \
         * v3 ^= v0;                            \
         * v3 <<<= ( 8,  8,  8,  8);            \
         */                                     \
        ADD_XOR_ROT(v0, v1, v3, 8);             \
        ADD_XOR_ROT(n0, n1, n3, 8);             \
        ADD_XOR_ROT(m0, m1, m3, 8);             \
                                                \
        /*                                      \
         * v2 += v3;                            \
         * v1 ^= v2;                            \
         * v1 <<<= ( 7,  7,  7,  7);            \
         */                                     \
        ADD_XOR_ROT(v2, v3, v1, 7);             \
        ADD_XOR_ROT(n2, n3, n1, 7);             \
        ADD_XOR_ROT(m2, m3, m1, 7);             \
                                                \
        /*                                      \
         * v1 <<<= 32;                          \
         * v2 <<<= 64;                          \
         * v3 <<<= 96;                          \
         */                                     \
        ROT_LEFT(v1, 32);                       \
        ROT_LEFT(n1, 32);                       \
        ROT_LEFT(m1, 32);                       \
                                                \
        ROT_LEFT(v2, 64);                       \
        ROT_LEFT(n2, 64);                       \
        ROT_LEFT(m2, 64);                       \
                                                \
        ROT_LEFT(v3, 96);                       \
        ROT_LEFT(n3, 96);                       \
        ROT_LEFT(m3, 96);                       \
 } while (--(rounds))

#define DOUBLE_ROUNDS_X4(rounds,                \
                         v0,v1,v2,v3,           \
                         n0,n1,n2,n3,           \
                         m0,m1,m2,m3,           \
                         p0,p1,p2,p3)           \
do {                                            \
        /*                                      \
         * v0 += v1;                            \
         * v3 ^= v0;                            \
         * v3 <<<= (16, 16, 16, 16);            \
         */                                     \
        ADD_XOR_ROT(v0, v1, v3, 16);            \
        ADD_XOR_ROT(n0, n1, n3, 16);            \
        ADD_XOR_ROT(m0, m1, m3, 16);            \
        ADD_XOR_ROT(p0, p1, p3, 16);            \
                                                \
        /*                                      \
         * v2 += v3;                            \
         * v1 ^= v2;                            \
         * v1 <<<= (12, 12, 12, 12);            \
         */                                     \
        ADD_XOR_ROT(v2, v3, v1, 12);            \
        ADD_XOR_ROT(n2, n3, n1, 12);            \
        ADD_XOR_ROT(m2, m3, m1, 12);            \
        ADD_XOR_ROT(p2, p3, p1, 12);            \
                                                \
        /*                                      \
         * v0 += v1;                            \
         * v3 ^= v0;                            \
         * v3 <<<= ( 8,  8,  8,  8);            \
         */                                     \
        ADD_XOR_ROT(v0, v1, v3, 8);             \
        ADD_XOR_ROT(n0, n1, n3, 8);             \
        ADD_XOR_ROT(m0, m1, m3, 8);             \
        ADD_XOR_ROT(p0, p1, p3, 8);             \
                                                \
        /*                                      \
         * v2 += v3;                            \
         * v1 ^= v2;                            \
         * v1 <<<= ( 7,  7,  7,  7);            \
         */                                     \
        ADD_XOR_ROT(v2, v3, v1, 7);             \
        ADD_XOR_ROT(n2, n3, n1, 7);             \
        ADD_XOR_ROT(m2, m3, m1, 7);             \
        ADD_XOR_ROT(p2, p3, p1, 7);             \
                                                \
        /*                                      \
         * v1 >>>= 32;                          \
         * v2 >>>= 64;                          \
         * v3 >>>= 96;                          \
         */                                     \
        ROT_RIGHT(v1, 32);                      \
        ROT_RIGHT(n1, 32);                      \
        ROT_RIGHT(m1, 32);                      \
        ROT_RIGHT(p1, 32);                      \
                                                \
        ROT_RIGHT(v2, 64);                      \
        ROT_RIGHT(n2, 64);                      \
        ROT_RIGHT(m2, 64);                      \
        ROT_RIGHT(p2, 64);                      \
                                                \
        ROT_RIGHT(v3, 96);                      \
        ROT_RIGHT(n3, 96);                      \
        ROT_RIGHT(m3, 96);                      \
        ROT_RIGHT(p3, 96);                      \
                                                \
        /*                                      \
         * v0 += v1;                            \
         * v3 ^= v0;                            \
         * v3 <<<= (16, 16, 16, 16);            \
         */                                     \
        ADD_XOR_ROT(v0, v1, v3, 16);            \
        ADD_XOR_ROT(n0, n1, n3, 16);            \
        ADD_XOR_ROT(m0, m1, m3, 16);            \
        ADD_XOR_ROT(p0, p1, p3, 16);            \
                                                \
        /*                                      \
         * v2 += v3;                            \
         * v1 ^= v2;                            \
         * v1 <<<= (12, 12, 12, 12);            \
         */                                     \
        ADD_XOR_ROT(v2, v3, v1, 12);            \
        ADD_XOR_ROT(n2, n3, n1, 12);            \
        ADD_XOR_ROT(m2, m3, m1, 12);            \
        ADD_XOR_ROT(p2, p3, p1, 12);            \
                                                \
        /*                                      \
         * v0 += v1;                            \
         * v3 ^= v0;                            \
         * v3 <<<= ( 8,  8,  8,  8);            \
         */                                     \
        ADD_XOR_ROT(v0, v1, v3, 8);             \
        ADD_XOR_ROT(n0, n1, n3, 8);             \
        ADD_XOR_ROT(m0, m1, m3, 8);             \
        ADD_XOR_ROT(p0, p1, p3, 8);             \
                                                \
        /*                                      \
         * v2 += v3;                            \
         * v1 ^= v2;                            \
         * v1 <<<= ( 7,  7,  7,  7);            \
         */                                     \
        ADD_XOR_ROT(v2, v3, v1, 7);             \
        ADD_XOR_ROT(n2, n3, n1, 7);             \
        ADD_XOR_ROT(m2, m3, m1, 7);             \
        ADD_XOR_ROT(p2, p3, p1, 7);             \
                                                \
        /*                                      \
         * v1 <<<= 32;                          \
         * v2 <<<= 64;                          \
         * v3 <<<= 96;                          \
         */                                     \
        ROT_LEFT(v1, 32);                       \
        ROT_LEFT(n1, 32);                       \
        ROT_LEFT(m1, 32);                       \
        ROT_LEFT(p1, 32);                       \
                                                \
        ROT_LEFT(v2, 64);                       \
        ROT_LEFT(n2, 64);                       \
        ROT_LEFT(m2, 64);                       \
        ROT_LEFT(p2, 64);                       \
                                                \
        ROT_LEFT(v3, 96);                       \
        ROT_LEFT(n3, 96);                       \
        ROT_LEFT(m3, 96);                       \
        ROT_LEFT(p3, 96);                       \
 } while (--(rounds))

#endif /* !_CHACHA_ROUND_H_ */
