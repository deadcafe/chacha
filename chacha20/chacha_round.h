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

/********************************************************************************
 * common round operation
 ********************************************************************************/
/*
 * Basix operations
 */
#define QUARTER_LINE0(a,b,c,d)                  \
        do {                                    \
                a = PLUS(a, b);                 \
                d = XOR(d, a);                  \
                d = ROTATE_LEFT_16(d);          \
        } while (0)

#define QUARTER_LINE1(a,b,c,d)                  \
        do {                                    \
                c = PLUS(c, d);                 \
                b = XOR(b, c);                  \
                b = ROTATE_LEFT_12(b);          \
        } while (0)

#define QUARTER_LINE2(a,b,c,d)                  \
        do {                                    \
                a = PLUS(a, b);                 \
                d = XOR(d, a);                  \
                d = ROTATE_LEFT_8(d);           \
        } while (0)

#define QUARTER_LINE3(a,b,c,d)                  \
        do {                                    \
                c = PLUS(c, d);                 \
                b = XOR(b, c);                  \
                b = ROTATE_LEFT_7(b);           \
        } while (0)

#define QUARTER_ROUND(a,b,c,d)                  \
        do {                                    \
                QUARTER_LINE0(a, b, c, d);      \
                QUARTER_LINE1(a, b, c, d);      \
                QUARTER_LINE2(a, b, c, d);      \
                QUARTER_LINE3(a, b, c, d);      \
        } while (0)

#define DOUBLE_ROUND(x0,x1,x2,x3,                               \
                     x4,x5,x6,x7,                               \
                     x8,x9,xa,xb,                               \
                     xc,xd,xe,xf)                               \
        do {                                                    \
                QUARTER_ROUND(v_##x0, v_##x4, v_##x8, v_##xc);  \
                QUARTER_ROUND(v_##x1, v_##x5, v_##x9, v_##xd);	\
                QUARTER_ROUND(v_##x2, v_##x6, v_##xa, v_##xe);  \
                QUARTER_ROUND(v_##x3, v_##x7, v_##xb, v_##xf);  \
                QUARTER_ROUND(v_##x0, v_##x5, v_##xa, v_##xf);  \
                QUARTER_ROUND(v_##x1, v_##x6, v_##xb, v_##xc);  \
                QUARTER_ROUND(v_##x2, v_##x7, v_##x8, v_##xd);  \
                QUARTER_ROUND(v_##x3, v_##x4, v_##x9, v_##xe);  \
        } while (0)

/*
 * v0: (x0, x1, x2, x3)
 * v1: (x4, x5, x6, x7)
 * v2: (x8, x9, xa, xb)
 * v3: (xc, xd, xe, xf)
 */

#define VEC_DOUBLE_QUARTER_ROUND(v0,v1,v2,v3)                           \
        do {                                                            \
                QUARTER_LINE0(v_##v0, v_##v1, v_##v2, v_##v3);          \
                QUARTER_LINE1(v_##v0, v_##v1, v_##v2, v_##v3);          \
                QUARTER_LINE2(v_##v0, v_##v1, v_##v2, v_##v3);          \
                QUARTER_LINE3(v_##v0, v_##v1, v_##v2, v_##v3);          \
                VEC_ROTATE_RIGHT_ALL(v_##v0, v_##v1, v_##v2, v_##v3);   \
                                                                        \
                QUARTER_LINE0(v_##v0, v_##v1, v_##v2, v_##v3);          \
                QUARTER_LINE1(v_##v0, v_##v1, v_##v2, v_##v3);          \
                QUARTER_LINE2(v_##v0, v_##v1, v_##v2, v_##v3);          \
                QUARTER_LINE3(v_##v0, v_##v1, v_##v2, v_##v3);          \
                VEC_ROTATE_LEFT_ALL(v_##v0, v_##v1, v_##v2, v_##v3);    \
        } while (0)

#endif /* !_CHVCHV_ROUND_H_ */
