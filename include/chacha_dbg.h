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

#ifndef _CHACHA_DBG_H_
#define _CHACHA_DBG_H_

#include <stdio.h>

static inline void
_hexdump(FILE *fp,
         const char *msg,
         const void *p,
         size_t len)
{
        unsigned int i, out, ofs;
        const unsigned char *data = p;

        fprintf(fp, "%s\n", msg);

        ofs = 0;
        while (ofs < len) {
                char line[120];

                out = snprintf(line, sizeof(line), "%08x:", ofs);
                for (i = 0; ((ofs + i) < len) && (i < 16); i++)
                        out += snprintf(line + out, sizeof(line) - out,
                                        " %02x", (data[ofs + i] & 0xff));
                for(; i <= 16; i++)
                        out += snprintf(line + out, sizeof(line) - out, " | ");
                for(i = 0; (ofs < len) && (i < 16); i++, ofs++) {
                        unsigned char c = data[ofs];

                        if ( (c < ' ') || (c > '~'))
                                c = '.';
                        out += snprintf(line + out, sizeof(line) - out, "%c", c);
                }
                fprintf(fp, "%s\n", line);
        }
}


#define HEXDUMP(m,p,l)	_hexdump(stderr, m,p,l)

#define DBG_TRACE(fmt, ...)	fprintf(stderr, "%s:%d " fmt, __func__, __LINE__, __VA_ARGS__)

#endif /* !_CHACHA_DBG_H_ */
