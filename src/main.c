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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <x86intrin.h>

#include "chacha.h"
#include "chacha_dbg.h"

struct test_vector_s {
        /* key */
        const uint8_t *K;
        size_t         Klen;

        /* salt */
        const uint8_t *S;
        size_t         Slen;

        /* IV */
        const uint8_t *I;
        size_t         Ilen;

        /* text */
        const uint8_t *P;
        const uint8_t *C;
        size_t Plen;

};

static const uint8_t Key_chacha[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};

static const uint8_t Salt_chacha[] = {
        0x00, 0x00, 0x00, 0x00,
};

static const uint8_t IV_chacha[] = {
        0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t Plain_chacha[] = {
        0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61,
        0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
        0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
        0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39,
        0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
        0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66,
        0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
#if 0
        0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20,
        0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75,
        0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
        0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f,
        0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
        0x74, 0x2e,
#endif
};

static const uint8_t Cipher_chacha[] = {
        0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80,
        0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
        0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2,
        0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
        0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab,
        0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
        0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab,
        0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
#if 0
        0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61,
        0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
        0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06,
        0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
        0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6,
        0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
        0x87, 0x4d,
#endif
};

#define VECTOR(X)                                               \
        {                                                       \
                Key_##X,sizeof(Key_##X),                        \
                (Salt_##X),sizeof(Salt_##X),                    \
                (IV_##X),sizeof(IV_##X),                        \
                Plain_##X,Cipher_##X,sizeof(Plain_##X),         \
        }


static const struct test_vector_s test_vectores[] = {
        VECTOR(chacha),
};

static int
set_random(void *dst,
           size_t len)
{
        int fd;
        int ret = -1;

        if ((fd = open("/dev/urandom", 0)) >= 0) {
                if (read(fd, dst, len) == (ssize_t) len)
                        ret = 0;
                close(fd);
        }
        return ret;
}

/*
 * on cache perf
 */
static void
benchmark(const char *name,
          void (*fnc)(uint8_t *,
                      const uint8_t *,
                      size_t,
                      const uint8_t *,
                      const uint8_t *,
                      const uint8_t *))
{
        struct data_s {
                uint8_t txt[1024 * 64];
                uint8_t key[CHACHA_KEY_LEN];
                uint8_t salt[CHACHA_SALT_LEN];
                uint8_t iv[CHACHA_IV_LEN];
        } ;
        struct data_s data, *data_p = &data;
        for (size_t len = sizeof(data.txt); len >= CHACHA_BLOCK_LEN; len >>= 1) {
                size_t sum = 0;
                unsigned loops = 10240;
                uint64_t time;
                uint32_t aux;

                set_random(data_p, sizeof(*data_p));
                time = __rdtscp(&aux);
                while (loops--) {
                        fnc(data_p->txt, data_p->txt, len,
                            data_p->key, data_p->salt, data_p->iv);
                        sum += len;
                }
                time = __rdtscp(&aux) - time;

                fprintf(stderr, "benchmarck %s %zu: %f %lu %lu\n",
                        name,
                        len,
                        (double) time / sum,
                        (unsigned long) time / 10240,
                        (unsigned long) time);
        }
}

static inline void
verify(const char *name,
       void (*fnc)(uint8_t *,
                   const uint8_t *,
                   size_t,
                   const uint8_t *,
                   const uint8_t *,
                   const uint8_t *))
{
        struct {
                uint8_t plain[1025 * 64];
                uint8_t salt[64 + CHACHA_SALT_LEN];
                uint8_t key[64 + CHACHA_KEY_LEN];
                uint8_t iv[64 + CHACHA_IV_LEN];
        } data;

        if (set_random(&data, sizeof(data)))
                exit(0);

        for (size_t offset = 0; offset < 64; offset++) {
                uint8_t cipher_0[1025 * 64];
                uint8_t cipher_1[1025 * 64];

                for (size_t len = 1; len <= 1024 * 64; len += 1) {
                        chacha_gen(&cipher_0[offset],
                                   &data.plain[offset],
                                   len,
                                   &data.key[offset],
                                   &data.salt[offset],
                                   &data.iv[offset]);

                        fnc(&cipher_1[offset],
                            &data.plain[offset],
                            len,
                            &data.key[offset],
                            &data.salt[offset],
                            &data.iv[offset]);

                        if (memcmp(&cipher_0[offset], &cipher_1[offset], len)) {
                                fprintf(stderr,
                                        "%s failed verify offset:%zu len:%zu\n",
                                        name, offset, len);
                                exit(0);
                        }
                }
                fprintf(stderr, "ok offset:%zu\n", offset);
        }
}

static inline void
test_arch(const char *name,
          void (*fnc)(uint8_t *,
                      const uint8_t *,
                      size_t,
                      const uint8_t *,
                      const uint8_t *,
                      const uint8_t *),
          const struct test_vector_s *vec)
{
        uint8_t cipher[vec->Plen];

        memset(cipher, 0, sizeof(cipher));
        fnc(cipher, vec->P, vec->Plen, vec->K, vec->S, vec->I);

        if (memcmp(cipher, vec->C, vec->Plen))
                fprintf(stderr, "%s mismatched cipher\n", name);
#if 0
        uint8_t plain[vec->Plen];
        fnc(plain, vec->C, vec->Plen, vec->K, vec->S, vec->I);
        if (memcmp(plain, vec->P, vec->Plen))
                fprintf(stderr, "%s mismatched plain\n", name);
#endif
}


enum arch_e {
        arch_gen = 0,
        arch_sse,
        arch_avx,
        arch_avx2,
        arch_avx512,

        ARCH_NB,
};

enum action_e {
        act_test = 0,
        act_verify,
        act_bench,
};

const char *arch_name[] = {
        "generic",
        "sse",
        "avx",
        "avx2",
        "avx512",
};

static void
test(unsigned act_flags,
     unsigned arch_flags)
{
        if (act_flags & 1u << act_test) {
                if (arch_flags & 1u << arch_gen) {
                        test_arch(arch_name[arch_gen], chacha_gen,
                                  &test_vectores[0]);
                }
                if (arch_flags & 1u << arch_sse) {
                        test_arch(arch_name[arch_sse], chacha_sse,
                                  &test_vectores[0]);
                }
                if (arch_flags & 1u << arch_avx) {
                        test_arch(arch_name[arch_avx], chacha_avx,
                                  &test_vectores[0]);
                }
                if (arch_flags & 1u << arch_avx2) {
                        test_arch(arch_name[arch_avx2], chacha_avx2,
                                  &test_vectores[0]);
                }
                if (arch_flags & 1u << arch_avx512) {
                        test_arch(arch_name[arch_avx512], chacha_avx512,
                                  &test_vectores[0]);
                }
        }
        if (act_flags & 1u << act_verify) {
                if (arch_flags & 1u << arch_sse) {
                        verify(arch_name[arch_sse], chacha_sse);
                }
                if (arch_flags & 1u << arch_avx) {
                        verify(arch_name[arch_avx], chacha_avx);
                }
                if (arch_flags & 1u << arch_avx2) {
                        verify(arch_name[arch_avx2], chacha_avx2);
                }
                if (arch_flags & 1u << arch_avx512) {
                        verify(arch_name[arch_avx512], chacha_avx512);
                }
        }
        if (act_flags & 1u << act_bench) {
                if (arch_flags & 1u << arch_gen) {
                        benchmark(arch_name[arch_gen], chacha_gen);
                }
                if (arch_flags & 1u << arch_sse) {
                        benchmark(arch_name[arch_sse], chacha_sse);
                }
                if (arch_flags & 1u << arch_avx) {
                        benchmark(arch_name[arch_avx], chacha_avx);
                }
                if (arch_flags & 1u << arch_avx2) {
                        benchmark(arch_name[arch_avx2], chacha_avx2);
                }
                if (arch_flags & 1u << arch_avx512) {
                        benchmark(arch_name[arch_avx512], chacha_avx512);
                }
        }
}

static void
usage(const char *prog)
{
        fprintf(stderr,
                "%s [-t] [-v] [-b] [-g] [-s] [-a] [-2] [-5]\n"
                "\t-t:\tACT test\n"
                "\t-v:\tACT verify\n"
                "\t-b:\tACT benchmark\n"
                "\t-g:\tARCH generic\n"
                "\t-s:\tARCH SSE\n"
                "\t-a:\tARCH AVX\n"
                "\t-2:\tARCH AVX2\n"
                "\t-5:\tARCH AVX512\n",
                prog);
}

int
main(int ac, char **av)
{
        int opt;
        unsigned arch_flags = 0;
        unsigned act_flags = 0;

        while ((opt = getopt(ac, av, "tvbasg25")) != -1) {
                switch (opt) {
                case 't':
                        act_flags |= 1u << act_test;
                        break;
                case 'v':
                        act_flags |= 1u << act_verify;
                        break;
                case 'b':
                        act_flags |= 1u << act_bench;
                        break;
                case 'a':	/* avx */
                        arch_flags |= 1u << arch_avx;
                        break;
                case 's':	/* sse */
                        arch_flags |= 1u << arch_sse;
                        break;
                case 'g':	/* generic */
                        arch_flags |= 1u << arch_gen;
                        break;
                case '2':
                        arch_flags |= 1u << arch_avx2;
                        break;
                case '5':
                        arch_flags |= 1u << arch_avx512;
                        break;
                default:
                        usage(av[0]);
                        return 0;
                }
        }

        if (!act_flags || !arch_flags) {
                usage(av[0]);
                return 0;
        }
        test(act_flags, arch_flags);

        return 0;
}
