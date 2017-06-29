#if 0
#define VEC8_ROT(a,imm) _mm256_or_si256(_mm256_slli_epi32(a, imm), _mm256_srli_epi32(a, (32-imm)))

#define VEC8_QUARTERROUND_SHUFFLE(a,b,c,d)                              \
        x_##a = _mm256_add_epi32(x_##a, x_##b);                         \
        t_##a = _mm256_xor_si256(x_##d, x_##a);                         \
        x_##d = _mm256_shuffle_epi8(t_##a, rot16);                      \
        x_##c = _mm256_add_epi32(x_##c, x_##d);                         \
        t_##c = _mm256_xor_si256(x_##b, x_##c);                         \
        x_##b = VEC8_ROT(t_##c, 12);                                    \
        x_##a = _mm256_add_epi32(x_##a, x_##b);                         \
        t_##a = _mm256_xor_si256(x_##d, x_##a);                         \
        x_##d = _mm256_shuffle_epi8(t_##a, rot8);                       \
        x_##c = _mm256_add_epi32(x_##c, x_##d);                         \
        t_##c = _mm256_xor_si256(x_##b, x_##c);                         \
        x_##b = VEC8_ROT(t_##c,  7)

#define VEC8_QUARTERROUND(a,b,c,d) VEC8_QUARTERROUND_SHUFFLE(a,b,c,d)

#define VEC8_LINE1(a,b,c,d)                                             \
        x_##a = _mm256_add_epi32(x_##a, x_##b);                         \
        x_##d = _mm256_shuffle_epi8(_mm256_xor_si256(x_##d, x_##a), rot16)

#define VEC8_LINE2(a,b,c,d)                                             \
        x_##c = _mm256_add_epi32(x_##c, x_##d);                         \
        x_##b = VEC8_ROT(_mm256_xor_si256(x_##b, x_##c), 12)

#define VEC8_LINE3(a,b,c,d)                                             \
        x_##a = _mm256_add_epi32(x_##a, x_##b);                         \
        x_##d = _mm256_shuffle_epi8(_mm256_xor_si256(x_##d, x_##a), rot8)

#define VEC8_LINE4(a,b,c,d)                                             \
        x_##c = _mm256_add_epi32(x_##c, x_##d);                         \
        x_##b = VEC8_ROT(_mm256_xor_si256(x_##b, x_##c),  7)

#define VEC8_ROUND_SEQ(a1,b1,c1,d1,a2,b2,c2,d2,a3,b3,c3,d3,a4,b4,c4,d4) \
        VEC8_LINE1(a1, b1, c1, d1);                                     \
        VEC8_LINE1(a2, b2, c2, d2);                                     \
        VEC8_LINE1(a3, b3, c3, d3);                                     \
        VEC8_LINE1(a4, b4, c4, d4);                                     \
        VEC8_LINE2(a1, b1, c1, d1);                                     \
        VEC8_LINE2(a2, b2, c2, d2);                                     \
        VEC8_LINE2(a3, b3, c3, d3);                                     \
        VEC8_LINE2(a4, b4, c4, d4);                                     \
        VEC8_LINE3(a1, b1, c1, d1);                                     \
        VEC8_LINE3(a2, b2, c2, d2);                                     \
        VEC8_LINE3(a3, b3, c3, d3);                                     \
        VEC8_LINE3(a4, b4, c4, d4);                                     \
        VEC8_LINE4(a1, b1, c1, d1);                                     \
        VEC8_LINE4(a2, b2, c2, d2);                                     \
        VEC8_LINE4(a3, b3, c3, d3);                                     \
        VEC8_LINE4(a4, b4, c4, d4)

#define VEC8_ROUND(a1,b1,c1,d1,a2,b2,c2,d2,a3,b3,c3,d3,a4,b4,c4,d4)     \
        VEC8_ROUND_SEQ(a1,b1,c1,d1,a2,b2,c2,d2,a3,b3,c3,d3,a4,b4,c4,d4)

#define ROUNDS 20

#define ROTATE(v,c) (ROTL32(v,c))
#define XOR(v,w) ((v) ^ (w))
#define PLUS(v,w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v),1))

#define QUARTERROUND(a,b,c,d)                                           \
        x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]),16);       \
        x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]),12);       \
        x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]), 8);       \
        x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]), 7);

#define ONEQUAD_TRANSPOSE(a,b,c,d)                                      \
        {                                                               \
                __m128i t0, t1, t2, t3;                                 \
                x_##a = _mm256_add_epi32(x_##a, orig##a);               \
                x_##b = _mm256_add_epi32(x_##b, orig##b);               \
                x_##c = _mm256_add_epi32(x_##c, orig##c);               \
                x_##d = _mm256_add_epi32(x_##d, orig##d);               \
                t_##a = _mm256_unpacklo_epi32(x_##a, x_##b);            \
                t_##b = _mm256_unpacklo_epi32(x_##c, x_##d);            \
                t_##c = _mm256_unpackhi_epi32(x_##a, x_##b);            \
                t_##d = _mm256_unpackhi_epi32(x_##c, x_##d);            \
                x_##a = _mm256_unpacklo_epi64(t_##a, t_##b);            \
                x_##b = _mm256_unpackhi_epi64(t_##a, t_##b);            \
                x_##c = _mm256_unpacklo_epi64(t_##c, t_##d);            \
                x_##d = _mm256_unpackhi_epi64(t_##c, t_##d);            \
                t0 = _mm_xor_si128(_mm256_extracti128_si256(x_##a, 0),  \
                                   _mm_loadu_si128((__m128i *) (m + 0))); \
                _mm_storeu_si128((__m128i *) (out + 0), t0);            \
                t1 = _mm_xor_si128(_mm256_extracti128_si256(x_##b, 0),  \
                                   _mm_loadu_si128((__m128i *) (m + 64))); \
                _mm_storeu_si128((__m128i *) (out + 64), t1);           \
                t2 = _mm_xor_si128(_mm256_extracti128_si256(x_##c, 0),  \
                                   _mm_loadu_si128((__m128i *) (m + 128))); \
                _mm_storeu_si128((__m128i *) (out + 128), t2);          \
                t3 = _mm_xor_si128(_mm256_extracti128_si256(x_##d, 0),  \
                                   _mm_loadu_si128((__m128i *) (m + 192))); \
                _mm_storeu_si128((__m128i *) (out + 192), t3);          \
                t0 = _mm_xor_si128(_mm256_extracti128_si256(x_##a, 1),  \
                                   _mm_loadu_si128((__m128i *) (m + 256))); \
                _mm_storeu_si128((__m128i *) (out + 256), t0);          \
                t1 = _mm_xor_si128(_mm256_extracti128_si256(x_##b, 1),  \
                                   _mm_loadu_si128((__m128i *) (m + 320))); \
                _mm_storeu_si128((__m128i *) (out + 320), t1);          \
                t2 = _mm_xor_si128(_mm256_extracti128_si256(x_##c, 1),  \
                                   _mm_loadu_si128((__m128i *) (m + 384))); \
                _mm_storeu_si128((__m128i *) (out + 384), t2);          \
                t3 = _mm_xor_si128(_mm256_extracti128_si256(x_##d, 1),  \
                                   _mm_loadu_si128((__m128i *) (m + 448))); \
                _mm_storeu_si128((__m128i *) (out + 448), t3);          \
        }

#define ONEQUAD(a,b,c,d) ONEQUAD_TRANSPOSE(a,b,c,d)

#define ONEQUAD_UNPCK(a,b,c,d)                                          \
        {                                                               \
                x_##a = _mm256_add_epi32(x_##a, orig##a);               \
                x_##b = _mm256_add_epi32(x_##b, orig##b);               \
                x_##c = _mm256_add_epi32(x_##c, orig##c);               \
                x_##d = _mm256_add_epi32(x_##d, orig##d);               \
                t_##a = _mm256_unpacklo_epi32(x_##a, x_##b);            \
                t_##b = _mm256_unpacklo_epi32(x_##c, x_##d);            \
                t_##c = _mm256_unpackhi_epi32(x_##a, x_##b);            \
                t_##d = _mm256_unpackhi_epi32(x_##c, x_##d);            \
                x_##a = _mm256_unpacklo_epi64(t_##a, t_##b);            \
                x_##b = _mm256_unpackhi_epi64(t_##a, t_##b);            \
                x_##c = _mm256_unpacklo_epi64(t_##c, t_##d);            \
                x_##d = _mm256_unpackhi_epi64(t_##c, t_##d);            \
        }

#define ONEOCTO(a,b,c,d,a2,b2,c2,d2)                                    \
        {                                                               \
                ONEQUAD_UNPCK(a, b, c, d);                              \
                ONEQUAD_UNPCK(a2, b2, c2, d2);                          \
                t_##a  = _mm256_permute2x128_si256(x_##a, x_##a2, 0x20); \
                t_##a2 = _mm256_permute2x128_si256(x_##a, x_##a2, 0x31); \
                t_##b  = _mm256_permute2x128_si256(x_##b, x_##b2, 0x20); \
                t_##b2 = _mm256_permute2x128_si256(x_##b, x_##b2, 0x31); \
                t_##c  = _mm256_permute2x128_si256(x_##c, x_##c2, 0x20); \
                t_##c2 = _mm256_permute2x128_si256(x_##c, x_##c2, 0x31); \
                t_##d  = _mm256_permute2x128_si256(x_##d, x_##d2, 0x20); \
                t_##d2 = _mm256_permute2x128_si256(x_##d, x_##d2, 0x31); \
                t_##a  = _mm256_xor_si256(t_##a , _mm256_loadu_si256((__m256i *) (m +   0))); \
                t_##b  = _mm256_xor_si256(t_##b , _mm256_loadu_si256((__m256i *) (m +  64))); \
                t_##c  = _mm256_xor_si256(t_##c , _mm256_loadu_si256((__m256i *) (m + 128))); \
                t_##d  = _mm256_xor_si256(t_##d , _mm256_loadu_si256((__m256i *) (m + 192))); \
                t_##a2 = _mm256_xor_si256(t_##a2, _mm256_loadu_si256((__m256i *) (m + 256))); \
                t_##b2 = _mm256_xor_si256(t_##b2, _mm256_loadu_si256((__m256i *) (m + 320))); \
                t_##c2 = _mm256_xor_si256(t_##c2, _mm256_loadu_si256((__m256i *) (m + 384))); \
                t_##d2 = _mm256_xor_si256(t_##d2, _mm256_loadu_si256((__m256i *) (m + 448))); \
                _mm256_storeu_si256((__m256i *) (out +   0), t_##a );   \
                _mm256_storeu_si256((__m256i *) (out +  64), t_##b );   \
                _mm256_storeu_si256((__m256i *) (out + 128), t_##c );   \
                _mm256_storeu_si256((__m256i *) (out + 192), t_##d );   \
                _mm256_storeu_si256((__m256i *) (out + 256), t_##a2);   \
                _mm256_storeu_si256((__m256i *) (out + 320), t_##b2);   \
                _mm256_storeu_si256((__m256i *) (out + 384), t_##c2);   \
                _mm256_storeu_si256((__m256i *) (out + 448), t_##d2);   \
        }

static void
salsa20_wordtobyte(u8 output[64],
                   const u32 input[16])
{
        u32 x[16];
        int i;

        for (i = 0; i < 16; ++i)
                x[i] = input[i];
        for (i = ROUNDS; i > 0; i -= 2) {
                QUARTERROUND( 0, 4, 8,12)
                QUARTERROUND( 1, 5, 9,13)
                QUARTERROUND( 2, 6,10,14)
                QUARTERROUND( 3, 7,11,15)
                QUARTERROUND( 0, 5,10,15)
                QUARTERROUND( 1, 6,11,12)
                QUARTERROUND( 2, 7, 8,13)
                QUARTERROUND( 3, 4, 9,14)
        }
        for (i = 0; i < 16; ++i)
                x[i] = PLUS(x[i],input[i]);
        for (i = 0; i < 16; ++i)
                U32TO8_LITTLE(output + 4 * i,x[i]);
}

void
ECRYPT_init(void)
{
        return;
}

static const char sigma[16] = "expand 32-byte k";
static const char tau[16] = "expand 16-byte k";

void
ECRYPT_keysetup(ECRYPT_ctx *x,
                const u8 *k,
                u32 kbits,
                u32 ivbits)
{
        const char *constants;

        x->input[4] = U8TO32_LITTLE(k + 0);
        x->input[5] = U8TO32_LITTLE(k + 4);
        x->input[6] = U8TO32_LITTLE(k + 8);
        x->input[7] = U8TO32_LITTLE(k + 12);
        if (kbits == 256) { /* recommended */
                k += 16;
                constants = sigma;
        } else { /* kbits == 128 */
                constants = tau;
        }
        x->input[8] = U8TO32_LITTLE(k + 0);
        x->input[9] = U8TO32_LITTLE(k + 4);
        x->input[10] = U8TO32_LITTLE(k + 8);
        x->input[11] = U8TO32_LITTLE(k + 12);
        x->input[0] = U8TO32_LITTLE(constants + 0);
        x->input[1] = U8TO32_LITTLE(constants + 4);
        x->input[2] = U8TO32_LITTLE(constants + 8);
        x->input[3] = U8TO32_LITTLE(constants + 12);
}

void
ECRYPT_ivsetup(ECRYPT_ctx *x,
               const u8 *iv)
{
        x->input[12] = 0;
        x->input[13] = 0;
        x->input[14] = U8TO32_LITTLE(iv + 0);
        x->input[15] = U8TO32_LITTLE(iv + 4);
}

void
ECRYPT_encrypt_bytes(ECRYPT_ctx *x_,
                     const u8 *m,
                     u8 *c_,
                     u32 bytes)
{
        u8 output[64];
        int i;
        u32* x = (u32 *) &x_->input;
        u8* out = c_;

        /* u8 */
        if (!bytes)
                return;
        if (bytes >= 512) {
                /* constant for shuffling bytes (replacing multiple-of-8 rotates) */
                __m256i rot16 = _mm256_set_epi8(13, 12, 15, 14,  9,  8, 11, 10,
                                                 5,  4,  7,  6,  1,  0,  3,  2,
                                                13, 12, 15, 14,  9,  8, 11, 10,
                                                 5,  4,  7,  6,  1,  0,  3,  2);
                __m256i rot8  = _mm256_set_epi8(14, 13, 12, 15, 10,  9,  8, 11,
                                                 6,  5,  4,  7,  2,  1,  0,  3,
                                                14, 13, 12, 15, 10,  9,  8, 11,
                                                 6,  5,  4,  7,  2,  1,  0,  3);
                u32 in12, in13;
                __m256i x_0 = _mm256_set1_epi32(x[0]);
                __m256i x_1 = _mm256_set1_epi32(x[1]);
                __m256i x_2 = _mm256_set1_epi32(x[2]);
                __m256i x_3 = _mm256_set1_epi32(x[3]);
                __m256i x_4 = _mm256_set1_epi32(x[4]);
                __m256i x_5 = _mm256_set1_epi32(x[5]);
                __m256i x_6 = _mm256_set1_epi32(x[6]);
                __m256i x_7 = _mm256_set1_epi32(x[7]);
                __m256i x_8 = _mm256_set1_epi32(x[8]);
                __m256i x_9 = _mm256_set1_epi32(x[9]);
                __m256i x_10 = _mm256_set1_epi32(x[10]);
                __m256i x_11 = _mm256_set1_epi32(x[11]);
                __m256i x_12;// = _mm256_set1_epi32(x[12]); /* useless */
                __m256i x_13;// = _mm256_set1_epi32(x[13]); /* useless */
                __m256i x_14 = _mm256_set1_epi32(x[14]);
                __m256i x_15 = _mm256_set1_epi32(x[15]);

                __m256i orig0 = x_0;
                __m256i orig1 = x_1;
                __m256i orig2 = x_2;
                __m256i orig3 = x_3;
                __m256i orig4 = x_4;
                __m256i orig5 = x_5;
                __m256i orig6 = x_6;
                __m256i orig7 = x_7;
                __m256i orig8 = x_8;
                __m256i orig9 = x_9;
                __m256i orig10 = x_10;
                __m256i orig11 = x_11;
                __m256i orig12;// = x_12; /* useless */
                __m256i orig13;// = x_13; /* useless */
                __m256i orig14 = x_14;
                __m256i orig15 = x_15;
                __m256i t_0;
                __m256i t_1;
                __m256i t_2;
                __m256i t_3;
                __m256i t_4;
                __m256i t_5;
                __m256i t_6;
                __m256i t_7;
                __m256i t_8;
                __m256i t_9;
                __m256i t_10;
                __m256i t_11;
                __m256i t_12;
                __m256i t_13;
                __m256i t_14;
                __m256i t_15;

                while (bytes >= 512) {
                        x_0 = orig0;
                        x_1 = orig1;
                        x_2 = orig2;
                        x_3 = orig3;
                        x_4 = orig4;
                        x_5 = orig5;
                        x_6 = orig6;
                        x_7 = orig7;
                        x_8 = orig8;
                        x_9 = orig9;
                        x_10 = orig10;
                        x_11 = orig11;
                        //x_12 = orig12; /* useless */
                        //x_13 = orig13; /* useless */
                        x_14 = orig14;
                        x_15 = orig15;

                        const __m256i addv12 = _mm256_set_epi64x(3, 2, 1, 0);
                        const __m256i addv13 = _mm256_set_epi64x(7, 6, 5, 4);
                        const __m256i permute = _mm256_set_epi32(7, 6, 3, 2, 5, 4, 1, 0);
                        __m256i t12, t13;
                        in12 = x[12];
                        in13 = x[13];
                        u64 in1213 = ((u64) in12) | (((u64) in13) << 32);
                        x_12 = _mm256_broadcastq_epi64(_mm_cvtsi64_si128(in1213));
                        x_13 = _mm256_broadcastq_epi64(_mm_cvtsi64_si128(in1213));

                        t12 = _mm256_add_epi64(addv12, x_12);
                        t13 = _mm256_add_epi64(addv13, x_13);

                        x_12 = _mm256_unpacklo_epi32(t12, t13);
                        x_13 = _mm256_unpackhi_epi32(t12, t13);

                        t12 = _mm256_unpacklo_epi32(x_12, x_13);
                        t13 = _mm256_unpackhi_epi32(x_12, x_13);

                        /* required because unpack* are intra-lane */
                        x_12 = _mm256_permutevar8x32_epi32(t12, permute);
                        x_13 = _mm256_permutevar8x32_epi32(t13, permute);

                        orig12 = x_12;
                        orig13 = x_13;

                        in1213 += 8;

                        x[12] = in1213 & 0xFFFFFFFF;
                        x[13] = (in1213 >> 32) &0xFFFFFFFF;

                        for (i = 0 ; i < ROUNDS ; i+=2) {
                                VEC8_ROUND( 0, 4, 8,12, 1, 5, 9,13, 2, 6,10,14, 3, 7,11,15);
                                VEC8_ROUND( 0, 5,10,15, 1, 6,11,12, 2, 7, 8,13, 3, 4, 9,14);
                        }

                        ONEOCTO(0,1,2,3,4,5,6,7);
                        m += 32;
                        out += 32;
                        ONEOCTO(8,9,10,11,12,13,14,15);
                        m -= 32;
                        out -= 32;

                        bytes -= 512;
                        out += 512;
                        m += 512;
                }
        }

        /* u4 */
        if (bytes >= 256) {
                }


        /* u1 */
        if (bytes >= 64) {
        }







        
        if (!bytes)
                return;
        for (;;) {
                salsa20_wordtobyte(output,x);
                x[12] = PLUSONE(x[12]);
                if (!x[12]) {
                        x[13] = PLUSONE(x[13]);
                        /* stopping at 2^70 bytes per nonce is user's responsibility */
                }
                if (bytes <= 64) {
                        for (i = 0; i < bytes; ++i)
                                out[i] = m[i] ^ output[i];
                        return;
                }
                for (i = 0; i < 64; ++i)
                        out[i] = m[i] ^ output[i];
                bytes -= 64;
                out += 64;
                m += 64;
        }
}

void
ECRYPT_decrypt_bytes(ECRYPT_ctx *x,
                     const u8 *c,
                     u8 *m,
                     u32 bytes)
{
        ECRYPT_encrypt_bytes(x,c,m,bytes);
}

void
ECRYPT_keystream_bytes(ECRYPT_ctx *x,
                       u8 *stream,
                       u32 bytes)
{
        u32 i;
        for (i = 0;i < bytes;++i)
                stream[i] = 0;
        ECRYPT_encrypt_bytes(x, stream, stream, bytes);
}
#endif
