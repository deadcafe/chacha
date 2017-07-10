#include <sys/types.h>
#include <stdint.h>
#include <x86intrin.h>

typedef unsigned int uint128_t __attribute__((mode(TI)));


/* copy 0-31 bytes */
inline __attribute__((always_inline)) static void
copy31(uint8_t *dst,
       const uint8_t *src,
       size_t bytes)
{
	size_t offset = src - dst;

	if (bytes & 16) {
                _mm_store_si128((__m128i *) dst, _mm_loadu_si128((__128i *) (dst + offset)));
                dst += 16;
        }

	if (bytes &  8) {
                *(uint64_t *) dst = *(uint64_t *) (dst + offset);
                dst += 8;
        }

	if (bytes &  4) {
                *(uint32_t *) dst = *(uint32_t *) (dst + offset);
                dst += 4;
        }

	if (bytes &  2) {
                *(uint16_t *) dst = *(uint16_t *) (dst + offset);
                dst += 2;
        }

	if (bytes &  1) {
                *( uint8_t *) dst = *( uint8_t *) (dst + offset);
        }
}


enum poly1305_state_flags_e {
	poly1305_started       = 1,
	poly1305_final_shift8  = 4,
	poly1305_final_shift16 = 8,
	poly1305_final_r2_r    = 16, /* use [r^2,r] for the final block */
	poly1305_final_r_1     = 32, /* use [r,1] for the final block */
};

struct poly1305_state_s {
	union {
		uint64_t h[3];
		uint32_t hh[10];
	};                       /*  40 bytes  */

	uint32_t R[5];           /*  20 bytes  */
	uint32_t R2[5];          /*  20 bytes  */
	uint32_t R4[5];          /*  20 bytes  */

	uint64_t pad[2];         /*  16 bytes  */
	uint64_t flags;          /*   8 bytes  */
};   /* 124 bytes total */

/*
 *
 */
void
poly1305_init_sse(struct poly1305_state_s *st,
                  const uint8_t *key,
                  size_t bytes)
{
	uint32_t *R;
	uint128_t d[3], m0;
	uint64_t r0, r1, r2;
	uint32_t rp0, rp1, rp2, rp3, rp4;
	uint64_t rt0, rt1, rt2, st2,c;
	uint64_t t0, t1;

	if (!bytes)
                bytes = ~(size_t) 0;

	_mm_storeu_si128((__m128i *) &st->hh[0], _mm_setzero_si128());
	_mm_storeu_si128((__m128i *) &st->hh[4], _mm_setzero_si128());
	_mm_storeu_si128((__m128i *) &st->hh[8], _mm_setzero_si128());

	t0 = *(uint64_t *) (key + 0);
	t1 = *(uint64_t *) (key + 8);
	r0 = t0 & 0xffc0fffffff; t0 >>= 44; t0 |= t1 << 20;
	r1 = t0 & 0xfffffc0ffff; t1 >>= 24;
	r2 = t1 & 0x00ffffffc0f;

	R    = st->R;
	R[0] = (uint32_t) ( r0                      ) & 0x3ffffff;
	R[1] = (uint32_t) (( r0 >> 26) | ( r1 << 18)) & 0x3ffffff;
	R[2] = (uint32_t) (( r1 >>  8)              ) & 0x3ffffff;
	R[3] = (uint32_t) (( r1 >> 34) | ( r2 << 10)) & 0x3ffffff;
	R[4] = (uint32_t) (( r2 >> 16)              );

	st->pad[0] = *(uint64_t *) (key + 16);
	st->pad[1] = *(uint64_t *) (key + 24);

	rt0 = r0;
	rt1 = r1;
	rt2 = r2;

        for (unsigned loops = 2, R = st->R2, limit = 16;
             loops && bytes > limit;
             loops--, R = st->R4, limit = 95) {

                st2 = rt2 * (5 << 2);

                d[0] = ((uint128_t) rt0 * rt0) + ((uint128_t) (rt1 * 2) * st2);
                d[1] = ((uint128_t) rt2 * st2) + ((uint128_t) (rt0 * 2) * rt1);
                d[2] = ((uint128_t) rt1 * rt1) + ((uint128_t) (rt2 * 2) * rt0);

                              rt0 = (uint64_t) d[0] & 0xfffffffffff; c = (uint64_t) (d[0] >> 44);
                d[1] += c   ; rt1 = (uint64_t) d[1] & 0xfffffffffff; c = (uint64_t) (d[1] >> 44);
                d[2] += c   ; rt2 = (uint64_t) d[2] & 0x3ffffffffff; c = (uint64_t) (d[2] >> 42);

                rt0 += c * 5; c = (rt0 >> 44); rt0 = rt0 & 0xfffffffffff;
                rt1 += c    ; c = (rt1 >> 44); rt1 = rt1 & 0xfffffffffff;
                rt2 += c    ;

                R[0] = (uint32_t) ( rt0                     ) & 0x3ffffff;
                R[1] = (uint32_t) ((rt0 >> 26) | (rt1 << 18)) & 0x3ffffff;
                R[2] = (uint32_t) ((rt1 >> 8)               ) & 0x3ffffff;
                R[3] = (uint32_t) ((rt1 >> 34) | (rt2 << 10)) & 0x3ffffff;
                R[4] = (uint32_t) ((rt2 >> 16)              );
        }
	st->flags = 0;
}

void
poly1305_update_sse(struct poly1305_state_s *st,
                    const uint8_t *m,
                    size_t bytes)
{
	__attribute__((aligned(64))) __m128i HIBIT = _mm_shuffle_epi32(_mm_cvtsi32_si128(1 << 24),
                                                                       _MM_SHUFFLE(1, 0, 1, 0));
	const __m128i MMASK = _mm_shuffle_epi32(_mm_cvtsi32_si128((1 << 26) - 1),
                                                _MM_SHUFFLE(1, 0, 1, 0));
	const __m128i FIVE = _mm_shuffle_epi32(_mm_cvtsi32_si128(5),
                                               _MM_SHUFFLE(1, 0, 1, 0));

	__m128i H0, H1, H2, H3, H4;
	__m128i T0, T1, T2, T3, T4, T5, T6, T7, T8;
	__m128i M0, M1, M2, M3, M4;
	__m128i M5, M6, M7, M8, M9;
	__m128i C1, C2;
	__m128i R20, R21, R22, R23, R24, S21, S22, S23, S24;
	__m128i R40, R41, R42, R43, R44, S41, S42, S43, S44;

	if (st->flags & poly1305_final_shift8)
                HIBIT = _mm_srli_si128(HIBIT, 8);
	if (st->flags & poly1305_final_shift16)
                HIBIT = _mm_setzero_si128();

	if (!(st->flags & poly1305_started)) {
		/* H = [Mx,My] */
		T5 = _mm_unpacklo_epi64(_mm_loadl_epi64((__m128i *) (m + 0)),
                                        _mm_loadl_epi64((__m128i *) (m + 16)));
		T6 = _mm_unpacklo_epi64(_mm_loadl_epi64((__m128i *) (m + 8)),
                                        _mm_loadl_epi64((__m128i *) (m + 24)));
		H0 = _mm_and_si128(MMASK, T5);
		H1 = _mm_and_si128(MMASK, _mm_srli_epi64(T5, 26));
		T5 = _mm_or_si128(_mm_srli_epi64(T5, 52), _mm_slli_epi64(T6, 12));
		H2 = _mm_and_si128(MMASK, T5);
		H3 = _mm_and_si128(MMASK, _mm_srli_epi64(T5, 26));
		H4 = _mm_srli_epi64(T6, 40);
		H4 = _mm_or_si128(H4, HIBIT);
		m += 32;
		bytes -= 32;
		st->flags |= poly1305_started;
	} else {
		T0 = _mm_loadu_si128((__m128i *) &st->hh[0]);
		T1 = _mm_loadu_si128((__m128i *) &st->hh[4]);
		T2 = _mm_loadu_si128((__m128i *) &st->hh[8]);
		H0 = _mm_shuffle_epi32(T0, _MM_SHUFFLE(1,1,0,0));
		H1 = _mm_shuffle_epi32(T0, _MM_SHUFFLE(3,3,2,2));
		H2 = _mm_shuffle_epi32(T1, _MM_SHUFFLE(1,1,0,0));
		H3 = _mm_shuffle_epi32(T1, _MM_SHUFFLE(3,3,2,2));
		H4 = _mm_shuffle_epi32(T2, _MM_SHUFFLE(1,1,0,0));
	}

	if (st->flags & (poly1305_final_r2_r|poly1305_final_r_1)) {
		if (st->flags & poly1305_final_r2_r) {
			/* use [r^2, r] */
			T2 = _mm_loadu_si128((__m128i *)&st->R[0]);
			T3 = _mm_cvtsi32_si128(st->R[4]);
			T0 = _mm_loadu_si128((__m128i *)&st->R2[0]);
			T1 = _mm_cvtsi32_si128(st->R2[4]);
			T4 = _mm_unpacklo_epi32(T0, T2);
			T5 = _mm_unpackhi_epi32(T0, T2);
			R24 = _mm_unpacklo_epi64(T1, T3);
		} else {
			/* use [r^1, 1] */
			T0 = _mm_loadu_si128((__m128i *) &st->R[0]);
			T1 = _mm_cvtsi32_si128(st->R[4]);
			T2 = _mm_cvtsi32_si128(1);
			T4 = _mm_unpacklo_epi32(T0, T2);
			T5 = _mm_unpackhi_epi32(T0, T2);
			R24 = T1;
		}

		R20 = _mm_shuffle_epi32(T4, _MM_SHUFFLE(1,1,0,0));
		R21 = _mm_shuffle_epi32(T4, _MM_SHUFFLE(3,3,2,2));
		R22 = _mm_shuffle_epi32(T5, _MM_SHUFFLE(1,1,0,0));
		R23 = _mm_shuffle_epi32(T5, _MM_SHUFFLE(3,3,2,2));
	} else {
		/* use [r^2, r^2] */
		T0 = _mm_loadu_si128((__m128i *) &st->R2[0]);
		T1 = _mm_cvtsi32_si128(st->R2[4]);
		R20 = _mm_shuffle_epi32(T0, _MM_SHUFFLE(0,0,0,0));
		R21 = _mm_shuffle_epi32(T0, _MM_SHUFFLE(1,1,1,1));
		R22 = _mm_shuffle_epi32(T0, _MM_SHUFFLE(2,2,2,2));
		R23 = _mm_shuffle_epi32(T0, _MM_SHUFFLE(3,3,3,3));
		R24 = _mm_shuffle_epi32(T1, _MM_SHUFFLE(0,0,0,0));
	}
	S21 = _mm_mul_epu32(R21, FIVE);
	S22 = _mm_mul_epu32(R22, FIVE);
	S23 = _mm_mul_epu32(R23, FIVE);
	S24 = _mm_mul_epu32(R24, FIVE);

	if (bytes >= 64) {
		T0 = _mm_loadu_si128((__m128i *) &st->R4[0]);
		T1 = _mm_cvtsi32_si128(st->R4[4]);
		R40 = _mm_shuffle_epi32(T0, _MM_SHUFFLE(0,0,0,0));
		R41 = _mm_shuffle_epi32(T0, _MM_SHUFFLE(1,1,1,1));
		R42 = _mm_shuffle_epi32(T0, _MM_SHUFFLE(2,2,2,2));
		R43 = _mm_shuffle_epi32(T0, _MM_SHUFFLE(3,3,3,3));
		R44 = _mm_shuffle_epi32(T1, _MM_SHUFFLE(0,0,0,0));
		S41 = _mm_mul_epu32(R41, FIVE);
		S42 = _mm_mul_epu32(R42, FIVE);
		S43 = _mm_mul_epu32(R43, FIVE);
		S44 = _mm_mul_epu32(R44, FIVE);

		while (bytes >= 64) {
			__m128i v00,v01,v02,v03,v04;
			__m128i v10,v11,v12,v13,v14;
			__m128i v20,v21,v22,v23,v24;
			__m128i v30,v31,v32,v33,v34;
			__m128i v40,v41,v42,v43,v44;
			__m128i T14,T15;

			/* H *= [r^4,r^4], preload [Mx,My] */
			T15 = S42;
			T0  = H4; T0  = _mm_mul_epu32(T0, S41);
			v01 = H3; v01 = _mm_mul_epu32(v01, T15);
			T14 = S43;
			T1  = H4; T1  = _mm_mul_epu32(T1 , T15);
			v11 = H3; v11 = _mm_mul_epu32(v11, T14);
			T2  = H4; T2  = _mm_mul_epu32(T2 , T14); T0 = _mm_add_epi64(T0, v01);
			T15 = S44;
			v02 = H2; v02 = _mm_mul_epu32(v02, T14);
			T3  = H4; T3  = _mm_mul_epu32(T3 , T15); T1 = _mm_add_epi64(T1, v11);
			v03 = H1; v03 = _mm_mul_epu32(v03, T15);
			v12 = H2; v12 = _mm_mul_epu32(v12, T15); T0 = _mm_add_epi64(T0, v02);
			T14 = R40;
			v21 = H3; v21 = _mm_mul_epu32(v21, T15);
			v31 = H3; v31 = _mm_mul_epu32(v31, T14); T0 = _mm_add_epi64(T0, v03);
			T4  = H4; T4  = _mm_mul_epu32(T4 , T14); T1 = _mm_add_epi64(T1, v12);
			v04 = H0; v04 = _mm_mul_epu32(v04, T14); T2 = _mm_add_epi64(T2, v21);
			v13 = H1; v13 = _mm_mul_epu32(v13, T14); T3 = _mm_add_epi64(T3, v31);
			T15 = R41;
			v22 = H2; v22 = _mm_mul_epu32(v22, T14);
			v32 = H2; v32 = _mm_mul_epu32(v32, T15); T0 = _mm_add_epi64(T0, v04);
			v41 = H3; v41 = _mm_mul_epu32(v41, T15); T1 = _mm_add_epi64(T1, v13);
			v14 = H0; v14 = _mm_mul_epu32(v14, T15); T2 = _mm_add_epi64(T2, v22);
			T14 = R42;
			T5 = _mm_unpacklo_epi64(_mm_loadl_epi64((__m128i *) (m + 0)),
                                                _mm_loadl_epi64((__m128i *) (m + 16)));
			v23 = H1; v23 = _mm_mul_epu32(v23, T15); T3 = _mm_add_epi64(T3, v32);
			v33 = H1; v33 = _mm_mul_epu32(v33, T14); T4 = _mm_add_epi64(T4, v41);
			v42 = H2; v42 = _mm_mul_epu32(v42, T14); T1 = _mm_add_epi64(T1, v14);
			T15 = R43;
			T6 = _mm_unpacklo_epi64(_mm_loadl_epi64((__m128i *) (m + 8)),
                                                _mm_loadl_epi64((__m128i *)(m + 24)));
			v24 = H0; v24 = _mm_mul_epu32(v24, T14); T2 = _mm_add_epi64(T2, v23);
			v34 = H0; v34 = _mm_mul_epu32(v34, T15); T3 = _mm_add_epi64(T3, v33);
			M0 = _mm_and_si128(MMASK, T5);
			v43 = H1; v43 = _mm_mul_epu32(v43, T15); T4 = _mm_add_epi64(T4, v42);
			M1 = _mm_and_si128(MMASK, _mm_srli_epi64(T5, 26));
			v44 = H0; v44 = _mm_mul_epu32(v44, R44); T2 = _mm_add_epi64(T2, v24);
			T5 = _mm_or_si128(_mm_srli_epi64(T5, 52), _mm_slli_epi64(T6, 12));
                        T3 = _mm_add_epi64(T3, v34);
			M3 = _mm_and_si128(MMASK, _mm_srli_epi64(T6, 14));
                        T4 = _mm_add_epi64(T4, v43);
			M2 = _mm_and_si128(MMASK, T5);
                        T4 = _mm_add_epi64(T4, v44);
			M4 = _mm_or_si128(_mm_srli_epi64(T6, 40), HIBIT);

			/* H += [Mx',My'] */
			T5 = _mm_loadu_si128((__m128i *) (m + 32));
			T6 = _mm_loadu_si128((__m128i *) (m + 48));
			T7 = _mm_unpacklo_epi32(T5, T6);
			T8 = _mm_unpackhi_epi32(T5, T6);
			M5 = _mm_unpacklo_epi32(T7, _mm_setzero_si128());
			M6 = _mm_unpackhi_epi32(T7, _mm_setzero_si128());
			M7 = _mm_unpacklo_epi32(T8, _mm_setzero_si128());
			M8 = _mm_unpackhi_epi32(T8, _mm_setzero_si128());
			M6 = _mm_slli_epi64(M6, 6);
			M7 = _mm_slli_epi64(M7, 12);
			M8 = _mm_slli_epi64(M8, 18);
			T0 = _mm_add_epi64(T0, M5);
			T1 = _mm_add_epi64(T1, M6);
			T2 = _mm_add_epi64(T2, M7);
			T3 = _mm_add_epi64(T3, M8);
			T4 = _mm_add_epi64(T4, HIBIT);

			/* H += [Mx,My]*[r^2,r^2] */
			T15 = S22;
			v00 = M4; v00 = _mm_mul_epu32(v00, S21);
			v01 = M3; v01 = _mm_mul_epu32(v01, T15);
			T14 = S23;
			v10 = M4; v10 = _mm_mul_epu32(v10, T15);
			v11 = M3; v11 = _mm_mul_epu32(v11, T14); T0 = _mm_add_epi64(T0, v00);
			v20 = M4; v20 = _mm_mul_epu32(v20, T14); T0 = _mm_add_epi64(T0, v01);
			T15 = S24;
			v02 = M2; v02 = _mm_mul_epu32(v02, T14); T1 = _mm_add_epi64(T1, v10);
			v30 = M4; v30 = _mm_mul_epu32(v30, T15); T1 = _mm_add_epi64(T1, v11);
			v03 = M1; v03 = _mm_mul_epu32(v03, T15); T2 = _mm_add_epi64(T2, v20);
			v12 = M2; v12 = _mm_mul_epu32(v12, T15); T0 = _mm_add_epi64(T0, v02);
			T14 = R20;
			v21 = M3; v21 = _mm_mul_epu32(v21, T15); T3 = _mm_add_epi64(T3, v30);
			v31 = M3; v31 = _mm_mul_epu32(v31, T14); T0 = _mm_add_epi64(T0, v03);
			v40 = M4; v40 = _mm_mul_epu32(v40, T14); T1 = _mm_add_epi64(T1, v12);
			v04 = M0; v04 = _mm_mul_epu32(v04, T14); T2 = _mm_add_epi64(T2, v21);
			v13 = M1; v13 = _mm_mul_epu32(v13, T14); T3 = _mm_add_epi64(T3, v31);
			T15 = R21;
			v22 = M2; v22 = _mm_mul_epu32(v22, T14); T4 = _mm_add_epi64(T4, v40);
			v32 = M2; v32 = _mm_mul_epu32(v32, T15); T0 = _mm_add_epi64(T0, v04);
			v41 = M3; v41 = _mm_mul_epu32(v41, T15); T1 = _mm_add_epi64(T1, v13);
			v14 = M0; v14 = _mm_mul_epu32(v14, T15); T2 = _mm_add_epi64(T2, v22);
			T14 = R22;
			v23 = M1; v23 = _mm_mul_epu32(v23, T15); T3 = _mm_add_epi64(T3, v32);
			v33 = M1; v33 = _mm_mul_epu32(v33, T14); T4 = _mm_add_epi64(T4, v41);
			v42 = M2; v42 = _mm_mul_epu32(v42, T14); T1 = _mm_add_epi64(T1, v14);
			T15 = R23;
			v24 = M0; v24 = _mm_mul_epu32(v24, T14); T2 = _mm_add_epi64(T2, v23);
			v34 = M0; v34 = _mm_mul_epu32(v34, T15); T3 = _mm_add_epi64(T3, v33);
			v43 = M1; v43 = _mm_mul_epu32(v43, T15); T4 = _mm_add_epi64(T4, v42);
			v44 = M0; v44 = _mm_mul_epu32(v44, R24); T2 = _mm_add_epi64(T2, v24);
                        T3 = _mm_add_epi64(T3, v34);
                        T4 = _mm_add_epi64(T4, v43);
                        T4 = _mm_add_epi64(T4, v44);

			/* reduce */
			C1 = _mm_srli_epi64(T0, 26);
                        C2 = _mm_srli_epi64(T3, 26);
                        T0 = _mm_and_si128(T0, MMASK);
                        T3 = _mm_and_si128(T3, MMASK);
                        T1 = _mm_add_epi64(T1, C1);
                        T4 = _mm_add_epi64(T4, C2);

			C1 = _mm_srli_epi64(T1, 26);
                        C2 = _mm_srli_epi64(T4, 26);
                        T1 = _mm_and_si128(T1, MMASK);
                        T4 = _mm_and_si128(T4, MMASK);
                        T2 = _mm_add_epi64(T2, C1);
                        T0 = _mm_add_epi64(T0, _mm_mul_epu32(C2, FIVE));

			C1 = _mm_srli_epi64(T2, 26);
                        C2 = _mm_srli_epi64(T0, 26);
                        T2 = _mm_and_si128(T2, MMASK);
                        T0 = _mm_and_si128(T0, MMASK);
                        T3 = _mm_add_epi64(T3, C1);
                        T1 = _mm_add_epi64(T1, C2);

			C1 = _mm_srli_epi64(T3, 26);
                        T3 = _mm_and_si128(T3, MMASK);
                        T4 = _mm_add_epi64(T4, C1);

			/* Final: H = (H*[r^4,r^4] + [Mx,My]*[r^2,r^2] + [Mx',My']) */
			H0 = T0;
			H1 = T1;
			H2 = T2;
			H3 = T3;
			H4 = T4;

			m += 64;
			bytes -= 64;
		}
	}


	if (bytes >= 32) {
		__m128i v01,v02,v03,v04;
		__m128i v11,v12,v13,v14;
		__m128i v21,v22,v23,v24;
		__m128i v31,v32,v33,v34;
		__m128i v41,v42,v43,v44;
		__m128i T14,T15;

		/* H *= [r^2,r^2] */
		T15 = S22;
		T0  = H4; T0  = _mm_mul_epu32(T0, S21);
		v01 = H3; v01 = _mm_mul_epu32(v01, T15);
		T14 = S23;
		T1  = H4; T1  = _mm_mul_epu32(T1 , T15);
		v11 = H3; v11 = _mm_mul_epu32(v11, T14);
		T2  = H4; T2  = _mm_mul_epu32(T2 , T14); T0 = _mm_add_epi64(T0, v01);
		T15 = S24;
		v02 = H2; v02 = _mm_mul_epu32(v02, T14);
		T3  = H4; T3  = _mm_mul_epu32(T3 , T15); T1 = _mm_add_epi64(T1, v11);
		v03 = H1; v03 = _mm_mul_epu32(v03, T15);
		v12 = H2; v12 = _mm_mul_epu32(v12, T15); T0 = _mm_add_epi64(T0, v02);
		T14 = R20;
		v21 = H3; v21 = _mm_mul_epu32(v21, T15);
		v31 = H3; v31 = _mm_mul_epu32(v31, T14); T0 = _mm_add_epi64(T0, v03);
		T4  = H4; T4  = _mm_mul_epu32(T4 , T14); T1 = _mm_add_epi64(T1, v12);
		v04 = H0; v04 = _mm_mul_epu32(v04, T14); T2 = _mm_add_epi64(T2, v21);
		v13 = H1; v13 = _mm_mul_epu32(v13, T14); T3 = _mm_add_epi64(T3, v31);
		T15 = R21;
		v22 = H2; v22 = _mm_mul_epu32(v22, T14);
		v32 = H2; v32 = _mm_mul_epu32(v32, T15); T0 = _mm_add_epi64(T0, v04);
		v41 = H3; v41 = _mm_mul_epu32(v41, T15); T1 = _mm_add_epi64(T1, v13);
		v14 = H0; v14 = _mm_mul_epu32(v14, T15); T2 = _mm_add_epi64(T2, v22);
		T14 = R22;
		v23 = H1; v23 = _mm_mul_epu32(v23, T15); T3 = _mm_add_epi64(T3, v32);
		v33 = H1; v33 = _mm_mul_epu32(v33, T14); T4 = _mm_add_epi64(T4, v41);
		v42 = H2; v42 = _mm_mul_epu32(v42, T14); T1 = _mm_add_epi64(T1, v14);
		T15 = R23;
		v24 = H0; v24 = _mm_mul_epu32(v24, T14); T2 = _mm_add_epi64(T2, v23);
		v34 = H0; v34 = _mm_mul_epu32(v34, T15); T3 = _mm_add_epi64(T3, v33);
		v43 = H1; v43 = _mm_mul_epu32(v43, T15); T4 = _mm_add_epi64(T4, v42);
		v44 = H0; v44 = _mm_mul_epu32(v44, R24); T2 = _mm_add_epi64(T2, v24);
		                                         T3 = _mm_add_epi64(T3, v34);
		                                         T4 = _mm_add_epi64(T4, v43);
		                                         T4 = _mm_add_epi64(T4, v44);

		/* H += [Mx,My] */
		if (m) {
			T5 = _mm_loadu_si128((__m128i *)(m + 0));
			T6 = _mm_loadu_si128((__m128i *)(m + 16));
			T7 = _mm_unpacklo_epi32(T5, T6);
			T8 = _mm_unpackhi_epi32(T5, T6);
			M0 = _mm_unpacklo_epi32(T7, _mm_setzero_si128());
			M1 = _mm_unpackhi_epi32(T7, _mm_setzero_si128());
			M2 = _mm_unpacklo_epi32(T8, _mm_setzero_si128());
			M3 = _mm_unpackhi_epi32(T8, _mm_setzero_si128());
			M1 = _mm_slli_epi64(M1, 6);
			M2 = _mm_slli_epi64(M2, 12);
			M3 = _mm_slli_epi64(M3, 18);
			T0 = _mm_add_epi64(T0, M0);
			T1 = _mm_add_epi64(T1, M1);
			T2 = _mm_add_epi64(T2, M2);
			T3 = _mm_add_epi64(T3, M3);
			T4 = _mm_add_epi64(T4, HIBIT);
		}

		/* reduce */
		C1 = _mm_srli_epi64(T0, 26);
                C2 = _mm_srli_epi64(T3, 26);
                T0 = _mm_and_si128(T0, MMASK);
                T3 = _mm_and_si128(T3, MMASK);
                T1 = _mm_add_epi64(T1, C1);
                T4 = _mm_add_epi64(T4, C2);

		C1 = _mm_srli_epi64(T1, 26);
                C2 = _mm_srli_epi64(T4, 26);
                T1 = _mm_and_si128(T1, MMASK);
                T4 = _mm_and_si128(T4, MMASK);
                T2 = _mm_add_epi64(T2, C1);
                T0 = _mm_add_epi64(T0, _mm_mul_epu32(C2, FIVE));

		C1 = _mm_srli_epi64(T2, 26);
                C2 = _mm_srli_epi64(T0, 26);
                T2 = _mm_and_si128(T2, MMASK);
                T0 = _mm_and_si128(T0, MMASK);
                T3 = _mm_add_epi64(T3, C1);
                T1 = _mm_add_epi64(T1, C2);

		C1 = _mm_srli_epi64(T3, 26);
                T3 = _mm_and_si128(T3, MMASK);
                T4 = _mm_add_epi64(T4, C1);

		/* H = (H*[r^2,r^2] + [Mx,My]) */
		H0 = T0;
		H1 = T1;
		H2 = T2;
		H3 = T3;
		H4 = T4;
	}

	if (m) {
		T0 = _mm_shuffle_epi32(H0, _MM_SHUFFLE(0,0,2,0));
		T1 = _mm_shuffle_epi32(H1, _MM_SHUFFLE(0,0,2,0));
		T2 = _mm_shuffle_epi32(H2, _MM_SHUFFLE(0,0,2,0));
		T3 = _mm_shuffle_epi32(H3, _MM_SHUFFLE(0,0,2,0));
		T4 = _mm_shuffle_epi32(H4, _MM_SHUFFLE(0,0,2,0));
		T0 = _mm_unpacklo_epi64(T0, T1);
		T1 = _mm_unpacklo_epi64(T2, T3);
		_mm_storeu_si128((__m128i *) &st->hh[0], T0);
		_mm_storeu_si128((__m128i *) &st->hh[4], T1);
		_mm_storel_epi64((__m128i *) &st->hh[8], T4);
	} else {
		uint32_t t0, t1, t2, t3, t4, b;
		uint64_t h0, h1, h2, g0, g1, g2, c, nc;

		/* H = H[0]+H[1] */
		T0 = H0;
		T1 = H1;
		T2 = H2;
		T3 = H3;
		T4 = H4;

		T0 = _mm_add_epi64(T0, _mm_srli_si128(T0, 8));
		T1 = _mm_add_epi64(T1, _mm_srli_si128(T1, 8));
		T2 = _mm_add_epi64(T2, _mm_srli_si128(T2, 8));
		T3 = _mm_add_epi64(T3, _mm_srli_si128(T3, 8));
		T4 = _mm_add_epi64(T4, _mm_srli_si128(T4, 8));

		t0 = _mm_cvtsi128_si32(T0)    ; b = (t0 >> 26); t0 &= 0x3ffffff;
		t1 = _mm_cvtsi128_si32(T1) + b; b = (t1 >> 26); t1 &= 0x3ffffff;
		t2 = _mm_cvtsi128_si32(T2) + b; b = (t2 >> 26); t2 &= 0x3ffffff;
		t3 = _mm_cvtsi128_si32(T3) + b; b = (t3 >> 26); t3 &= 0x3ffffff;
		t4 = _mm_cvtsi128_si32(T4) + b;

		/* everything except t4 is in range, so this is all safe */
		h0 =  (((uint64_t) t0      ) | ((uint64_t) t1 << 26)                       ) & 0xfffffffffffull;
		h1 =  (((uint64_t) t1 >> 18) | ((uint64_t) t2 <<  8) | ((uint64_t) t3 << 34)) & 0xfffffffffffull;
		h2 =  (((uint64_t) t3 >> 10) | ((uint64_t) t4 << 16)                       );

		             c = (h2 >> 42); h2 &= 0x3ffffffffff;
		h0 += c * 5; c = (h0 >> 44); h0 &= 0xfffffffffff;
		h1 += c;	 c = (h1 >> 44); h1 &= 0xfffffffffff;
		h2 += c;     c = (h2 >> 42); h2 &= 0x3ffffffffff;
		h0 += c * 5; c = (h0 >> 44); h0 &= 0xfffffffffff;
		h1 += c;

		g0 = h0 + 5; c = (g0 >> 44); g0 &= 0xfffffffffff;
		g1 = h1 + c; c = (g1 >> 44); g1 &= 0xfffffffffff;
		g2 = h2 + c - ((uint64_t) 1 << 42);

		c = (g2 >> 63) - 1;
		nc = ~c;
		h0 = (h0 & nc) | (g0 & c);
		h1 = (h1 & nc) | (g1 & c);
		h2 = (h2 & nc) | (g2 & c);

		st->h[0] = h0;
		st->h[1] = h1;
		st->h[2] = h2;
	}
}

void
poly1305_fin_sse(uint8_t *tag,
                 struct poly1305_state_s *st,
                 const uint8_t *m,
                 size_t leftover)
{
	uint64_t h0, h1, h2;
	uint64_t t0, t1, c;

	if (leftover) {
		__attribute__((aligned(16))) uint8_t final[32] = {0};

		poly1305_block_copy31(final, m, leftover);
		if (leftover != 16)
                        final[leftover] = 1;
		st->flags |= (leftover >= 16) ? poly1305_final_shift8 : poly1305_final_shift16;
		poly1305_update_sse(st, final, 32);
	}

	if (st->flags & poly1305_started) {
		/* finalize, H *= [r^2,r], or H *= [r,1] */
		if (!leftover || (leftover > 16))
			st->flags |= poly1305_final_r2_r;
		else
			st->flags |= poly1305_final_r_1;
		FN(poly1305_blocks)(st, NULL, 32);
	}

	h0 = st->h[0];
	h1 = st->h[1];
	h2 = st->h[2];

	/* pad */
	h0 = ((h0      ) | (h1 << 44));
	h1 = ((h1 >> 20) | (h2 << 24));

	__asm__ __volatile__(
		"addq %2, %0 ;\n"
		"adcq %3, %1 ;\n"
		: "+r"(h0), "+r"(h1)
		: "r"(st->pad[0]), "r"(st->pad[1])
		: "flags", "cc"
	);

	*(uint64_t *) (mac + 0) = h0;
	*(uint64_t *) (mac + 8) = h1;
}

