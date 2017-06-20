
/*
 * copy from poly1305-donna
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#if defined(__SIZEOF_INT128__)
typedef unsigned __int128 uint128_t;
#else
typedef unsigned uint128_t __attribute__((mode(TI)));
#endif

#define MUL(out, x, y) out = ((uint128_t) x * y)
#define ADD(out, in) out += in
#define ADDLO(out, in) out += in
#define SHR(in, shift) (uint64_t) (in >> (shift))
#define LO(in) (uint64_t) (in)


#define POLY_BLOCK_SIZE_IN_BYTES	16
#define POLY_KEY_SIZE_IN_BYTES		32
#define POLY_TAG_SIZE_IN_BYTES		16

struct poly_ctx_s {
        uint8_t buff[POLY_BLOCK_SIZE_IN_BYTES];

        uint64_t r[3];
        uint64_t h[3];
        uint64_t pad[2];
        size_t leftover;
        bool final;
};


static void
poly1305_init_gen(struct poly_ctx_s *ctx,
                  const uint8_t *key)
{
        uint64_t t0, t1;

        t0 = *((const uint64_t *) &key[0]);
        t1 = *((const uint64_t *) &key[8]);

        ctx->r[0] = ( t0                    ) & 0xffc0fffffff;
	ctx->r[1] = ((t0 >> 44) | (t1 << 20)) & 0xfffffc0ffff;
	ctx->r[2] = ((t1 >> 24)             ) & 0x00ffffffc0f;

	ctx->h[0] = 0;
	ctx->h[1] = 0;
	ctx->h[2] = 0;

	ctx->pad[0] = *((const uint64_t *) &key[16]);
	ctx->pad[1] = *((const uint64_t *) &key[24]);

	ctx->leftover = 0;
	ctx->final = false;
}

static void
poly1305_update_gen(struct poly_ctx_s *ctx,
                    const uint8_t *m,
                    size_t bytes)
{
	const uint64_t hibit = (ctx->final) ? 0 : (UINT64_C(1) << 40); /* 1 << 128 */
	uint64_t r0, r1, r2;
	uint64_t s1, s2;
	uint64_t h0, h1, h2;
	uint64_t c;
	uint128_t d0,d1,d2,d;

	r0 = ctx->r[0];
	r1 = ctx->r[1];
	r2 = ctx->r[2];

	h0 = ctx->h[0];
	h1 = ctx->h[1];
	h2 = ctx->h[2];

	s1 = r1 * (5 << 2);
	s2 = r2 * (5 << 2);

	while (bytes >= POLY_BLOCK_SIZE_IN_BYTES) {
		uint64_t t0, t1;

		t0 = *((const uint64_t *) &m[0]);
		t1 = *((const uint64_t *) &m[8]);

		h0 += (( t0                    ) & 0xfffffffffff);
		h1 += (((t0 >> 44) | (t1 << 20)) & 0xfffffffffff);
		h2 += (((t1 >> 24)             ) & 0x3ffffffffff) | hibit;

		MUL(d0, h0, r0);
                MUL(d, h1, s2);
                ADD(d0, d);
                MUL(d, h2, s1);
                ADD(d0, d);

		MUL(d1, h0, r1);
                MUL(d, h1, r0);
                ADD(d1, d);
                MUL(d, h2, s2);
                ADD(d1, d);

		MUL(d2, h0, r2);
                MUL(d, h1, r1);
                ADD(d2, d);
                MUL(d, h2, r0);
                ADD(d2, d);

		              c = SHR(d0, 44); h0 = LO(d0) & 0xfffffffffff;
		ADDLO(d1, c); c = SHR(d1, 44); h1 = LO(d1) & 0xfffffffffff;
		ADDLO(d2, c); c = SHR(d2, 42); h2 = LO(d2) & 0x3ffffffffff;
		h0  += c * 5; c = (h0 >> 44);  h0 =    h0  & 0xfffffffffff;
		h1  += c;

		m += POLY_BLOCK_SIZE_IN_BYTES;
		bytes -= POLY_BLOCK_SIZE_IN_BYTES;
	}

	ctx->h[0] = h0;
	ctx->h[1] = h1;
	ctx->h[2] = h2;

}

static void
poly1305_fin_gen(uint8_t *tag,
                 struct poly_ctx_s *ctx)
{
	uint64_t h0, h1, h2, c;
	uint64_t g0, g1, g2;
	uint64_t t0, t1;

	if (ctx->leftover) {
		size_t i = ctx->leftover;

		ctx->buff[i] = 1;
		for (i = i + 1; i < POLY_BLOCK_SIZE_IN_BYTES; i++)
			ctx->buff[i] = 0;
		ctx->final = true;
		poly1305_update_gen(ctx, ctx->buff, POLY_BLOCK_SIZE_IN_BYTES);
	}

	h0 = ctx->h[0];
	h1 = ctx->h[1];
	h2 = ctx->h[2];

	             c = (h1 >> 44); h1 &= 0xfffffffffff;
	h2 += c;     c = (h2 >> 42); h2 &= 0x3ffffffffff;
	h0 += c * 5; c = (h0 >> 44); h0 &= 0xfffffffffff;
	h1 += c;     c = (h1 >> 44); h1 &= 0xfffffffffff;
	h2 += c;     c = (h2 >> 42); h2 &= 0x3ffffffffff;
	h0 += c * 5; c = (h0 >> 44); h0 &= 0xfffffffffff;
	h1 += c;

	g0 = h0 + 5; c = (g0 >> 44); g0 &= 0xfffffffffff;
	g1 = h1 + c; c = (g1 >> 44); g1 &= 0xfffffffffff;
	g2 = h2 + c - (UINT64_C(1) << 42);

	c = (g2 >> ((sizeof(uint64_t) * 8) - 1)) - 1;
	g0 &= c;
	g1 &= c;
	g2 &= c;
	c = ~c;
	h0 = (h0 & c) | g0;
	h1 = (h1 & c) | g1;
	h2 = (h2 & c) | g2;

	t0 = ctx->pad[0];
	t1 = ctx->pad[1];

	h0 += (( t0                    ) & 0xfffffffffff)    ; c = (h0 >> 44); h0 &= 0xfffffffffff;
	h1 += (((t0 >> 44) | (t1 << 20)) & 0xfffffffffff) + c; c = (h1 >> 44); h1 &= 0xfffffffffff;
	h2 += (((t1 >> 24)             ) & 0x3ffffffffff) + c;                 h2 &= 0x3ffffffffff;

	h0 = ((h0      ) | (h1 << 44));
	h1 = ((h1 >> 20) | (h2 << 24));

        *((uint64_t *) &tag[0]) = h0;
        *((uint64_t *) &tag[8]) = h0;

	ctx->h[0] = 0;
	ctx->h[1] = 0;
	ctx->h[2] = 0;
	ctx->r[0] = 0;
	ctx->r[1] = 0;
	ctx->r[2] = 0;
	ctx->pad[0] = 0;
	ctx->pad[1] = 0;
}



