#ifndef _POLY1305_H_
#define _POLY1305_H_

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>

#define POLY_BLOCK_SIZE_IN_BYTES	16
#define POLY_KEY_SIZE_IN_BYTES		32
#define POLY_TAG_SIZE_IN_BYTES		16

struct poly_ctx_s {
        uint64_t r[3];
        uint64_t h[3];
        uint64_t pad[2];

        uint8_t buff[POLY_BLOCK_SIZE_IN_BYTES];
        size_t leftover;
};

/*
 * prototypes
 */
extern void poly1305_init_gen(struct poly_ctx_s *ctx,
                              const uint8_t *key);
extern void poly1305_update_gen(struct poly_ctx_s *ctx,
                                const uint8_t *m,
                                size_t bytes,
                                bool final);
extern void poly1305_fin_gen(uint8_t *tag,
                             struct poly_ctx_s *ctx);

#endif	/* !_POLY1305_H_ */
