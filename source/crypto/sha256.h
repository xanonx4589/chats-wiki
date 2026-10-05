#ifndef ZEROCOMMS_SHA256_H
#define ZEROCOMMS_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_DIGEST_SIZE 32
#define SHA256_BLOCK_SIZE 64
#define SHA256_MAX_BYTES (UINT64_MAX / 8)

typedef struct {
    uint32_t state[8];
    uint64_t byte_count;
    uint8_t block[SHA256_BLOCK_SIZE];
} sha256_context;

/* All calls return 1 on success, 0 on invalid arguments/length/state.
 * Initialize before updating; final clears the context and ends that hash.
 * Data may be NULL only when length is zero. Digest needs 32 writable bytes.
 * Context storage must not overlap data or digest. See sha256_notes.md. */
int sha256_init(sha256_context *ctx);
int sha256_update(sha256_context *ctx, const uint8_t *data, size_t length);
int sha256_final(sha256_context *ctx, uint8_t digest[SHA256_DIGEST_SIZE]);
int sha256(uint8_t digest[SHA256_DIGEST_SIZE], const uint8_t *data,
    size_t length);

#endif
