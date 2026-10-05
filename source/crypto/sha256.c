/* SHA-256, FIPS 180-4 sections 4.1.2, 4.2.2, 5.1.1, 5.3.3 and 6.2.2.
 * Algorithm source: https://doi.org/10.6028/NIST.FIPS.180-4
 * Independent C translation; no external crypto implementation included. */
#include "sha256.h"

#if SIZE_MAX > UINT64_MAX
#error This implementation requires size_t to be at most 64 bits.
#endif

static const uint32_t round_constant[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static void wipe(void *memory, size_t length) {
    volatile uint8_t *p = (volatile uint8_t *)memory;
    while (length != 0) {
        *p++ = 0;
        length--;
    }
}

static uint32_t load32_be(const uint8_t p[4]) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
        | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void store32_be(uint8_t p[4], uint32_t value) {
    for (unsigned i = 0; i < 4; i++) {
        p[i] = (uint8_t)(value >> (24 - 8 * i));
    }
}

static uint32_t rotate_right(uint32_t value, unsigned count) {
    return (value >> count) | (value << (32 - count));
}

static void compress(sha256_context *ctx, const uint8_t block[64]) {
    uint32_t w[16];
    uint32_t a = ctx->state[0], b = ctx->state[1];
    uint32_t c = ctx->state[2], d = ctx->state[3];
    uint32_t e = ctx->state[4], f = ctx->state[5];
    uint32_t g = ctx->state[6], h = ctx->state[7];

    for (unsigned t = 0; t < 64; t++) {
        unsigned j = t & 15;
        if (t < 16) {
            w[j] = load32_be(block + 4 * t);
        } else {
            /* Same W[t] recurrence, retaining only its last 16 words. */
            uint32_t x = w[(t - 15) & 15];
            uint32_t y = w[(t - 2) & 15];
            uint32_t s0 = rotate_right(x, 7) ^ rotate_right(x, 18) ^ (x >> 3);
            uint32_t s1 = rotate_right(y, 17) ^ rotate_right(y, 19) ^ (y >> 10);
            w[j] = s1 + w[(t - 7) & 15] + s0 + w[j];
        }
        uint32_t sum0 = rotate_right(a, 2) ^ rotate_right(a, 13)
            ^ rotate_right(a, 22);
        uint32_t sum1 = rotate_right(e, 6) ^ rotate_right(e, 11)
            ^ rotate_right(e, 25);
        uint32_t choice = (e & f) ^ (~e & g);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t1 = h + sum1 + choice + round_constant[t] + w[j];
        uint32_t t2 = sum0 + majority;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b;
    ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f;
    ctx->state[6] += g; ctx->state[7] += h;
    wipe(w, sizeof(w));
}

int sha256_init(sha256_context *ctx) {
    if (ctx == NULL) {
        return 0;
    }
    wipe(ctx, sizeof(*ctx));
    ctx->state[0] = 0x6a09e667u;
    ctx->state[1] = 0xbb67ae85u;
    ctx->state[2] = 0x3c6ef372u;
    ctx->state[3] = 0xa54ff53au;
    ctx->state[4] = 0x510e527fu;
    ctx->state[5] = 0x9b05688cu;
    ctx->state[6] = 0x1f83d9abu;
    ctx->state[7] = 0x5be0cd19u;
    return 1;
}

int sha256_update(sha256_context *ctx, const uint8_t *data, size_t length) {
    if (ctx == NULL || (data == NULL && length != 0)) {
        return 0;
    }
    if (ctx->byte_count > SHA256_MAX_BYTES
        || (uint64_t)length > SHA256_MAX_BYTES - ctx->byte_count) {
        return 0;
    }
    size_t used = (size_t)(ctx->byte_count & 63);
    ctx->byte_count += (uint64_t)length;
    while (length != 0) {
        size_t count = sizeof(ctx->block) - used;
        if (count > length) {
            count = length;
        }
        for (size_t i = 0; i < count; i++) {
            ctx->block[used + i] = data[i];
        }
        used += count;
        data += count;
        length -= count;
        if (used == sizeof(ctx->block)) {
            compress(ctx, ctx->block);
            used = 0;
        }
    }
    return 1;
}

int sha256_final(sha256_context *ctx, uint8_t digest[SHA256_DIGEST_SIZE]) {
    if (ctx == NULL || digest == NULL || ctx->byte_count > SHA256_MAX_BYTES) {
        return 0;
    }
    uint64_t bit_count = ctx->byte_count * 8;
    size_t used = (size_t)(ctx->byte_count & 63);
    ctx->block[used++] = 0x80;
    if (used > 56) {
        while (used < sizeof(ctx->block)) {
            ctx->block[used++] = 0;
        }
        compress(ctx, ctx->block);
        used = 0;
    }
    while (used < 56) {
        ctx->block[used++] = 0;
    }
    for (unsigned i = 0; i < 8; i++) {
        ctx->block[56 + i] = (uint8_t)(bit_count >> (56 - 8 * i));
    }
    compress(ctx, ctx->block);
    for (unsigned i = 0; i < 8; i++) {
        store32_be(digest + 4 * i, ctx->state[i]);
    }
    wipe(ctx, sizeof(*ctx));
    ctx->byte_count = UINT64_MAX; /* Finished: initialize before reuse. */
    return 1;
}

int sha256(uint8_t digest[SHA256_DIGEST_SIZE], const uint8_t *data,
    size_t length) {
    sha256_context ctx;
    if (digest == NULL || (data == NULL && length != 0)) {
        return 0;
    }
    sha256_init(&ctx);
    if (!sha256_update(&ctx, data, length)) {
        wipe(&ctx, sizeof(ctx));
        return 0;
    }
    return sha256_final(&ctx, digest);
}
