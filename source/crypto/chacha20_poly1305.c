#include "chacha20_poly1305.h"
#if SIZE_MAX > UINT64_MAX
#error This implementation requires size_t to be at most 64 bits.
#endif
typedef struct {
    uint32_t r[5];
    uint32_t h[5];
    uint32_t s[4];
} poly1305_state;
static void wipe(void *memory, size_t length) {
    volatile uint8_t *p = (volatile uint8_t *)memory;
    while (length != 0) {
        *p++ = 0;
        length--;
    }
}
static uint32_t load32(const uint8_t p[4]) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
        | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void store32(uint8_t p[4], uint32_t value) {
    for (unsigned i = 0; i < 4; i++) {
        p[i] = (uint8_t)(value >> (8 * i));
    }
}
static void store64(uint8_t p[8], uint64_t value) {
    for (unsigned i = 0; i < 8; i++) {
        p[i] = (uint8_t)(value >> (8 * i));
    }
}
static uint32_t rotate_left(uint32_t value, unsigned count) {
    return (value << count) | (value >> (32 - count));
}
static void quarter_round(uint32_t x[16], unsigned a, unsigned b,
    unsigned c, unsigned d) {
    x[a] += x[b]; x[d] = rotate_left(x[d] ^ x[a], 16);
    x[c] += x[d]; x[b] = rotate_left(x[b] ^ x[c], 12);
    x[a] += x[b]; x[d] = rotate_left(x[d] ^ x[a], 8);
    x[c] += x[d]; x[b] = rotate_left(x[b] ^ x[c], 7);
}
static void chacha20_block(uint8_t out[64], const uint8_t key[32],
    const uint8_t nonce[12], uint32_t counter) {
    uint32_t initial[16];
    uint32_t x[16];
    initial[0] = UINT32_C(0x61707865);
    initial[1] = UINT32_C(0x3320646e);
    initial[2] = UINT32_C(0x79622d32);
    initial[3] = UINT32_C(0x6b206574);
    for (unsigned i = 0; i < 8; i++) {
        initial[4 + i] = load32(key + 4 * i);
    }
    initial[12] = counter;
    for (unsigned i = 0; i < 3; i++) {
        initial[13 + i] = load32(nonce + 4 * i);
    }
    for (unsigned i = 0; i < 16; i++) {
        x[i] = initial[i];
    }
    for (unsigned i = 0; i < 10; i++) {
        quarter_round(x, 0, 4, 8, 12);
        quarter_round(x, 1, 5, 9, 13);
        quarter_round(x, 2, 6, 10, 14);
        quarter_round(x, 3, 7, 11, 15);
        quarter_round(x, 0, 5, 10, 15);
        quarter_round(x, 1, 6, 11, 12);
        quarter_round(x, 2, 7, 8, 13);
        quarter_round(x, 3, 4, 9, 14);
    }
    for (unsigned i = 0; i < 16; i++) {
        store32(out + 4 * i, x[i] + initial[i]);
    }
    wipe(x, sizeof(x));
    wipe(initial, sizeof(initial));
}
static void chacha20_xor(uint8_t *out, const uint8_t *in, size_t length,
    const uint8_t key[32], const uint8_t nonce[12], uint32_t counter) {
    uint8_t block[64];
    while (length != 0) {
        size_t count = length < sizeof(block) ? length : sizeof(block);
        chacha20_block(block, key, nonce, counter);
        for (size_t i = 0; i < count; i++) {
            out[i] = in[i] ^ block[i];
        }
        length -= count;
        in += count;
        out += count;
        if (length != 0) {
            counter++;
        }
    }
    wipe(block, sizeof(block));
}
static void poly1305_init(poly1305_state *state, const uint8_t key[32]) {
    state->r[0] = load32(key) & UINT32_C(0x3ffffff);
    state->r[1] = (load32(key + 3) >> 2) & UINT32_C(0x3ffff03);
    state->r[2] = (load32(key + 6) >> 4) & UINT32_C(0x3ffc0ff);
    state->r[3] = (load32(key + 9) >> 6) & UINT32_C(0x3f03fff);
    state->r[4] = (load32(key + 12) >> 8) & UINT32_C(0x00fffff);
    for (unsigned i = 0; i < 5; i++) {
        state->h[i] = 0;
    }
    for (unsigned i = 0; i < 4; i++) {
        state->s[i] = load32(key + 16 + 4 * i);
    }
}
static void poly1305_block(poly1305_state *state, const uint8_t block[16],
    uint32_t high_bit) {
    uint32_t *h = state->h;
    const uint32_t *r = state->r;
    uint64_t product[5] = {0};
    h[0] += load32(block) & UINT32_C(0x3ffffff);
    h[1] += (load32(block + 3) >> 2) & UINT32_C(0x3ffffff);
    h[2] += (load32(block + 6) >> 4) & UINT32_C(0x3ffffff);
    h[3] += (load32(block + 9) >> 6) & UINT32_C(0x3ffffff);
    h[4] += (load32(block + 12) >> 8) | high_bit;
    for (unsigned i = 0; i < 5; i++) {
        for (unsigned j = 0; j <= i; j++) {
            product[i] += (uint64_t)h[j] * r[i - j];
        }
        for (unsigned j = i + 1; j < 5; j++) {
            product[i] += (uint64_t)h[j] * (5 * r[i + 5 - j]);
        }
    }
    for (unsigned i = 0; i < 4; i++) {
        product[i + 1] += product[i] >> 26;
        h[i] = (uint32_t)product[i] & UINT32_C(0x3ffffff);
    }
    h[4] = (uint32_t)product[4] & UINT32_C(0x3ffffff);
    h[0] += (uint32_t)(product[4] >> 26) * 5;
    h[1] += h[0] >> 26;
    h[0] &= UINT32_C(0x3ffffff);
    wipe(product, sizeof(product));
}
static void poly1305_padded(poly1305_state *state, const uint8_t *data,
    size_t length) {
    while (length >= 16) {
        poly1305_block(state, data, UINT32_C(1) << 24);
        data += 16;
        length -= 16;
    }
    if (length != 0) {
        uint8_t block[16] = {0};
        for (size_t i = 0; i < length; i++) {
            block[i] = data[i];
        }
        poly1305_block(state, block, UINT32_C(1) << 24);
        wipe(block, sizeof(block));
    }
}
static void poly1305_finish(poly1305_state *state, uint8_t tag[16]) {
    uint32_t *h = state->h;
    uint32_t reduced[5];
    uint32_t words[4];
    uint32_t carry;
    uint32_t mask;
    uint64_t sum = 0;
    for (unsigned i = 1; i < 4; i++) {
        h[i + 1] += h[i] >> 26;
        h[i] &= UINT32_C(0x3ffffff);
    }
    h[0] += (h[4] >> 26) * 5;
    h[4] &= UINT32_C(0x3ffffff);
    h[1] += h[0] >> 26;
    h[0] &= UINT32_C(0x3ffffff);
    carry = 5;
    for (unsigned i = 0; i < 5; i++) {
        reduced[i] = h[i] + carry;
        carry = reduced[i] >> 26;
        reduced[i] &= UINT32_C(0x3ffffff);
    }
    mask = UINT32_C(0) - carry;
    for (unsigned i = 0; i < 5; i++) {
        h[i] = (h[i] & ~mask) | (reduced[i] & mask);
    }
    words[0] = h[0] | (h[1] << 26);
    words[1] = (h[1] >> 6) | (h[2] << 20);
    words[2] = (h[2] >> 12) | (h[3] << 14);
    words[3] = (h[3] >> 18) | (h[4] << 8);
    for (unsigned i = 0; i < 4; i++) {
        sum = (uint64_t)words[i] + state->s[i] + (sum >> 32);
        store32(tag + 4 * i, (uint32_t)sum);
    }
    wipe(reduced, sizeof(reduced));
    wipe(words, sizeof(words));
    wipe(state, sizeof(*state));
}
static void aead_tag(uint8_t tag[16], const uint8_t *ciphertext,
    size_t length, const uint8_t *aad, size_t aad_length,
    const uint8_t key[32], const uint8_t nonce[12]) {
    uint8_t block[64];
    poly1305_state state;
    chacha20_block(block, key, nonce, 0);
    poly1305_init(&state, block);
    wipe(block, sizeof(block));
    poly1305_padded(&state, aad, aad_length);
    poly1305_padded(&state, ciphertext, length);
    store64(block, (uint64_t)aad_length);
    store64(block + 8, (uint64_t)length);
    poly1305_block(&state, block, UINT32_C(1) << 24);
    poly1305_finish(&state, tag);
    wipe(block, sizeof(block));
}
static int valid_inputs(const uint8_t *out, const uint8_t *in,
    size_t length, const uint8_t tag[16], const uint8_t *aad,
    size_t aad_length, const uint8_t key[32], const uint8_t nonce[12]) {
    if (key == NULL || nonce == NULL || tag == NULL) {
        return 0;
    }
    if (length != 0 && (in == NULL || out == NULL)) {
        return 0;
    }
    if (aad_length != 0 && aad == NULL) {
        return 0;
    }
    return length / 64 + (length % 64 != 0) <= UINT32_MAX;
}
int chacha20_poly1305_encrypt(uint8_t *ciphertext, uint8_t tag[16],
    const uint8_t *plaintext, size_t length,
    const uint8_t *aad, size_t aad_length,
    const uint8_t key[32], const uint8_t nonce[12]) {
    if (!valid_inputs(ciphertext, plaintext, length, tag, aad, aad_length,
        key, nonce)) {
        return 0;
    }
    chacha20_xor(ciphertext, plaintext, length, key, nonce, 1);
    aead_tag(tag, ciphertext, length, aad, aad_length, key, nonce);
    return 1;
}
int chacha20_poly1305_decrypt(uint8_t *plaintext,
    const uint8_t *ciphertext, size_t length, const uint8_t tag[16],
    const uint8_t *aad, size_t aad_length,
    const uint8_t key[32], const uint8_t nonce[12]) {
    uint8_t expected[16];
    uint32_t difference = 0;
    if (!valid_inputs(plaintext, ciphertext, length, tag, aad, aad_length,
        key, nonce)) {
        return 0;
    }
    aead_tag(expected, ciphertext, length, aad, aad_length, key, nonce);
    for (unsigned i = 0; i < 16; i++) {
        difference |= (uint32_t)(expected[i] ^ tag[i]);
    }
    wipe(expected, sizeof(expected));
    if (difference != 0) {
        return 0;
    }
    chacha20_xor(plaintext, ciphertext, length, key, nonce, 1);
    return 1;
}
