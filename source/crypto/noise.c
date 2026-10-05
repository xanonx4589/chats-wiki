#include "noise.h"
#include "sha256.h"
#include "chacha20_poly1305.h"
#include <string.h>
typedef uint32_t FIELD[16];
void SS_WIPE(void *memory, size_t length) {
    volatile uint8_t *p = memory;
    while (length--) *p++ = 0;
}
static void CARRY(FIELD out, uint64_t value[16]) {
    for (unsigned pass = 0; pass < 3; pass++) {
        for (unsigned i = 0; i < 15; i++) {
            value[i + 1] += value[i] >> 16;
            value[i] &= 65535;
        }
        value[0] += 19 * (value[15] >> 15);
        value[15] &= 32767;
    }
    for (unsigned i = 0; i < 16; i++) out[i] = (uint32_t)value[i];
}
static void ADD(FIELD out, const FIELD a, const FIELD b) {
    uint64_t value[16];
    for (unsigned i = 0; i < 16; i++) value[i] = (uint64_t)a[i] + b[i];
    CARRY(out, value);
    SS_WIPE(value, sizeof(value));
}
static void SUB(FIELD out, const FIELD a, const FIELD b) {
    uint64_t value[16];
    for (unsigned i = 0; i < 16; i++)
        value[i] = (uint64_t)a[i] + (i == 0 ? 131034U : i == 15 ? 65534U : 131070U) - b[i];
    CARRY(out, value);
    SS_WIPE(value, sizeof(value));
}
static void MUL(FIELD out, const FIELD a, const FIELD b) {
    uint64_t value[31] = {0};
    for (unsigned i = 0; i < 16; i++)
        for (unsigned j = 0; j < 16; j++) value[i + j] += (uint64_t)a[i] * b[j];
    for (unsigned i = 16; i < 31; i++) value[i - 16] += 38 * value[i];
    CARRY(out, value);
    SS_WIPE(value, sizeof(value));
}
static void SWAP(FIELD a, FIELD b, uint32_t bit) {
    uint32_t mask = UINT32_C(0) - bit;
    for (unsigned i = 0; i < 16; i++) {
        uint32_t change = mask & (a[i] ^ b[i]);
        a[i] ^= change;
        b[i] ^= change;
    }
}
static void INVERT(FIELD out, const FIELD input) {
    FIELD value = {1};
    for (int bit = 254; bit >= 0; bit--) {
        MUL(value, value, value);
        if (bit != 2 && bit != 4) MUL(value, value, input);
    }
    memcpy(out, value, sizeof(value));
    SS_WIPE(value, sizeof(value));
}
static void ENCODE(uint8_t out[32], const FIELD input) {
    FIELD reduced;
    uint32_t borrow = 0;
    for (unsigned i = 0; i < 16; i++) {
        uint32_t value = input[i] - (i == 0 ? 65517U : i == 15 ? 32767U : 65535U) - borrow;
        borrow = value >> 31;
        reduced[i] = value & (i == 15 ? 32767U : 65535U);
    }
    uint32_t mask = UINT32_C(0) - (1 - borrow);
    for (unsigned i = 0; i < 16; i++) {
        uint32_t value = (reduced[i] & mask) | (input[i] & ~mask);
        out[2 * i] = (uint8_t)value;
        out[2 * i + 1] = (uint8_t)(value >> 8);
    }
    SS_WIPE(reduced, sizeof(reduced));
}
int SS_X25519(uint8_t out[32], const uint8_t secret[32], const uint8_t public_key[32]) {
    uint8_t scalar[32];
    FIELD x1, x2 = {1}, z2 = {0}, x3, z3 = {1};
    FIELD a, aa, b, bb, e, c, d, da, cb, constant = {56129, 1};
    if (!out || !secret || !public_key) return 0;
    memcpy(scalar, secret, 32);
    scalar[0] &= 248;
    scalar[31] = (scalar[31] & 127) | 64;
    for (unsigned i = 0; i < 16; i++) x1[i] = public_key[2 * i] | ((uint32_t)public_key[2 * i + 1] << 8);
    x1[15] &= 32767;
    memcpy(x3, x1, sizeof(x1));
    uint32_t swap = 0;
    for (int bit = 254; bit >= 0; bit--) {
        uint32_t current = (scalar[bit / 8] >> (bit & 7)) & 1;
        swap ^= current;
        SWAP(x2, x3, swap);
        SWAP(z2, z3, swap);
        swap = current;
        ADD(a, x2, z2); MUL(aa, a, a);
        SUB(b, x2, z2); MUL(bb, b, b);
        SUB(e, aa, bb);
        ADD(c, x3, z3); SUB(d, x3, z3);
        MUL(da, d, a); MUL(cb, c, b);
        ADD(x3, da, cb); MUL(x3, x3, x3);
        SUB(z3, da, cb); MUL(z3, z3, z3); MUL(z3, z3, x1);
        MUL(x2, aa, bb);
        MUL(z2, e, constant); ADD(z2, z2, aa); MUL(z2, z2, e);
    }
    SWAP(x2, x3, swap); SWAP(z2, z3, swap);
    INVERT(z2, z2); MUL(x2, x2, z2); ENCODE(out, x2);
    unsigned nonzero = 0;
    for (unsigned i = 0; i < 32; i++) nonzero |= out[i];
    SS_WIPE(scalar, sizeof(scalar));
    SS_WIPE(x1, sizeof(x1)); SS_WIPE(x2, sizeof(x2)); SS_WIPE(z2, sizeof(z2));
    SS_WIPE(x3, sizeof(x3)); SS_WIPE(z3, sizeof(z3)); SS_WIPE(a, sizeof(a));
    SS_WIPE(aa, sizeof(aa)); SS_WIPE(b, sizeof(b)); SS_WIPE(bb, sizeof(bb));
    SS_WIPE(e, sizeof(e)); SS_WIPE(c, sizeof(c)); SS_WIPE(d, sizeof(d));
    SS_WIPE(da, sizeof(da)); SS_WIPE(cb, sizeof(cb));
    return nonzero != 0;
}
int SS_PUBLIC_KEY(uint8_t out[32], const uint8_t secret[32]) {
    static const uint8_t base[32] = {9};
    return SS_X25519(out, secret, base);
}
static int HASH_PAIR(uint8_t out[32], const uint8_t *a, size_t na, const uint8_t *b, size_t nb) {
    sha256_context hash;
    int ok = sha256_init(&hash) && sha256_update(&hash, a, na)
        && sha256_update(&hash, b, nb) && sha256_final(&hash, out);
    SS_WIPE(&hash, sizeof(hash));
    return ok;
}
static int HMAC(uint8_t out[32], const uint8_t key[32], const uint8_t *data, size_t length) {
    uint8_t pad[64] = {0}, inner[32];
    memcpy(pad, key, 32);
    for (unsigned i = 0; i < 64; i++) pad[i] ^= 0x36;
    int ok = HASH_PAIR(inner, pad, 64, data, length);
    for (unsigned i = 0; i < 64; i++) pad[i] ^= 0x36 ^ 0x5c;
    ok = ok && HASH_PAIR(out, pad, 64, inner, 32);
    SS_WIPE(pad, sizeof(pad)); SS_WIPE(inner, sizeof(inner));
    return ok;
}
static int HKDF(const uint8_t ck[32], const uint8_t *input, size_t length, uint8_t a[32], uint8_t b[32]) {
    uint8_t key[32], data[33] = {1};
    int ok = HMAC(key, ck, input, length) && HMAC(a, key, data, 1);
    if (ok) { memcpy(data, a, 32); data[32] = 2; ok = HMAC(b, key, data, 33); }
    SS_WIPE(key, sizeof(key)); SS_WIPE(data, sizeof(data));
    return ok;
}
static int MIX_HASH(SS_HANDSHAKE *state, const uint8_t *data, size_t length) {
    return HASH_PAIR(state->hash, state->hash, 32, data, length);
}
static int MIX_KEY(SS_HANDSHAKE *state, const uint8_t secret[32], const uint8_t remote[32]) {
    uint8_t dh[32], ck[32];
    int ok = SS_X25519(dh, secret, remote)
        && HKDF(state->ck, dh, 32, ck, state->cipher.key);
    if (ok) { memcpy(state->ck, ck, 32); state->cipher.nonce = 0; }
    SS_WIPE(dh, sizeof(dh)); SS_WIPE(ck, sizeof(ck));
    return ok;
}
static void NONCE(uint8_t out[12], uint64_t value) {
    memset(out, 0, 4);
    for (unsigned i = 0; i < 8; i++) out[4 + i] = (uint8_t)(value >> (8 * i));
}
static int EMPTY_TAG(SS_HANDSHAKE *state, uint8_t tag[16], int writing) {
    uint8_t nonce[12];
    NONCE(nonce, state->cipher.nonce);
    int ok = writing
        ? chacha20_poly1305_encrypt(NULL, tag, NULL, 0, state->hash, 32, state->cipher.key, nonce)
        : chacha20_poly1305_decrypt(NULL, NULL, 0, tag, state->hash, 32, state->cipher.key, nonce);
    if (ok) { state->cipher.nonce++; ok = MIX_HASH(state, tag, 16); }
    SS_WIPE(nonce, sizeof(nonce));
    return ok;
}
static int INITIALIZE(SS_HANDSHAKE *state, const uint8_t remote[32], const uint8_t *prologue, size_t length) {
    static const uint8_t name[] = "Noise_NK_25519_ChaChaPoly_SHA256";
    SS_WIPE(state, sizeof(*state));
    if (sizeof(name) - 1 <= 32) memcpy(state->hash, name, sizeof(name) - 1);
    else if (!sha256(state->hash, name, sizeof(name) - 1)) return 0;
    memcpy(state->ck, state->hash, 32);
    return MIX_HASH(state, prologue, length) && MIX_HASH(state, remote, 32);
}
static int SPLIT(SS_HANDSHAKE *state, SS_CHANNEL *channel, int initiator) {
    uint8_t first[32], second[32];
    SS_WIPE(channel, sizeof(*channel));
    int ok = HKDF(state->ck, NULL, 0, first, second);
    if (ok) {
        memcpy(channel->tx.key, initiator ? first : second, 32);
        memcpy(channel->rx.key, initiator ? second : first, 32);
    }
    SS_WIPE(first, sizeof(first)); SS_WIPE(second, sizeof(second));
    return ok;
}
int SS_NOISE_START(SS_HANDSHAKE *state, uint8_t message[48], const uint8_t remote[32],
    const uint8_t ephemeral[32], const uint8_t *prologue, size_t length) {
    if (!state || !message || !remote || !ephemeral || (!prologue && length)) return 0;
    int ok = INITIALIZE(state, remote, prologue, length);
    memcpy(state->ephemeral, ephemeral, 32);
    ok = ok && SS_PUBLIC_KEY(message, ephemeral) && MIX_HASH(state, message, 32)
        && MIX_KEY(state, ephemeral, remote) && EMPTY_TAG(state, message + 32, 1);
    if (ok) state->stage = 1;
    else { SS_WIPE(state, sizeof(*state)); SS_WIPE(message, 48); }
    return ok;
}
int SS_NOISE_RESPOND(SS_CHANNEL *channel, uint8_t response[48], const uint8_t message[48],
    const uint8_t secret[32], const uint8_t ephemeral[32], const uint8_t *prologue, size_t length) {
    SS_HANDSHAKE state;
    uint8_t public_key[32], tag[16];
    if (!channel || !response || !message || !secret || !ephemeral || (!prologue && length)) return 0;
    SS_WIPE(channel, sizeof(*channel));
    memcpy(tag, message + 32, 16);
    int ok = SS_PUBLIC_KEY(public_key, secret) && INITIALIZE(&state, public_key, prologue, length)
        && MIX_HASH(&state, message, 32) && MIX_KEY(&state, secret, message)
        && EMPTY_TAG(&state, tag, 0) && SS_PUBLIC_KEY(response, ephemeral)
        && MIX_HASH(&state, response, 32) && MIX_KEY(&state, ephemeral, message)
        && EMPTY_TAG(&state, response + 32, 1) && SPLIT(&state, channel, 0);
    if (!ok) { SS_WIPE(channel, sizeof(*channel)); SS_WIPE(response, 48); }
    SS_WIPE(&state, sizeof(state)); SS_WIPE(public_key, sizeof(public_key)); SS_WIPE(tag, sizeof(tag));
    return ok;
}
int SS_NOISE_FINISH(SS_HANDSHAKE *state, SS_CHANNEL *channel, const uint8_t response[48]) {
    uint8_t tag[16];
    if (!state || !channel || !response || state->stage != 1) return 0;
    memcpy(tag, response + 32, 16);
    int ok = MIX_HASH(state, response, 32) && MIX_KEY(state, state->ephemeral, response)
        && EMPTY_TAG(state, tag, 0) && SPLIT(state, channel, 1);
    if (!ok) SS_WIPE(channel, sizeof(*channel));
    SS_WIPE(state, sizeof(*state)); SS_WIPE(tag, sizeof(tag));
    return ok;
}
int SS_ENCRYPT(SS_CIPHER *cipher, uint8_t *out, const uint8_t *plain, size_t length) {
    uint8_t nonce[12];
    if (!cipher || !out || (!plain && length) || length > 65519 || cipher->nonce == UINT64_MAX) return 0;
    NONCE(nonce, cipher->nonce);
    int ok = chacha20_poly1305_encrypt(out, out + length, plain, length, NULL, 0, cipher->key, nonce);
    if (ok) cipher->nonce++;
    SS_WIPE(nonce, sizeof(nonce));
    return ok;
}
int SS_DECRYPT(SS_CIPHER *cipher, uint8_t *out, const uint8_t *encrypted, size_t length) {
    uint8_t nonce[12];
    if (!cipher || !out || !encrypted || length < 16 || length > 65535 || cipher->nonce == UINT64_MAX) return 0;
    NONCE(nonce, cipher->nonce);
    int ok = chacha20_poly1305_decrypt(out, encrypted, length - 16, encrypted + length - 16,
        NULL, 0, cipher->key, nonce);
    if (ok) cipher->nonce++;
    SS_WIPE(nonce, sizeof(nonce));
    return ok;
}
