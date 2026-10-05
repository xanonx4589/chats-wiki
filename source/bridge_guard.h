#ifndef BRIDGE_GUARD_H
#define BRIDGE_GUARD_H
#include "altchats_net.h"
#include <stdint.h>
#include <string.h>
#define BG_HEX_SIZE 64
#define BG_TOKEN_MARKER "{{BRIDGE_TOKEN}}"
#define BG_NONCE_MARKER "{{BRIDGE_NONCE}}"
#ifndef BG_PERMIT_MS
#define BG_PERMIT_MS 10000UL
#endif
typedef struct {
    char token[BG_HEX_SIZE + 1], permit[BG_HEX_SIZE + 1];
    uint32_t started, length;
    int pending;
} BRIDGE_GUARD;
static inline void BG_WIPE(void *memory, size_t length) {
    volatile unsigned char *p = memory;
    while (length--) *p++ = 0;
}
static inline int BG_RANDOM_BYTES(unsigned char *out, size_t length) { return SS_RANDOM(out, length); }
static inline int BG_RANDOM_HEX(char out[BG_HEX_SIZE + 1]) {
    static const char digits[] = "0123456789abcdef";
    unsigned char bytes[BG_HEX_SIZE / 2] = {0};
    BG_WIPE(out, BG_HEX_SIZE + 1);
    int ok = BG_RANDOM_BYTES(bytes, sizeof(bytes));
    if (ok) {
        for (size_t i = 0; i < sizeof(bytes); i++) {
            out[2 * i] = digits[bytes[i] >> 4];
            out[2 * i + 1] = digits[bytes[i] & 15];
        }
    }
    BG_WIPE(bytes, sizeof(bytes));
    return ok;
}
static inline int BG_MATCH(const char expected[BG_HEX_SIZE + 1], const char *value) {
    if (!value || strlen(value) != BG_HEX_SIZE || !expected[0]) return 0;
    unsigned difference = 0;
    for (unsigned i = 0; i < BG_HEX_SIZE; i++)
        difference |= (unsigned char)expected[i] ^ (unsigned char)value[i];
    return difference == 0;
}
static inline int BG_INIT(BRIDGE_GUARD *guard) {
    BG_WIPE(guard, sizeof(*guard));
    return BG_RANDOM_HEX(guard->token);
}
static inline void BG_CANCEL(BRIDGE_GUARD *guard) {
    BG_WIPE(guard->permit, sizeof(guard->permit));
    guard->pending = 0;
    guard->started = guard->length = 0;
}
static inline void BG_EXPIRE(BRIDGE_GUARD *guard, uint32_t now) {
    if (guard->pending && (uint32_t)(now - guard->started) >= BG_PERMIT_MS) BG_CANCEL(guard);
}
static inline int BG_ISSUE(BRIDGE_GUARD *guard, uint32_t length, uint32_t now) {
    BG_EXPIRE(guard, now);
    if (guard->pending) return -1;
    if (!length || !BG_RANDOM_HEX(guard->permit)) return 0;
    guard->length = length;
    guard->started = now;
    guard->pending = 1;
    return 1;
}
static inline int BG_TAKE(BRIDGE_GUARD *guard, const char *permit, uint32_t length, uint32_t now) {
    BG_EXPIRE(guard, now);
    if (!guard->pending || guard->length != length || !BG_MATCH(guard->permit, permit)) return 0;
    BG_CANCEL(guard);
    return 1;
}
static inline int BG_RENDER(char *out, size_t capacity, const char *source, size_t length,
    const char token[BG_HEX_SIZE + 1], const char nonce[BG_HEX_SIZE + 1]) {
    size_t used = 0, offset = 0;
    unsigned tokens = 0, nonces = 0;
    while (offset < length) {
        const char *replacement = NULL;
        size_t marker = 0;
        if (length - offset >= sizeof(BG_TOKEN_MARKER) - 1
            && !memcmp(source + offset, BG_TOKEN_MARKER, sizeof(BG_TOKEN_MARKER) - 1)) {
            replacement = token;
            marker = sizeof(BG_TOKEN_MARKER) - 1;
            tokens++;
        } else if (length - offset >= sizeof(BG_NONCE_MARKER) - 1
            && !memcmp(source + offset, BG_NONCE_MARKER, sizeof(BG_NONCE_MARKER) - 1)) {
            replacement = nonce;
            marker = sizeof(BG_NONCE_MARKER) - 1;
            nonces++;
        }
        size_t count = replacement ? BG_HEX_SIZE : 1;
        if (count > capacity - used) return -1;
        memcpy(out + used, replacement ? replacement : source + offset, count);
        used += count;
        offset += replacement ? marker : 1;
    }
    return tokens == 1 && nonces == 2 ? (int)used : -1;
}
#endif

