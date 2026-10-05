#ifndef SOCSTREAM_NOISE_H
#define SOCSTREAM_NOISE_H
#include <stddef.h>
#include <stdint.h>
typedef struct { uint8_t key[32]; uint64_t nonce; } SS_CIPHER;
typedef struct { SS_CIPHER tx, rx; } SS_CHANNEL;
typedef struct {
    uint8_t ck[32], hash[32], ephemeral[32];
    SS_CIPHER cipher;
    unsigned stage;
} SS_HANDSHAKE;
void SS_WIPE(void *memory, size_t length);
int SS_X25519(uint8_t out[32], const uint8_t secret[32], const uint8_t public_key[32]);
int SS_PUBLIC_KEY(uint8_t out[32], const uint8_t secret[32]);
int SS_NOISE_START(SS_HANDSHAKE *state, uint8_t message[48], const uint8_t remote[32],
    const uint8_t ephemeral[32], const uint8_t *prologue, size_t length);
int SS_NOISE_RESPOND(SS_CHANNEL *channel, uint8_t response[48], const uint8_t message[48],
    const uint8_t secret[32], const uint8_t ephemeral[32], const uint8_t *prologue, size_t length);
int SS_NOISE_FINISH(SS_HANDSHAKE *state, SS_CHANNEL *channel, const uint8_t response[48]);
int SS_ENCRYPT(SS_CIPHER *cipher, uint8_t *out, const uint8_t *plain, size_t length);
int SS_DECRYPT(SS_CIPHER *cipher, uint8_t *out, const uint8_t *encrypted, size_t length);
#endif
