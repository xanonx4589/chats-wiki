#ifndef ZEROCOMMS_CHACHA20_POLY1305_H
#define ZEROCOMMS_CHACHA20_POLY1305_H
#include <stddef.h>
#include <stdint.h>
#define CHACHA20_POLY1305_KEY_SIZE 32
#define CHACHA20_POLY1305_NONCE_SIZE 12
#define CHACHA20_POLY1305_TAG_SIZE 16
int chacha20_poly1305_encrypt(uint8_t *ciphertext, uint8_t tag[16],
    const uint8_t *plaintext, size_t length,
    const uint8_t *aad, size_t aad_length,
    const uint8_t key[32], const uint8_t nonce[12]);
int chacha20_poly1305_decrypt(uint8_t *plaintext,
    const uint8_t *ciphertext, size_t length, const uint8_t tag[16],
    const uint8_t *aad, size_t aad_length,
    const uint8_t key[32], const uint8_t nonce[12]);
#endif
