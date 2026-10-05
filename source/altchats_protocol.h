#ifndef ALTCHATS_PROTOCOL_H
#define ALTCHATS_PROTOCOL_H
#include <stdint.h>
#include "crypto/noise.h"
#ifndef ALTCHATS_PORT
#define ALTCHATS_PORT 3333
#endif
#define SS_CLIENT_MAX 1023
#define SS_TEXT_MAX 1024
#define SS_NAME_MAX 63
#define SS_MESSAGE_MAX 8192
#define SS_PACKET_MAX 1152
#define SS_WIRE_MAX (SS_PACKET_MAX + 16)
#define SS_QUEUE_MAX 16384
#define SS_RELAY_QUEUE_MAX 65536
#define SS_DM_MAX 8
#define SS_HELLO_SIZE 33
#define SS_RELAY_PROLOGUE "ALTCHATS relay v1"
enum { SS_HELLO = 1, SS_SELF, SS_JOIN, SS_LEAVE, SS_LOBBY, SS_DM, SS_MISSING, SS_NAME, SS_PING, SS_PONG };
enum { SS_DM_START = 0, SS_DM_REPLY, SS_DM_DATA, SS_DM_CANCEL };
enum { SS_DM_FREE = 0, SS_DM_WAIT_REPLY, SS_DM_INVITED, SS_DM_WAIT_CONFIRM, SS_DM_READY, SS_DM_WAIT_ACK };
enum { SS_EVENT_SELF = 1, SS_EVENT_JOIN, SS_EVENT_LEAVE, SS_EVENT_LOBBY, SS_EVENT_DM, SS_EVENT_STATE, SS_EVENT_NOTICE, SS_EVENT_NAME };
static inline uint32_t SS_LOAD32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static inline void SS_STORE32(uint8_t *p, uint32_t value) {
    for (unsigned i = 0; i < 4; i++) p[i] = (uint8_t)(value >> (24 - 8 * i));
}
static inline void SS_TAG_HEX(char out[33], const uint8_t tag[16]) {
    static const char hex[] = "0123456789abcdef";
    for (unsigned i = 0; i < 16; i++) { out[2 * i] = hex[tag[i] >> 4]; out[2 * i + 1] = hex[tag[i] & 15]; }
    out[32] = 0;
}
static inline int SS_MATCH(const uint8_t *a, const uint8_t *b, unsigned count) {
    unsigned difference = 0;
    for (unsigned i = 0; i < count; i++) difference |= a[i] ^ b[i];
    return difference == 0;
}
#endif
