#ifndef ALTCHATS_SESSION_H
#define ALTCHATS_SESSION_H
#include "altchats_net.h"
#include "altchats_protocol.h"
typedef void (*SS_EVENT_FN)(void *, unsigned, uint32_t, const uint8_t *, int, const uint8_t *, int);
typedef struct {
    uint32_t id;
    uint8_t public_key[32], name[SS_NAME_MAX], name_length, name_pending;
} SS_MEMBER;
typedef struct {
    uint32_t peer, started;
    uint8_t tag[16], first[48];
    unsigned stage;
    SS_HANDSHAKE handshake;
    SS_CHANNEL channel;
} SS_DIRECT;
typedef struct {
    SS_SOCKET sock;
    SS_CHANNEL relay;
    uint8_t secret[32], relay_public[32];
    uint8_t name[SS_NAME_MAX], name_length, name_changed;
    uint8_t input[4 + SS_WIRE_MAX], output[SS_QUEUE_MAX];
    int received, needed, pending;
    uint32_t id, input_started, output_progress, joined;
    uint32_t ping_sequence, ping_started, ping_last;
    unsigned ping_state;
    SS_MEMBER members[SS_CLIENT_MAX];
    SS_DIRECT direct[SS_DM_MAX];
    SS_EVENT_FN event;
    void *context;
} SS_CLIENT;
int SS_RELAY_KEY(uint8_t relay_public[32], const char *value);
int SS_CONNECT_CLIENT(SS_CLIENT *client, const char *host, unsigned relay_port, const uint8_t relay_public[32], SS_EVENT_FN event, void *context);
void SS_END_CLIENT(SS_CLIENT *client);
int SS_CLIENT_IO(SS_CLIENT *client, int ready);
int SS_SEND_TEXT(SS_CLIENT *client, uint32_t peer, const uint8_t *name, int name_length, const uint8_t *text, int length);
int SS_SET_NAME(SS_CLIENT *client, const uint8_t *name, int length);
int SS_START_DM(SS_CLIENT *client, uint32_t peer);
int SS_ACCEPT_DM(SS_CLIENT *client, uint32_t peer);
int SS_CLOSE_DM(SS_CLIENT *client, uint32_t peer);
unsigned SS_DM_STATE(const SS_CLIENT *client, uint32_t peer);
int SS_HAS_MEMBER(const SS_CLIENT *client, uint32_t peer);
#endif
