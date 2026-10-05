#include "altchats_session.h"
#include <stdio.h>
#ifndef SS_CONNECT_MS
#define SS_CONNECT_MS 10000UL
#endif
#ifndef SS_IO_MS
#define SS_IO_MS 30000UL
#endif
#ifndef SS_INVITE_MS
#define SS_INVITE_MS 120000UL
#endif
#ifndef SS_PING_INTERVAL_MS
#define SS_PING_INTERVAL_MS 15000UL
#endif
#ifndef SS_PING_TIMEOUT_MS
#define SS_PING_TIMEOUT_MS 60000UL
#endif
static void EVENT(SS_CLIENT *client, unsigned type, uint32_t peer, const uint8_t *name, int n, const uint8_t *text, int length) {
    if (client->event) client->event(client->context, type, peer, name, n, text, length);
}
static void STATE(SS_CLIENT *client, SS_DIRECT *dm) {
    uint8_t value = (uint8_t)('0' + dm->stage);
    char tag[33]; SS_TAG_HEX(tag, dm->tag);
    EVENT(client, SS_EVENT_STATE, dm->peer, (const uint8_t *)tag, 32, &value, 1);
}
static SS_MEMBER *MEMBER(SS_CLIENT *client, uint32_t peer) {
    for (unsigned i = 0; i < SS_CLIENT_MAX; i++) if (client->members[i].id == peer && peer) return &client->members[i];
    return NULL;
}
int SS_HAS_MEMBER(const SS_CLIENT *client, uint32_t peer) {
    for (unsigned i = 0; i < SS_CLIENT_MAX; i++) if (client->members[i].id == peer && peer) return 1;
    return 0;
}
static SS_DIRECT *DIRECT(SS_CLIENT *client, uint32_t peer) {
    for (unsigned i = 0; i < SS_DM_MAX; i++) if (client->direct[i].stage && client->direct[i].peer == peer) return &client->direct[i];
    return NULL;
}
unsigned SS_DM_STATE(const SS_CLIENT *client, uint32_t peer) {
    for (unsigned i = 0; i < SS_DM_MAX; i++) if (client->direct[i].stage && client->direct[i].peer == peer) return client->direct[i].stage;
    return SS_DM_FREE;
}
static int QUEUE(SS_CLIENT *client, const uint8_t *packet, int length) {
    if (client->sock == SS_INVALID || length <= 0 || length > SS_PACKET_MAX || length + 20 > SS_QUEUE_MAX - client->pending) return 0;
    uint8_t *out = client->output + client->pending;
    SS_STORE32(out, (uint32_t)length + 16);
    if (!SS_ENCRYPT(&client->relay.tx, out + 4, packet, (size_t)length)) return 0;
    if (!client->pending) client->output_progress = SS_TICKS();
    client->pending += length + 20;
    return 1;
}
static int HEARTBEAT(SS_CLIENT *client, uint32_t now) {
    if (!client->id) return 1;
    if (!client->ping_state) {
        if ((uint32_t)(now - client->ping_last) < SS_PING_INTERVAL_MS) return 1;
        if (client->ping_sequence == UINT32_MAX) return 0;
        client->ping_sequence++; client->ping_started = now; client->ping_state = 1;
    }
    if ((uint32_t)(now - client->ping_started) >= SS_PING_TIMEOUT_MS) return 0;
    if (client->ping_state == 1) {
        uint8_t packet[5] = {SS_PING}; SS_STORE32(packet + 1, client->ping_sequence);
        if (QUEUE(client, packet, 5)) client->ping_state = 2;
    }
    return 1;
}
int SS_SET_NAME(SS_CLIENT *client, const uint8_t *name, int length) {
    if (client->sock == SS_INVALID || length < 0 || length > SS_NAME_MAX || (!name && length)
        || (length && (memchr(name, '\r', (size_t)length) || memchr(name, '\n', (size_t)length)))) return 0;
    if (length == client->name_length && (!length || !memcmp(client->name, name, (size_t)length))) return 1;
    SS_WIPE(client->name, sizeof(client->name));
    if (length) memcpy(client->name, name, (size_t)length);
    client->name_length = (uint8_t)length; client->name_changed = 1;
    return 1;
}
static int NAME_PACKET(SS_CLIENT *client, uint32_t target) {
    uint8_t packet[6 + SS_NAME_MAX] = {SS_NAME};
    SS_STORE32(packet + 1, target); packet[5] = client->name_length;
    memcpy(packet + 6, client->name, client->name_length);
    int ok = QUEUE(client, packet, 6 + client->name_length);
    SS_WIPE(packet, sizeof(packet)); return ok;
}
static void SEND_NAMES(SS_CLIENT *client) {
    if (!client->id) return;
    if (client->name_changed) {
        if (!NAME_PACKET(client, 0)) return;
        client->name_changed = 0;
    }
    for (unsigned i = 0; i < SS_CLIENT_MAX; i++) if (client->members[i].id && client->members[i].name_pending) {
        if (!NAME_PACKET(client, client->members[i].id)) return;
        client->members[i].name_pending = 0;
    }
}
static void SAVE_NAME(SS_CLIENT *client, uint32_t peer, const uint8_t *name, int length) {
    SS_MEMBER *member = MEMBER(client, peer);
    if (!member) return;
    SS_WIPE(member->name, sizeof(member->name));
    if (length) memcpy(member->name, name, (size_t)length);
    member->name_length = (uint8_t)length;
    EVENT(client, SS_EVENT_NAME, peer, name, length, NULL, 0);
}
static int DM_PACKET(SS_CLIENT *client, uint32_t peer, const uint8_t tag[16], unsigned type, const uint8_t *data, int length) {
    uint8_t packet[SS_PACKET_MAX];
    if (length < 0 || length > SS_PACKET_MAX - 22) return 0;
    packet[0] = SS_DM; SS_STORE32(packet + 1, peer);
    memcpy(packet + 5, tag, 16); packet[21] = (uint8_t)type;
    if (length) memcpy(packet + 22, data, (size_t)length);
    int ok = QUEUE(client, packet, length + 22);
    SS_WIPE(packet, sizeof(packet));
    return ok;
}
static void FORGET(SS_CLIENT *client, SS_DIRECT *dm) {
    uint32_t peer = dm->peer;
    char tag[33]; SS_TAG_HEX(tag, dm->tag);
    SS_WIPE(dm, sizeof(*dm));
    EVENT(client, SS_EVENT_STATE, peer, (const uint8_t *)tag, 32, (const uint8_t *)"0", 1);
}
static void PROLOGUE(uint8_t out[71], const SS_CLIENT *client, uint32_t initiator, uint32_t responder, const uint8_t tag[16]) {
    memcpy(out, "ALTCHATS DM v1", 15);
    memcpy(out + 15, client->relay_public, 32);
    SS_STORE32(out + 47, initiator); SS_STORE32(out + 51, responder);
    memcpy(out + 55, tag, 16);
}
static int CONFIRM(SS_CLIENT *client, SS_DIRECT *dm) {
    uint8_t plain = 0, encrypted[17];
    int ok = SS_ENCRYPT(&dm->channel.tx, encrypted, &plain, 1)
        && DM_PACKET(client, dm->peer, dm->tag, SS_DM_DATA, encrypted, 17);
    SS_WIPE(encrypted, sizeof(encrypted));
    return ok;
}
int SS_START_DM(SS_CLIENT *client, uint32_t peer) {
    SS_MEMBER *member = MEMBER(client, peer);
    uint8_t ephemeral[32], first[48], prologue[71] = {0};
    if (!client->id || !member || peer == client->id || DIRECT(client, peer)
        || SS_QUEUE_MAX - client->pending < 90) return 0;
    SS_DIRECT *dm = NULL;
    for (unsigned i = 0; i < SS_DM_MAX; i++) if (!client->direct[i].stage) { dm = &client->direct[i]; break; }
    if (!dm) return 0;
    dm->peer = peer; dm->started = SS_TICKS();
    int ok = SS_RANDOM(dm->tag, 16) && SS_RANDOM(ephemeral, 32);
    PROLOGUE(prologue, client, client->id, peer, dm->tag);
    ok = ok && SS_NOISE_START(&dm->handshake, first, member->public_key, ephemeral, prologue, sizeof(prologue))
        && DM_PACKET(client, peer, dm->tag, SS_DM_START, first, 48);
    if (ok) { dm->stage = SS_DM_WAIT_REPLY; STATE(client, dm); }
    else SS_WIPE(dm, sizeof(*dm));
    SS_WIPE(ephemeral, sizeof(ephemeral)); SS_WIPE(first, sizeof(first)); SS_WIPE(prologue, sizeof(prologue));
    return ok;
}
int SS_ACCEPT_DM(SS_CLIENT *client, uint32_t peer) {
    SS_DIRECT *dm = DIRECT(client, peer);
    uint8_t ephemeral[32], response[48], prologue[71] = {0};
    if (!dm || dm->stage != SS_DM_INVITED || SS_QUEUE_MAX - client->pending < 90) return 0;
    PROLOGUE(prologue, client, peer, client->id, dm->tag);
    int ok = SS_RANDOM(ephemeral, 32) && SS_NOISE_RESPOND(&dm->channel, response, dm->first,
        client->secret, ephemeral, prologue, sizeof(prologue)) && DM_PACKET(client, peer, dm->tag, SS_DM_REPLY, response, 48);
    if (ok) {
        SS_WIPE(dm->first, sizeof(dm->first));
        dm->stage = SS_DM_WAIT_CONFIRM; dm->started = SS_TICKS(); STATE(client, dm);
    } else { DM_PACKET(client, peer, dm->tag, SS_DM_CANCEL, NULL, 0); FORGET(client, dm); }
    SS_WIPE(ephemeral, sizeof(ephemeral)); SS_WIPE(response, sizeof(response)); SS_WIPE(prologue, sizeof(prologue));
    return ok;
}
int SS_CLOSE_DM(SS_CLIENT *client, uint32_t peer) {
    SS_DIRECT *dm = DIRECT(client, peer);
    if (!dm) return 0;
    int ok = DM_PACKET(client, peer, dm->tag, SS_DM_CANCEL, NULL, 0);
    FORGET(client, dm);
    return ok;
}
static int DIRECT_MESSAGE(SS_CLIENT *client, const uint8_t *packet, int length) {
    if (length < 22) return 0;
    uint32_t peer = SS_LOAD32(packet + 1);
    const uint8_t *tag = packet + 5, *data = packet + 22;
    unsigned kind = packet[21];
    length -= 22;
    if (!MEMBER(client, peer) || peer == client->id || kind > SS_DM_CANCEL) return 0;
    SS_DIRECT *dm = DIRECT(client, peer);
    if (kind == SS_DM_START) {
        if (length != 48) return 0;
        int simultaneous = dm && dm->stage == SS_DM_WAIT_REPLY;
        if (dm && (!simultaneous || client->id < peer)) {
            return DM_PACKET(client, peer, tag, SS_DM_CANCEL, NULL, 0);
        }
        if (dm) { DM_PACKET(client, peer, dm->tag, SS_DM_CANCEL, NULL, 0); FORGET(client, dm); }
        for (unsigned i = 0; i < SS_DM_MAX; i++) if (!client->direct[i].stage) { dm = &client->direct[i]; break; }
        if (!dm) return DM_PACKET(client, peer, tag, SS_DM_CANCEL, NULL, 0);
        dm->peer = peer; dm->stage = SS_DM_INVITED; dm->started = SS_TICKS();
        memcpy(dm->tag, tag, 16); memcpy(dm->first, data, 48); STATE(client, dm);
        if (simultaneous) SS_ACCEPT_DM(client, peer);
        return 1;
    }
    if (!dm || !SS_MATCH(dm->tag, tag, 16)) return 1;
    if (kind == SS_DM_CANCEL) {
        if (length) return 0;
        FORGET(client, dm); return 1;
    }
    if (kind == SS_DM_REPLY) {
        if (length != 48) return 0;
        if (dm->stage != SS_DM_WAIT_REPLY) {
            DM_PACKET(client, peer, tag, SS_DM_CANCEL, NULL, 0); FORGET(client, dm); return 1;
        }
        if (!SS_NOISE_FINISH(&dm->handshake, &dm->channel, data) || !CONFIRM(client, dm)) {
            DM_PACKET(client, peer, tag, SS_DM_CANCEL, NULL, 0); FORGET(client, dm); return 1;
        }
        dm->stage = SS_DM_WAIT_ACK; dm->started = SS_TICKS(); STATE(client, dm); return 1;
    }
    uint8_t plain[SS_PACKET_MAX];
    if (length < 17) return 0;
    if (dm->stage != SS_DM_READY && dm->stage != SS_DM_WAIT_CONFIRM && dm->stage != SS_DM_WAIT_ACK) {
        DM_PACKET(client, peer, tag, SS_DM_CANCEL, NULL, 0); FORGET(client, dm); return 1;
    }
    if (!SS_DECRYPT(&dm->channel.rx, plain, data, (size_t)length)) {
        DM_PACKET(client, peer, tag, SS_DM_CANCEL, NULL, 0); FORGET(client, dm);
        SS_WIPE(plain, sizeof(plain)); return 1;
    }
    int n = length - 16, ok = 1;
    if (dm->stage == SS_DM_WAIT_CONFIRM || dm->stage == SS_DM_WAIT_ACK) {
        if (n != 1 || plain[0] != 0) ok = 0;
        else {
            if (dm->stage == SS_DM_WAIT_CONFIRM) ok = CONFIRM(client, dm);
            if (ok) { dm->stage = SS_DM_READY; STATE(client, dm); }
        }
    } else if (n < 3 || plain[0] != 1 || plain[1] > SS_NAME_MAX || n <= 2 + plain[1] || n - 2 - plain[1] > SS_TEXT_MAX) ok = 0;
    else {
        SAVE_NAME(client, peer, plain + 2, plain[1]);
        EVENT(client, SS_EVENT_DM, peer, plain + 2, plain[1], plain + 2 + plain[1], n - 2 - plain[1]);
    }
    if (!ok) { DM_PACKET(client, peer, tag, SS_DM_CANCEL, NULL, 0); FORGET(client, dm); }
    SS_WIPE(plain, sizeof(plain));
    return 1;
}
static int PROCESS(SS_CLIENT *client, const uint8_t *packet, int length) {
    if (length <= 0) return 0;
    uint32_t peer = length >= 5 ? SS_LOAD32(packet + 1) : 0;
    if (!client->id) {
        if (length != 5 || packet[0] != SS_SELF || !peer) return 0;
        client->id = peer; client->ping_last = SS_TICKS();
        EVENT(client, SS_EVENT_SELF, peer, NULL, 0, NULL, 0); return 1;
    }
    if (packet[0] == SS_PONG) {
        if (length != 5) return 0;
        if (client->ping_state == 2 && peer == client->ping_sequence) {
            client->ping_state = 0; client->ping_last = SS_TICKS();
        }
        return 1;
    }
    if (packet[0] == SS_JOIN) {
        if (length != 37 || !peer || peer == client->id || MEMBER(client, peer)) return 0;
        for (unsigned i = 0; i < SS_CLIENT_MAX; i++) if (!client->members[i].id) {
            client->members[i].id = peer; memcpy(client->members[i].public_key, packet + 5, 32);
            client->members[i].name_pending = 1;
            EVENT(client, SS_EVENT_JOIN, peer, NULL, 0, NULL, 0); return 1;
        }
        return 0;
    }
    if (packet[0] == SS_LEAVE || packet[0] == SS_MISSING) {
        if (length != 5 || !peer || peer == client->id) return 0;
        SS_MEMBER *member = MEMBER(client, peer);
        if (member) SS_WIPE(member, sizeof(*member));
        SS_DIRECT *dm = DIRECT(client, peer);
        if (dm) FORGET(client, dm);
        EVENT(client, SS_EVENT_LEAVE, peer, NULL, 0, NULL, 0); return 1;
    }
    if (packet[0] == SS_LOBBY) {
        if (length < 7 || !MEMBER(client, peer) || packet[5] > SS_NAME_MAX
            || length <= 6 + packet[5] || length - 6 - packet[5] > SS_TEXT_MAX) return 0;
        SAVE_NAME(client, peer, packet + 6, packet[5]);
        EVENT(client, SS_EVENT_LOBBY, peer, packet + 6, packet[5], packet + 6 + packet[5], length - 6 - packet[5]);
        return 1;
    }
    if (packet[0] == SS_NAME) {
        if (length < 6 || !MEMBER(client, peer) || packet[5] > SS_NAME_MAX || length != 6 + packet[5]) return 0;
        SAVE_NAME(client, peer, packet + 6, packet[5]); return 1;
    }
    return packet[0] == SS_DM && DIRECT_MESSAGE(client, packet, length);
}
int SS_SEND_TEXT(SS_CLIENT *client, uint32_t peer, const uint8_t *name, int name_length, const uint8_t *text, int length) {
    if (!client->id || !text || length <= 0 || name_length < 0 || name_length > SS_NAME_MAX
        || (!name && name_length) || length > SS_MESSAGE_MAX - name_length - 1) return 0;
    SS_DIRECT *dm = peer ? DIRECT(client, peer) : NULL;
    if (peer && (!dm || dm->stage != SS_DM_READY)) return 0;
    int chunks = (length + SS_TEXT_MAX - 4) / (SS_TEXT_MAX - 3);
    int overhead = peer ? 60 : 22;
    if (length + chunks * (overhead + name_length) > SS_QUEUE_MAX - client->pending) return 0;
    if (!SS_SET_NAME(client, name, name_length)) return 0;
    uint8_t plain[SS_PACKET_MAX], encrypted[SS_PACKET_MAX];
    int offset = 0, ok = 1;
    while (offset < length) {
        int count = length - offset;
        if (count > SS_TEXT_MAX) {
            count = SS_TEXT_MAX;
            while (count > SS_TEXT_MAX - 3 && (text[offset + count] & 0xc0) == 0x80) count--;
        }
        plain[0] = peer ? 1 : SS_LOBBY; plain[1] = (uint8_t)name_length;
        if (name_length) memcpy(plain + 2, name, (size_t)name_length);
        memcpy(plain + 2 + name_length, text + offset, (size_t)count);
        int n = 2 + name_length + count;
        if (peer) ok = SS_ENCRYPT(&dm->channel.tx, encrypted, plain, (size_t)n)
            && DM_PACKET(client, peer, dm->tag, SS_DM_DATA, encrypted, n + 16);
        else ok = QUEUE(client, plain, n);
        if (!ok) break;
        offset += count;
    }
    if (!ok) SS_END_CLIENT(client);
    SS_WIPE(plain, sizeof(plain)); SS_WIPE(encrypted, sizeof(encrypted));
    return ok;
}
static int WAIT_ONE(SS_SOCKET sock, int events, uint32_t start, uint32_t limit) {
    while (1) {
        uint32_t elapsed = (uint32_t)(SS_TICKS() - start);
        if (elapsed >= limit) return 0;
        SS_POLL p = {sock, events, 0};
        int result = SS_WAIT(&p, 1, (int)(limit - elapsed));
        if (result < 0) return 0;
        if (p.ready) return 1;
    }
}
static int EXACT(SS_SOCKET sock, uint8_t *bytes, int length, int writing, uint32_t start) {
    int used = 0;
    while (used < length) {
        if (!WAIT_ONE(sock, writing ? SS_WRITE : SS_READ, start, SS_IO_MS)) return 0;
        int n = writing ? SS_SEND(sock, bytes + used, length - used) : SS_RECV(sock, bytes + used, length - used);
        if (n < 0 && SS_RETRY()) continue;
        if (n <= 0) return 0;
        used += n;
    }
    return 1;
}
int SS_RELAY_KEY(uint8_t relay_public[32], const char *value) {
    uint8_t default_secret[32] = {0}, default_public[32];
    if (!SS_PUBLIC_KEY(default_public, default_secret)) return 0;
    if (!strcmp(value, "OPEN") || !strcmp(value, "open")) {
        memcpy(relay_public, default_public, 32); return 2;
    }
    if (!SS_HEX_PARSE(relay_public, value)) return 0;
    return SS_MATCH(relay_public, default_public, 32) ? 2 : 1;
}
int SS_CONNECT_CLIENT(SS_CLIENT *client, const char *host, unsigned relay_port, const uint8_t relay_public[32], SS_EVENT_FN event, void *context) {
    uint8_t ephemeral[32], first[52], response[52], hello[SS_HELLO_SIZE];
    SS_HANDSHAKE handshake;
    struct addrinfo hints = {0}, *addresses = NULL;
    char port[16];
    SS_WIPE(client, sizeof(*client)); client->sock = SS_INVALID;
    client->event = event; client->context = context; client->needed = 4;
    memcpy(client->relay_public, relay_public, 32);
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM; hints.ai_protocol = IPPROTO_TCP;
    snprintf(port, sizeof(port), "%u", relay_port);
    int ok = 0;
    if (relay_port < 1 || relay_port > 65535) goto done;
    if (getaddrinfo(host, port, &hints, &addresses)) goto done;
    uint32_t started = SS_TICKS();
    for (struct addrinfo *p = addresses; p; p = p->ai_next) {
        client->sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (client->sock == SS_INVALID) continue;
        if (SS_NONBLOCK(client->sock)) {
            int result = connect(client->sock, p->ai_addr, (int)p->ai_addrlen);
            if (!result || (SS_CONNECT_PENDING() && WAIT_ONE(client->sock, SS_WRITE, started, SS_CONNECT_MS) && SS_CONNECT_ERROR(client->sock))) break;
        }
        SS_CLOSE(client->sock); client->sock = SS_INVALID;
    }
    freeaddrinfo(addresses);
    if (client->sock == SS_INVALID || !SS_RANDOM(ephemeral, 32)) goto done;
    SS_STORE32(first, 48);
    if (!SS_NOISE_START(&handshake, first + 4, relay_public, ephemeral,
        (const uint8_t *)SS_RELAY_PROLOGUE, sizeof(SS_RELAY_PROLOGUE) - 1)) goto done;
    started = SS_TICKS();
    if (!EXACT(client->sock, first, 52, 1, started) || !EXACT(client->sock, response, 4, 0, started)
        || SS_LOAD32(response) != 48 || !EXACT(client->sock, response + 4, 48, 0, started)
        || !SS_NOISE_FINISH(&handshake, &client->relay, response + 4)
        || !SS_RANDOM(client->secret, 32) || !SS_PUBLIC_KEY(hello + 1, client->secret)) goto done;
    hello[0] = SS_HELLO;
    ok = QUEUE(client, hello, SS_HELLO_SIZE); client->joined = SS_TICKS();
done:
    SS_WIPE(ephemeral, sizeof(ephemeral)); SS_WIPE(first, sizeof(first)); SS_WIPE(response, sizeof(response));
    SS_WIPE(hello, sizeof(hello)); SS_WIPE(&handshake, sizeof(handshake));
    if (!ok) SS_END_CLIENT(client);
    return ok;
}
void SS_END_CLIENT(SS_CLIENT *client) {
    if (client->sock != SS_INVALID) { shutdown(client->sock, SS_SHUT); SS_CLOSE(client->sock); }
    SS_EVENT_FN event = client->event; void *context = client->context;
    SS_WIPE(client, sizeof(*client)); client->sock = SS_INVALID;
    client->event = event; client->context = context;
}
int SS_CLIENT_IO(SS_CLIENT *client, int ready) {
    if (client->sock == SS_INVALID) return 0;
    uint32_t now = SS_TICKS();
    if ((!client->id && (uint32_t)(now - client->joined) >= SS_IO_MS)
        || (client->received && (uint32_t)(now - client->input_started) >= SS_IO_MS)
        || (client->pending && (uint32_t)(now - client->output_progress) >= SS_IO_MS)) goto failed;
    if (!HEARTBEAT(client, now)) goto failed;
    for (unsigned i = 0; i < SS_DM_MAX; i++) {
        SS_DIRECT *dm = &client->direct[i];
        if (dm->stage && dm->stage != SS_DM_READY && (uint32_t)(now - dm->started) >= SS_INVITE_MS) SS_CLOSE_DM(client, dm->peer);
    }
    if (client->pending && (ready & (SS_WRITE | SS_ERROR))) {
        int n = SS_SEND(client->sock, client->output, client->pending);
        if (n < 0 && SS_RETRY()) { }
        else if (n <= 0) goto failed;
        else {
            client->pending -= n; memmove(client->output, client->output + n, (size_t)client->pending);
            SS_WIPE(client->output + client->pending, (size_t)n); client->output_progress = SS_TICKS();
        }
    }
    if (ready & (SS_READ | SS_ERROR)) {
        int n = SS_RECV(client->sock, client->input + client->received, client->needed - client->received);
        if (n < 0 && SS_RETRY()) return 1;
        if (n <= 0) goto failed;
        if (!client->received) client->input_started = SS_TICKS();
        client->received += n;
        if (client->received == client->needed) {
            if (client->needed == 4) {
                uint32_t length = SS_LOAD32(client->input);
                if (length < 17 || length > SS_WIRE_MAX) goto failed;
                client->needed = 4 + (int)length;
            } else {
                uint8_t plain[SS_PACKET_MAX];
                int ok = SS_DECRYPT(&client->relay.rx, plain, client->input + 4, (size_t)client->needed - 4)
                    && PROCESS(client, plain, client->needed - 20);
                SS_WIPE(plain, sizeof(plain)); SS_WIPE(client->input, sizeof(client->input));
                client->received = 0; client->needed = 4;
                if (!ok) goto failed;
            }
        }
    }
    if (!HEARTBEAT(client, SS_TICKS())) goto failed;
    SEND_NAMES(client);
    return 1;
failed:
    SS_END_CLIENT(client);
    return 0;
}
