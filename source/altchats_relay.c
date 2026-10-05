#include "altchats_net.h"
#include "altchats_protocol.h"
#include <signal.h>
#include <stdio.h>
#define DEFAULT_CLIENTS 63
#ifndef SS_BYTE_RATE
#define SS_BYTE_RATE 16384UL
#endif
#ifndef SS_FRAME_RATE
#define SS_FRAME_RATE 32UL
#endif
#ifndef SS_INPUT_IDLE_MS
#define SS_INPUT_IDLE_MS 30000UL
#endif
#ifndef SS_INPUT_TOTAL_MS
#define SS_INPUT_TOTAL_MS 120000UL
#endif
#ifndef SS_OUTPUT_IDLE_MS
#define SS_OUTPUT_IDLE_MS 60000UL
#endif
typedef struct {
    SS_SOCKET sock;
    SS_CHANNEL channel;
    uint8_t public_key[32], input[4 + SS_WIRE_MAX], output[SS_RELAY_QUEUE_MAX];
    int phase, received, needed, pending;
    uint32_t id, accepted, input_started, input_progress, output_progress;
    uint32_t byte_credit, frame_credit, updated;
} PEER;
static PEER *peers;
static int client_limit = DEFAULT_CLIENTS;
static uint32_t next_id = 1;
static uint8_t identity[32];
static int private_mode;
static volatile sig_atomic_t stopped;
static void STOP(int signal_number) { (void)signal_number; stopped = 1; }
static void DESTROY(PEER *peer) {
    SS_CLOSE(peer->sock);
    SS_WIPE(peer, sizeof(*peer)); peer->sock = SS_INVALID;
}
static void DROP(PEER *peer) { peer->phase = -1; }
static int QUEUE(PEER *peer, const uint8_t *packet, int length) {
    if (peer->sock == SS_INVALID || peer->phase < 1) return 0;
    if (length <= 0 || length > SS_PACKET_MAX || length + 20 > SS_RELAY_QUEUE_MAX - peer->pending) {
        DROP(peer); return 0;
    }
    uint8_t *out = peer->output + peer->pending;
    SS_STORE32(out, (uint32_t)length + 16);
    if (!SS_ENCRYPT(&peer->channel.tx, out + 4, packet, (size_t)length)) { DROP(peer); return 0; }
    if (!peer->pending) peer->output_progress = SS_TICKS();
    peer->pending += length + 20;
    return 1;
}
static void FANOUT(const uint8_t *packet, int length, int excluded) {
    for (int i = 0; i < client_limit; i++) if (i != excluded && peers[i].phase == 2) QUEUE(&peers[i], packet, length);
}
static void REAP(void) {
    for (int i = 0; i < client_limit; i++) {
        PEER *peer = &peers[i];
        if (peer->sock == SS_INVALID || peer->phase >= 0) continue;
        uint32_t id = peer->id;
        DESTROY(peer);
        if (id) {
            uint8_t packet[5] = {SS_LEAVE}; SS_STORE32(packet + 1, id);
            FANOUT(packet, 5, i);
        }
    }
}
static PEER *FIND(uint32_t id) {
    for (int i = 0; i < client_limit; i++) if (peers[i].phase == 2 && peers[i].id == id) return &peers[i];
    return NULL;
}
static void REFILL(uint32_t *credit, uint32_t capacity, uint32_t rate, uint32_t elapsed) {
    if (elapsed >= (capacity - *credit + rate - 1) / rate) *credit = capacity;
    else *credit += elapsed * rate;
}
static void UPDATE_RATE(PEER *peer, uint32_t now) {
    uint32_t elapsed = (uint32_t)(now - peer->updated);
    REFILL(&peer->byte_credit, SS_BYTE_RATE * 2000, SS_BYTE_RATE, elapsed);
    REFILL(&peer->frame_credit, SS_FRAME_RATE * 2000, SS_FRAME_RATE, elapsed);
    peer->updated = now;
}
static int CAN_READ(const PEER *peer) { return peer->byte_credit >= 1000 && (peer->received || peer->frame_credit >= 1000); }
static int EXPIRED(const PEER *peer) {
    uint32_t now = SS_TICKS();
    return (peer->phase < 2 && (uint32_t)(now - peer->accepted) >= SS_INPUT_IDLE_MS)
        || (peer->received && ((uint32_t)(now - peer->input_progress) >= SS_INPUT_IDLE_MS
            || (uint32_t)(now - peer->input_started) >= SS_INPUT_TOTAL_MS))
        || (peer->pending && (uint32_t)(now - peer->output_progress) >= SS_OUTPUT_IDLE_MS);
}
static void WRITE_PEER(PEER *peer) {
    int n = SS_SEND(peer->sock, peer->output, peer->pending);
    if (n < 0 && SS_RETRY()) return;
    if (n <= 0) { DROP(peer); return; }
    peer->pending -= n; memmove(peer->output, peer->output + n, (size_t)peer->pending);
    SS_WIPE(peer->output + peer->pending, (size_t)n); peer->output_progress = SS_TICKS();
}
static int REGISTER(int index, const uint8_t *packet, int length) {
    PEER *peer = &peers[index];
    if (length != SS_HELLO_SIZE || packet[0] != SS_HELLO || !next_id) return 0;
    memcpy(peer->public_key, packet + 1, 32);
    peer->id = next_id++;
    uint8_t self[5] = {SS_SELF}; SS_STORE32(self + 1, peer->id);
    if (!QUEUE(peer, self, 5)) return 0;
    for (int i = 0; i < client_limit; i++) if (i != index && peers[i].phase == 2) {
        uint8_t joined[37] = {SS_JOIN}; SS_STORE32(joined + 1, peers[i].id);
        memcpy(joined + 5, peers[i].public_key, 32);
        if (!QUEUE(peer, joined, 37)) return 0;
    }
    peer->phase = 2;
    uint8_t joined[37] = {SS_JOIN}; SS_STORE32(joined + 1, peer->id);
    memcpy(joined + 5, peer->public_key, 32); FANOUT(joined, 37, index);
    SS_WIPE(joined, sizeof(joined));
    return 1;
}
static int PROCESS(int index, uint8_t *packet, int length) {
    PEER *peer = &peers[index];
    if (peer->phase == 1) return REGISTER(index, packet, length);
    if (length < 2) return 0;
    if (packet[0] == SS_PING) {
        if (length != 5) return 0;
        packet[0] = SS_PONG; return QUEUE(peer, packet, 5);
    }
    if (packet[0] == SS_NAME) {
        if (length < 6 || packet[5] > SS_NAME_MAX || length != 6 + packet[5]) return 0;
        uint32_t id = SS_LOAD32(packet + 1);
        if (id == peer->id) return 0;
        SS_STORE32(packet + 1, peer->id);
        if (!id) FANOUT(packet, length, index);
        else {
            PEER *target = FIND(id);
            if (target) QUEUE(target, packet, length);
        }
        return 1;
    }
    if (packet[0] == SS_LOBBY) {
        unsigned n = packet[1];
        if (n > SS_NAME_MAX || length <= (int)n + 2 || length - (int)n - 2 > SS_TEXT_MAX) return 0;
        uint8_t forwarded[SS_PACKET_MAX];
        forwarded[0] = SS_LOBBY; SS_STORE32(forwarded + 1, peer->id);
        memcpy(forwarded + 5, packet + 1, (size_t)length - 1);
        FANOUT(forwarded, length + 4, index); SS_WIPE(forwarded, sizeof(forwarded));
        return 1;
    }
    if (packet[0] != SS_DM || length < 22) return 0;
    unsigned kind = packet[21]; int n = length - 22;
    if ((kind == SS_DM_START || kind == SS_DM_REPLY) ? n != 48
        : kind == SS_DM_DATA ? (n < 17 || n > SS_TEXT_MAX + SS_NAME_MAX + 18)
        : kind != SS_DM_CANCEL || n != 0) return 0;
    uint32_t id = SS_LOAD32(packet + 1);
    if (!id || id == peer->id) return 0;
    PEER *target = FIND(id);
    if (!target) {
        uint8_t missing[5] = {SS_MISSING}; SS_STORE32(missing + 1, id);
        return QUEUE(peer, missing, 5);
    }
    SS_STORE32(packet + 1, peer->id);
    QUEUE(target, packet, length);
    return 1;
}
static void READ_PEER(int index) {
    PEER *peer = &peers[index];
    if (!CAN_READ(peer)) return;
    int length = peer->needed - peer->received;
    if (length > (int)(peer->byte_credit / 1000)) length = (int)(peer->byte_credit / 1000);
    int n = SS_RECV(peer->sock, peer->input + peer->received, length);
    if (n < 0 && SS_RETRY()) return;
    if (n <= 0) { DROP(peer); return; }
    uint32_t now = SS_TICKS();
    if (!peer->received) { peer->input_started = now; peer->frame_credit -= 1000; }
    peer->input_progress = now; peer->byte_credit -= (uint32_t)n * 1000; peer->received += n;
    if (peer->received != peer->needed) return;
    if (peer->needed == 4) {
        uint32_t count = SS_LOAD32(peer->input);
        if ((!peer->phase && count != 48) || (peer->phase && (count < 17 || count > SS_WIRE_MAX))) { DROP(peer); return; }
        peer->needed = 4 + (int)count; return;
    }
    int ok;
    if (!peer->phase) {
        uint8_t ephemeral[32], response[48];
        ok = SS_RANDOM(ephemeral, 32) && SS_NOISE_RESPOND(&peer->channel, response, peer->input + 4,
            identity, ephemeral, (const uint8_t *)SS_RELAY_PROLOGUE, sizeof(SS_RELAY_PROLOGUE) - 1);
        if (ok) {
            SS_STORE32(peer->output, 48); memcpy(peer->output + 4, response, 48);
            peer->pending = 52; peer->output_progress = SS_TICKS(); peer->phase = 1;
        }
        SS_WIPE(ephemeral, sizeof(ephemeral)); SS_WIPE(response, sizeof(response));
    } else {
        uint8_t plain[SS_PACKET_MAX];
        ok = SS_DECRYPT(&peer->channel.rx, plain, peer->input + 4, (size_t)peer->needed - 4)
            && PROCESS(index, plain, peer->needed - 20);
        SS_WIPE(plain, sizeof(plain));
    }
    SS_WIPE(peer->input, sizeof(peer->input)); peer->received = 0; peer->needed = 4;
    if (!ok) DROP(peer);
}
static int PARSE_LIMIT(int argc, char *argv[]) {
    if (argc == 1) return 1;
    if (argc != 2 || !argv[1][0]) return 0;
    int value = 0;
    for (const char *p = argv[1]; *p; p++) {
        if (*p < '0' || *p > '9') return 0;
        int digit = *p - '0';
        if (value > (SS_CLIENT_MAX - digit) / 10) return 0;
        value = value * 10 + digit;
    }
    if (!value || value > SS_CLIENT_MAX) return 0;
    client_limit = value; return 1;
}
static int START_MODE(void) {
    char answer[16];
    while (1) {
        printf("Privatize this relay? [y/N]: "); fflush(stdout);
        if (!fgets(answer, sizeof(answer), stdin)) { SS_WIPE(answer, sizeof(answer)); return 0; }
        int full = !strchr(answer, '\n') && strlen(answer) == sizeof(answer) - 1;
        if (full) { int c; do { c = getchar(); } while (c != '\n' && c != EOF); }
        answer[strcspn(answer, "\r\n")] = 0;
        char *value = answer;
        while (*value == ' ' || *value == '\t') value++;
        size_t length = strlen(value);
        while (length && (value[length - 1] == ' ' || value[length - 1] == '\t')) value[--length] = 0;
        private_mode = !strcmp(value, "y") || !strcmp(value, "Y") || !strcmp(value, "yes") || !strcmp(value, "Yes") || !strcmp(value, "YES");
        int open = !*value || !strcmp(value, "n") || !strcmp(value, "N") || !strcmp(value, "no") || !strcmp(value, "No") || !strcmp(value, "NO");
        SS_WIPE(answer, sizeof(answer));
        if (!full && (private_mode || open)) break;
        printf("Enter Y for private mode, or N/Enter for OPEN.\n");
    }
    return 1;
}
int main(int argc, char *argv[]) {
    if (!PARSE_LIMIT(argc, argv)) { fprintf(stderr, "Usage: altchats_relay [max_clients: 1-%d]\n", SS_CLIENT_MAX); return 1; }
    if (!SS_NET_START()) return 1;
    SS_SOCKET listener = SS_INVALID;
    int result = 1;
    uint8_t public_key[32]; char key[65];
    unsigned relay_port;
    if (!SS_READ_PORT("Starting relay port", ALTCHATS_PORT, &relay_port) || !START_MODE()) goto cleanup;
    peers = calloc((size_t)client_limit, sizeof(*peers));
    if (!peers) goto cleanup;
    for (int i = 0; i < client_limit; i++) peers[i].sock = SS_INVALID;
    SS_WIPE(identity, sizeof(identity));
    if ((private_mode && !SS_RANDOM(identity, 32)) || !SS_PUBLIC_KEY(public_key, identity)) goto cleanup;
    SS_HEX(key, public_key);
    listener = SS_LISTEN(INADDR_ANY, &relay_port, SOMAXCONN);
    if (listener == SS_INVALID) { fprintf(stderr, "No usable relay port at or above %u, or listening socket failed.\n", relay_port); goto cleanup; }
    printf("ALTCHATS: port %u, up to %d clients. Ctrl+C to stop.\nRELAY PUBLIC KEY: %s\n", relay_port, client_limit, private_mode ? key : "OPEN");
    printf("RELAY MODE: %s\n", private_mode ? "PRIVATE" : "OPEN");
    if (private_mode) printf("Give this public key to users through a trusted source. It changes after a restart.\n");
    else printf("Clients can use OPEN or omit the key. Relay identity is not verified in OPEN mode.\n");
    fflush(stdout); signal(SIGINT, STOP); signal(SIGTERM, STOP);
    SS_POLL sockets[SS_CLIENT_MAX + 1];
    while (!stopped) {
        REAP();
        sockets[0] = (SS_POLL){listener, SS_READ, 0};
        uint32_t now = SS_TICKS();
        for (int i = 0; i < client_limit; i++) {
            PEER *peer = &peers[i]; sockets[i + 1] = (SS_POLL){SS_INVALID, 0, 0};
            if (peer->sock == SS_INVALID || peer->phase < 0) continue;
            UPDATE_RATE(peer, now);
            sockets[i + 1].sock = peer->sock;
            if (CAN_READ(peer)) sockets[i + 1].events |= SS_READ;
            if (peer->pending) sockets[i + 1].events |= SS_WRITE;
        }
        if (SS_WAIT(sockets, client_limit + 1, 100) < 0) goto cleanup;
        for (int i = 0; i < client_limit; i++) {
            PEER *peer = &peers[i];
            if (peer->sock == SS_INVALID || peer->phase < 0) continue;
            if (EXPIRED(peer)) { DROP(peer); continue; }
            if (peer->pending && (sockets[i + 1].ready & (SS_WRITE | SS_ERROR))) WRITE_PEER(peer);
            if (peer->phase >= 0 && (sockets[i + 1].ready & (SS_READ | SS_ERROR))) READ_PEER(i);
        }
        REAP();
        if (sockets[0].ready & SS_ERROR) goto cleanup;
        if (sockets[0].ready & SS_READ) {
            SS_SOCKET sock = accept(listener, NULL, NULL);
            if (sock == SS_INVALID) continue;
            int slot = 0;
            while (slot < client_limit && peers[slot].sock != SS_INVALID) slot++;
            if (slot == client_limit || !SS_NONBLOCK(sock)) SS_CLOSE(sock);
            else {
                PEER *peer = &peers[slot]; peer->sock = sock; peer->needed = 4;
                peer->byte_credit = SS_BYTE_RATE * 2000; peer->frame_credit = SS_FRAME_RATE * 2000;
                peer->accepted = peer->updated = SS_TICKS();
            }
        }
    }
    result = 0;
cleanup:
    if (peers) { for (int i = 0; i < client_limit; i++) DESTROY(&peers[i]); free(peers); }
    SS_CLOSE(listener); SS_WIPE(identity, sizeof(identity)); SS_WIPE(public_key, sizeof(public_key));
    SS_NET_END();
    if (result) fprintf(stderr, "Relay could not start or its socket failed.\n");
    return result;
}
