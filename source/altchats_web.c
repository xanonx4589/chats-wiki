#include "altchats_session.h"
#include "bridge_guard.h"
#include <ctype.h>
#include <signal.h>
#include <stdio.h>
#ifndef WEB_PORT
#define WEB_PORT 8080
#endif
#define SS_STRING_INNER(x) #x
#define SS_STRING(x) SS_STRING_INNER(x)
static char web_host[16] = "127.0.0.1:" SS_STRING(WEB_PORT);
static char web_origin[23] = "http://127.0.0.1:" SS_STRING(WEB_PORT);
#define HTTP_CLIENTS 4
#define HEADER_MAX 4096
#define MESSAGE_MAX SS_MESSAGE_MAX
#define BUFFER_MAX 32768
#define HTTP_MS 5000UL
typedef struct {
    SS_SOCKET sock;
    char input[HEADER_MAX + MESSAGE_MAX + 1], output[BUFFER_MAX + 1024];
    int used, head, body, action, size, sent, permit_length;
    uint32_t started, target;
} HTTP;
static HTTP http[HTTP_CLIENTS];
static BRIDGE_GUARD guard;
static SS_CLIENT connection;
static char page[24576], inbox[16384];
static int page_size, inbox_size;
static uint32_t guard_target;
static unsigned name_cursor;
static volatile sig_atomic_t stopped;
static void STOP(int n) { (void)n; stopped = 1; }
static void WIPE(void *memory, size_t length) { SS_WIPE(memory, length); }
static void CLOSE_HTTP(HTTP *client) {
    SS_CLOSE(client->sock); WIPE(client, sizeof(*client)); client->sock = SS_INVALID;
}
static int QUOTED(char *out, int capacity, const uint8_t *text, int length) {
    static const char hex[] = "0123456789abcdef";
    int used = 0;
    if (capacity < 2) return -1;
    out[used++] = '"';
    for (int i = 0; i < length; i++) {
        unsigned c = text[i];
        int needed = c < 32 ? 6 : c == '"' || c == '\\' ? 2 : 1;
        if (needed + 1 > capacity - used) return -1;
        if (c < 32) {
            out[used++] = '\\'; out[used++] = 'u'; out[used++] = '0'; out[used++] = '0';
            out[used++] = hex[c >> 4]; out[used++] = hex[c & 15];
        } else {
            if (c == '"' || c == '\\') out[used++] = '\\';
            out[used++] = (char)c;
        }
    }
    out[used++] = '"';
    return used;
}
static int ROW(char *out, int capacity, unsigned type, uint32_t id, const char *tag,
    const uint8_t *name, int n, const uint8_t *text, int length) {
    int used = snprintf(out, (size_t)capacity, "[\"%u\",\"%lu%s%s\",", type, (unsigned long)id, tag ? ":" : "", tag ? tag : "");
    if (used <= 0 || used >= capacity) return -1;
    int count = QUOTED(out + used, capacity - used, name, n);
    if (count < 0 || count + 2 > capacity - used) return -1;
    used += count; out[used++] = ',';
    count = QUOTED(out + used, capacity - used, text, length);
    if (count < 0 || count + 1 > capacity - used) return -1;
    used += count; out[used++] = ']'; return used;
}
static void EVENT(void *context, unsigned type, uint32_t id, const uint8_t *name, int n, const uint8_t *text, int length) {
    (void)context;
    if (length < 0 || n < 0 || length > SS_TEXT_MAX || n > SS_NAME_MAX) return;
    char tag[33], *session = NULL;
    if (type == SS_EVENT_STATE && n == 32) {
        memcpy(tag, name, 32); tag[32] = 0; session = tag; name = NULL; n = 0;
    } else if (type == SS_EVENT_DM) {
        for (unsigned i = 0; i < SS_DM_MAX; i++) if (connection.direct[i].stage && connection.direct[i].peer == id) {
            SS_TAG_HEX(tag, connection.direct[i].tag); session = tag; break;
        }
    }
    if (6 * (length + n) + 100 > (int)sizeof(inbox) - inbox_size) {
        WIPE(inbox, sizeof(inbox));
        const char notice[] = "[\"7\",\"0\",\"\",\"Unread messages discarded: buffer full.\"]";
        memcpy(inbox, notice, sizeof(notice) - 1); inbox_size = sizeof(notice) - 1;
    }
    if (inbox_size) inbox[inbox_size++] = ',';
    int count = ROW(inbox + inbox_size, (int)sizeof(inbox) - inbox_size, type, id, session, name, n, text, length);
    if (count > 0) inbox_size += count;
}
static void REPLY(HTTP *client, int code, const char *reason, const char *type,
    const char *body, int length, const char *nonce) {
    char policy[512] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
    if (nonce) {
        int size = snprintf(policy, sizeof(policy),
            "default-src 'none'; script-src 'unsafe-inline' 'nonce-%s'; "
            "style-src 'unsafe-inline' 'nonce-%s'; connect-src 'self'; "
            "frame-ancestors 'none'; base-uri 'none'; form-action 'none'", nonce, nonce);
        if (size < 0 || size >= (int)sizeof(policy)) { CLOSE_HTTP(client); return; }
    }
    int head = snprintf(client->output, 1024,
        "HTTP/1.1 %d %s\r\nContent-Type: %s; charset=utf-8\r\n"
        "Content-Length: %d\r\nConnection: close\r\nCache-Control: no-store\r\n"
        "Pragma: no-cache\r\nX-Content-Type-Options: nosniff\r\n"
        "X-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\n"
        "Cross-Origin-Resource-Policy: same-origin\r\n"
        "Content-Security-Policy: %s\r\n\r\n", code, reason, type, length, policy);
    if (head < 0 || head >= 1024 || length < 0 || length > BUFFER_MAX) { CLOSE_HTTP(client); return; }
    memmove(client->output + head, body, (size_t)length);
    client->size = head + length;
    WIPE(client->input, sizeof(client->input));
}
static void HTTP_ERROR(HTTP *client, int code, const char *message) {
    REPLY(client, code, message, "text/plain", message, (int)strlen(message), NULL);
}
static int SAME(const char *a, const char *b) {
    while (*a && *b && tolower((unsigned char)*a) == tolower((unsigned char)*b)) { a++; b++; }
    return *a == *b;
}
static int PARSE(HTTP *client) {
    char *end = strstr(client->input, "\r\n\r\n");
    if (!end) {
        if (client->used >= HEADER_MAX) HTTP_ERROR(client, 431, "Headers too large");
        return 0;
    }
    client->head = (int)(end - client->input) + 4;
    if (client->head > HEADER_MAX) { HTTP_ERROR(client, 431, "Headers too large"); return 0; }
    for (int i = 0; i < client->head; i++) {
        unsigned char c = (unsigned char)client->input[i];
        if ((c < 32 && c != '\r' && c != '\n' && c != '\t') || c == 127) goto malformed;
    }
    char *line = strstr(client->input, "\r\n");
    if (!line) goto malformed;
    *line = 0;
    char *path = strchr(client->input, ' ');
    if (!path) goto malformed;
    *path++ = 0;
    char *version = strchr(path, ' ');
    if (!version) goto malformed;
    *version++ = 0;
    if (strcmp(version, "HTTP/1.1") && strcmp(version, "HTTP/1.0")) goto malformed;
    if (!strcmp(client->input, "GET") && !strcmp(path, "/")) client->action = 1;
    else if (!strcmp(client->input, "POST") && !strcmp(path, "/poll")) client->action = 2;
    else if (!strcmp(client->input, "POST") && !strcmp(path, "/send")) client->action = 3;
    else if (!strcmp(client->input, "POST") && !strcmp(path, "/permit")) client->action = 4;
    else if (!strcmp(client->input, "POST") && !strcmp(path, "/dm-start")) client->action = 5;
    else if (!strcmp(client->input, "POST") && !strcmp(path, "/dm-accept")) client->action = 6;
    else if (!strcmp(client->input, "POST") && !strcmp(path, "/dm-close")) client->action = 7;
    else if (!strcmp(client->input, "POST") && !strcmp(path, "/name")) client->action = 8;
    else { HTTP_ERROR(client, 404, "Not found"); return 0; }
    int host = 0, length = 0, marker = 0, origin = 0, referer = 0;
    int token = 0, ticket = 0, declared = 0, content_type = 0, fetch_site = 0;
    int recipient = 0;
    const char *permit = NULL;
    line += 2;
    while (line < end) {
        char *next = strstr(line, "\r\n"), *value = strchr(line, ':');
        if (!next || !value || value >= next || value == line) goto malformed;
        for (char *p = line; p < value; p++) {
            unsigned char c = (unsigned char)*p;
            if (!isalnum(c) && !strchr("!#$%&'*+-.^_`|~", c)) goto malformed;
        }
        *next = 0;
        *value++ = 0;
        while (*value == ' ' || *value == '\t') value++;
        char *tail = next;
        while (tail > value && (tail[-1] == ' ' || tail[-1] == '\t')) *--tail = 0;
        for (char *p = value; *p; p++) if ((unsigned char)*p < 32 && *p != '\t') goto malformed;
        if (SAME(line, "Host")) {
            if (host++ || strcmp(value, web_host)) goto forbidden;
        } else if (SAME(line, "Content-Length")) {
            if (length++ || !*value) goto malformed;
            for (char *p = value; *p; p++) {
                if (*p < '0' || *p > '9') goto malformed;
                client->body = client->body * 10 + *p - '0';
                if (client->body > MESSAGE_MAX) { HTTP_ERROR(client, 413, "Message too large (8192 bytes maximum)"); return 0; }
            }
        } else if (SAME(line, "Transfer-Encoding") || SAME(line, "Expect")) goto malformed;
        else if (SAME(line, "X-Altchats")) {
            if (marker++ || strcmp(value, "1")) goto forbidden;
        } else if (SAME(line, "X-Bridge-Token")) {
            if (token++ || !BG_MATCH(guard.token, value)) goto forbidden;
        } else if (SAME(line, "X-Peer")) {
            if (recipient++ || !*value) goto malformed;
            for (const char *p = value; *p; p++) {
                if (*p < '0' || *p > '9') goto malformed;
                unsigned digit = (unsigned)(*p - '0');
                if (client->target > (UINT32_MAX - digit) / 10) goto malformed;
                client->target = client->target * 10 + digit;
            }
        } else if (SAME(line, "X-Send-Permit")) {
            if (ticket++) goto forbidden;
            permit = value;
        } else if (SAME(line, "X-Message-Length")) {
            if (declared++ || !*value) goto malformed;
            for (char *p = value; *p; p++) {
                if (*p < '0' || *p > '9') goto malformed;
                client->permit_length = client->permit_length * 10 + *p - '0';
                if (client->permit_length > MESSAGE_MAX) {
                    HTTP_ERROR(client, 413, "Message too large (8192 bytes maximum)");
                    return 0;
                }
            }
        } else if (SAME(line, "Content-Type")) {
            if (content_type++ || (!SAME(value, "text/plain; charset=utf-8")
                && !SAME(value, "text/plain"))) goto malformed;
        } else if (SAME(line, "Sec-Fetch-Site")) {
            if (fetch_site++ || (client->action != 1 && strcmp(value, "same-origin"))) goto forbidden;
        } else if (SAME(line, "Origin")) {
            if (origin++ || strcmp(value, web_origin)) goto forbidden;
        } else if (SAME(line, "Referer")) {
            size_t size = strlen(web_origin);
            if (referer++ || strncmp(value, web_origin, size) || value[size] != '/') goto forbidden;
        }
        line = next + 2;
    }
    if (!host || (client->action != 1 && (!marker || !token))) goto forbidden;
    if (client->action != 1 && (!length || !content_type)) goto malformed;
    if ((client->action != 3 && client->action != 8 && client->body) || (client->action == 3 && !client->body)) goto malformed;
    if (client->action == 4) {
        if (!declared || !client->permit_length || ticket) goto malformed;
    } else if (declared) goto malformed;
    if (recipient && client->action != 3 && client->action != 4 && (client->action < 5 || client->action > 7)) goto malformed;
    if (client->action >= 5 && client->action <= 7 && (!recipient || !client->target)) goto malformed;
    if (client->action == 3) {
        if (!ticket || guard_target != client->target || !BG_TAKE(&guard, permit, (uint32_t)client->body, SS_TICKS())) goto forbidden;
    } else if (ticket) goto malformed;
    return 1;
forbidden:
    HTTP_ERROR(client, 403, "Forbidden");
    return 0;
malformed:
    HTTP_ERROR(client, 400, "Bad request");
    return 0;
}
static void DISPATCH(HTTP *client) {
    if (client->action == 1) {
        char nonce[BG_HEX_SIZE + 1];
        if (!BG_RANDOM_HEX(nonce)) { HTTP_ERROR(client, 503, "Random source unavailable"); return; }
        int size = BG_RENDER(client->output + 1024, BUFFER_MAX, page, (size_t)page_size, guard.token, nonce);
        if (size < 0) HTTP_ERROR(client, 500, "Use the matching altchats.html from this build");
        else REPLY(client, 200, "OK", "text/html", client->output + 1024, size, nonce);
        BG_WIPE(nonce, sizeof(nonce)); return;
    }
    if (connection.sock == SS_INVALID) {
        HTTP_ERROR(client, 410, "Relay is busy or disconnected; or lobby is full. Close and restart the bridge to try to reconnect."); return;
    }
    if (!connection.id) { HTTP_ERROR(client, 202, "Relay verified. Joining the lobby..."); return; }
    if (client->action == 2) {
        char *out = client->output + 1024;
        int used = snprintf(out, BUFFER_MAX, "[[\"0\",\"%lu\",\"", (unsigned long)connection.id);
        for (unsigned i = 0; i < SS_CLIENT_MAX; i++) if (connection.members[i].id)
            used += snprintf(out + used, BUFFER_MAX - (size_t)used, "%lu,", (unsigned long)connection.members[i].id);
        memcpy(out + used, "\",\"", 3); used += 3;
        for (unsigned i = 0; i < SS_DM_MAX; i++) if (connection.direct[i].stage) {
            char tag[33]; SS_TAG_HEX(tag, connection.direct[i].tag);
            used += snprintf(out + used, BUFFER_MAX - (size_t)used, "%lu:%u:%s,",
                (unsigned long)connection.direct[i].peer, connection.direct[i].stage, tag);
        }
        memcpy(out + used, "\"]", 2); used += 2;
        if (inbox_size) { out[used++] = ','; memcpy(out + used, inbox, (size_t)inbox_size); used += inbox_size; }
        int budget = 4096;
        for (unsigned i = 0; i <= SS_CLIENT_MAX; i++) {
            SS_MEMBER *member = i ? &connection.members[name_cursor] : NULL;
            uint32_t id = member ? member->id : connection.id;
            if (id) {
                char row[6 * SS_NAME_MAX + 64];
                int size = ROW(row, sizeof(row), SS_EVENT_NAME, id, NULL,
                    member ? member->name : connection.name, member ? member->name_length : connection.name_length, NULL, 0);
                if (size < 0 || size + 1 > budget || size + 2 > BUFFER_MAX - used) break;
                out[used++] = ','; memcpy(out + used, row, (size_t)size); used += size; budget -= size + 1;
            }
            if (i) name_cursor = (name_cursor + 1) % SS_CLIENT_MAX;
        }
        out[used++] = ']';
        REPLY(client, 200, "OK", "application/json", out, used, NULL);
        WIPE(inbox, sizeof(inbox)); inbox_size = 0; return;
    }
    if (client->action == 8) {
        if (SS_SET_NAME(&connection, (const uint8_t *)client->input + client->head, client->body))
            REPLY(client, 200, "OK", "text/plain", "", 0, NULL);
        else HTTP_ERROR(client, 400, "Display name: maximum 63 UTF-8 bytes, one line.");
        return;
    }
    if (client->action >= 5 && client->action <= 7) {
        int ok = client->action == 5 ? SS_START_DM(&connection, client->target)
            : client->action == 6 ? SS_ACCEPT_DM(&connection, client->target) : SS_CLOSE_DM(&connection, client->target);
        if (ok) REPLY(client, 200, "OK", "text/plain", "", 0, NULL);
        else HTTP_ERROR(client, 409, "Peer unavailable, DM already active, or session/buffer not ready.");
        return;
    }
    if (client->target && SS_DM_STATE(&connection, client->target) != SS_DM_READY) {
        HTTP_ERROR(client, 409, "Wait for DM acceptance and key confirmation before sending."); return;
    }
    if (client->action == 4) {
        if (client->permit_length + 132 * (client->permit_length / 1021 + 1) > SS_QUEUE_MAX - connection.pending) {
            HTTP_ERROR(client, 503, "Send buffer full. Try again shortly."); return;
        }
        int granted = BG_ISSUE(&guard, (uint32_t)client->permit_length, SS_TICKS());
        if (granted < 0) HTTP_ERROR(client, 409, "A send is already pending. Try again shortly.");
        else if (!granted) HTTP_ERROR(client, 503, "Random source unavailable");
        else { guard_target = client->target; REPLY(client, 200, "OK", "text/plain", guard.permit, BG_HEX_SIZE, NULL); }
        return;
    }
    uint8_t *body = (uint8_t *)client->input + client->head;
    uint8_t *newline = memchr(body, '\n', (size_t)client->body);
    if (!newline || newline - body > SS_NAME_MAX || newline == body + client->body - 1) {
        HTTP_ERROR(client, 400, "Use a display name of up to 63 UTF-8 bytes and a nonempty message."); return;
    }
    int n = (int)(newline - body);
    if (!SS_SEND_TEXT(&connection, client->target, body, n, newline + 1, client->body - n - 1)) {
        HTTP_ERROR(client, 409, "Send not queued. Check message size, DM state and buffer space."); return;
    }
    REPLY(client, 200, "OK", "text/plain", "", 0, NULL);
}
static void READ_HTTP(HTTP *client) {
    if (client->size < 0) {
        int count = SS_RECV(client->sock, client->input, sizeof(client->input));
        if (count == -1 && SS_RETRY()) return;
        if (count <= 0) CLOSE_HTTP(client);
        else WIPE(client->input, count);
        return;
    }
    int limit = client->head ? client->head + client->body : HEADER_MAX;
    int count = SS_RECV(client->sock, client->input + client->used, limit - client->used);
    if (count == -1 && SS_RETRY()) return;
    if (count <= 0) { CLOSE_HTTP(client); return; }
    if (!client->head && memchr(client->input + client->used, 0, count)) { HTTP_ERROR(client, 400, "Bad request"); return; }
    client->used += count;
    client->input[client->used] = 0;
    if (!client->head && !PARSE(client)) return;
    if (client->used > client->head + client->body) { HTTP_ERROR(client, 400, "Bad request"); return; }
    if (client->used == client->head + client->body) DISPATCH(client);
}
static void WRITE_HTTP(HTTP *client) {
    int count = (int)SS_SEND(client->sock, client->output + client->sent, client->size - client->sent);
    if (count == -1 && SS_RETRY()) return;
    if (count <= 0) { CLOSE_HTTP(client); return; }
    WIPE(client->output + client->sent, count);
    client->sent += count;
    if (client->sent == client->size) {
        shutdown(client->sock, SS_SHUT_WRITE);
        client->size = -1;
    }
}
int main(int argc, char *argv[]) {
    if (argc != 2 && argc != 3) { printf("Usage: altchats_web RELAY_HOST [RELAY_PUBLIC_KEY|OPEN]\n"); return 1; }
    uint8_t relay_public[32];
    int mode = SS_RELAY_KEY(relay_public, argc == 3 ? argv[2] : "OPEN");
    if (!mode) { fprintf(stderr, "Use OPEN, or the relay's 64-digit public key from a trusted source.\n"); return 1; }
    FILE *file = fopen("altchats.html", "rb");
    if (!file) { fprintf(stderr, "Run from the folder containing altchats.html.\n"); return 1; }
    page_size = (int)fread(page, 1, sizeof(page), file);
    int bad_file = ferror(file) || !page_size || fgetc(file) != EOF;
    fclose(file);
    if (bad_file) { fprintf(stderr, "HTML file must be 1-24576 bytes.\n"); return 1; }
    unsigned relay_port, web_port;
    if (!SS_READ_PORT("Relay port", ALTCHATS_PORT, &relay_port)
        || !SS_READ_PORT("Starting local web port", WEB_PORT, &web_port)) return 1;
    if (!SS_NET_START()) return 1;
    SS_SOCKET listener = SS_INVALID;
    int result = 1;
    connection.sock = SS_INVALID;
    for (int i = 0; i < HTTP_CLIENTS; i++) http[i].sock = SS_INVALID;
    if (!BG_INIT(&guard)) { fprintf(stderr, "Random source unavailable.\n"); goto cleanup; }
    listener = SS_LISTEN(INADDR_LOOPBACK, &web_port, 4);
    if (listener == SS_INVALID) {
        fprintf(stderr, "No usable local web port at or above %u, or listening socket failed.\n", web_port); goto cleanup;
    }
    if (web_port == 80) strcpy(web_host, "127.0.0.1");
    else snprintf(web_host, sizeof(web_host), "127.0.0.1:%u", web_port);
    snprintf(web_origin, sizeof(web_origin), "http://%s", web_host);
    if (!SS_CONNECT_CLIENT(&connection, argv[1], relay_port, relay_public, EVENT, NULL)) {
        fprintf(stderr, "Relay connection/authentication failed. No unverified fallback.\n"); goto cleanup;
    }
    printf("%s Open %s/ on this computer.\nCtrl+C stops the bridge.\n",
        mode == 2 ? "OPEN relay. Identity not verified." : "Relay verified.", web_origin);
    fflush(stdout); signal(SIGINT, STOP); signal(SIGTERM, STOP);
    SS_POLL sockets[HTTP_CLIENTS + 2];
    while (!stopped) {
        sockets[0] = (SS_POLL){listener, SS_READ, 0};
        sockets[1] = (SS_POLL){connection.sock, SS_READ | (connection.pending ? SS_WRITE : 0), 0};
        for (int i = 0; i < HTTP_CLIENTS; i++)
            sockets[i + 2] = (SS_POLL){http[i].sock, http[i].size > 0 ? SS_WRITE : SS_READ, 0};
        if (SS_WAIT(sockets, HTTP_CLIENTS + 2, 100) < 0) goto cleanup;
        uint32_t now = SS_TICKS(); BG_EXPIRE(&guard, now);
        if (connection.sock != SS_INVALID && !SS_CLIENT_IO(&connection, sockets[1].ready)) {
            BG_CANCEL(&guard); WIPE(inbox, sizeof(inbox)); inbox_size = 0;
        }
        for (int i = 0; i < HTTP_CLIENTS; i++) {
            HTTP *client = &http[i];
            if (client->sock == SS_INVALID) continue;
            if ((uint32_t)(now - client->started) >= HTTP_MS) { CLOSE_HTTP(client); continue; }
            if (client->size > 0 && (sockets[i + 2].ready & (SS_WRITE | SS_ERROR))) WRITE_HTTP(client);
            else if (sockets[i + 2].ready & (SS_READ | SS_ERROR)) READ_HTTP(client);
        }
        if (sockets[0].ready & SS_ERROR) goto cleanup;
        if (sockets[0].ready & SS_READ) {
            SS_SOCKET sock = accept(listener, NULL, NULL);
            if (sock == SS_INVALID) continue;
            int slot = 0;
            while (slot < HTTP_CLIENTS && http[slot].sock != SS_INVALID) slot++;
            if (slot == HTTP_CLIENTS || !SS_NONBLOCK(sock)) SS_CLOSE(sock);
            else { http[slot].sock = sock; http[slot].started = SS_TICKS(); }
        }
    }
    result = 0;
cleanup:
    for (int i = 0; i < HTTP_CLIENTS; i++) CLOSE_HTTP(&http[i]);
    SS_END_CLIENT(&connection); SS_CLOSE(listener);
    SS_WIPE(inbox, sizeof(inbox)); SS_WIPE(&guard, sizeof(guard)); SS_WIPE(relay_public, sizeof(relay_public));
    SS_NET_END(); return result;
}
