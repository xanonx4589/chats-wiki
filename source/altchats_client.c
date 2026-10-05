#include "altchats_session.h"
#include <stdio.h>
#ifdef _WIN32
#include <process.h>
static CRITICAL_SECTION mutex;
#define LOCK() EnterCriticalSection(&mutex)
#define UNLOCK() LeaveCriticalSection(&mutex)
#define THREAD_RESULT unsigned __stdcall
#define THREAD_END 0
#else
#include <pthread.h>
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
#define LOCK() pthread_mutex_lock(&mutex)
#define UNLOCK() pthread_mutex_unlock(&mutex)
#define THREAD_RESULT void *
#define THREAD_END NULL
#endif
static SS_CLIENT connection;
static int ended;
static void PRINT_TEXT(const uint8_t *p, int length) {
    for (int i = 0; i < length; i++) {
        unsigned char c = p[i];
        putchar((c < 32 && c != '\n' && c != '\t') || c == 127 ? '?' : c);
    }
}
static void EVENT(void *context, unsigned type, uint32_t id, const uint8_t *name, int n, const uint8_t *text, int length) {
    (void)context;
    if (type == SS_EVENT_SELF) printf("\nJoined as #%lu.\n", (unsigned long)id);
    else if (type == SS_EVENT_JOIN) printf("\n#%lu joined.\n", (unsigned long)id);
    else if (type == SS_EVENT_LEAVE) printf("\n#%lu left.\n", (unsigned long)id);
    else if (type == SS_EVENT_STATE) {
        unsigned stage = length ? (unsigned)(text[0] - '0') : 0;
        if (stage == SS_DM_INVITED) printf("\nDM invitation from #%lu. Type /accept %lu or /close %lu.\n", (unsigned long)id, (unsigned long)id, (unsigned long)id);
        else if (stage == SS_DM_READY) printf("\nEncrypted DM with #%lu ready. /dm %lu selects it; /lobby returns to the lobby.\n", (unsigned long)id, (unsigned long)id);
        else if (!stage) printf("\nDM with #%lu ended.\n", (unsigned long)id);
        else printf("\nDM with #%lu: waiting for acceptance/key confirmation.\n", (unsigned long)id);
    } else if (type == SS_EVENT_LOBBY || type == SS_EVENT_DM) {
        printf(type == SS_EVENT_DM ? "\n> [DM #%lu] " : "\n> [#%lu] ", (unsigned long)id);
        if (n) { PRINT_TEXT(name, n); printf(": "); }
        PRINT_TEXT(text, length);
        if (!length || text[length - 1] != '\n') putchar('\n');
    }
    fflush(stdout);
}
static THREAD_RESULT RECEIVE(void *argument) {
    (void)argument;
    while (1) {
        LOCK();
        if (ended || connection.sock == SS_INVALID) { UNLOCK(); break; }
        SS_POLL socket = {connection.sock, SS_READ | (connection.pending ? SS_WRITE : 0), 0};
        UNLOCK();
        int ok = SS_WAIT(&socket, 1, 100);
        LOCK();
        if (!ended && connection.sock == socket.sock && (ok < 0 || !SS_CLIENT_IO(&connection, socket.ready))) {
            ended = 1; printf("\nConnection ended. Press Enter to exit.\n"); fflush(stdout);
        }
        UNLOCK();
    }
    return THREAD_END;
}
static int ID(const char *value, uint32_t *out) {
    while (*value == ' ' || *value == '\t') value++;
    if (*value < '0' || *value > '9') return 0;
    uint32_t id = 0;
    while (*value >= '0' && *value <= '9') {
        unsigned digit = (unsigned)(*value++ - '0');
        if (id > (UINT32_MAX - digit) / 10) return 0;
        id = id * 10 + digit;
    }
    while (*value == ' ' || *value == '\t' || *value == '\r' || *value == '\n') value++;
    if (*value || !id) return 0;
    *out = id; return 1;
}
int main(int argc, char *argv[]) {
    if (argc != 2 && argc != 3) { printf("Usage: altchats_client RELAY_HOST [RELAY_PUBLIC_KEY|OPEN]\n"); return 1; }
    uint8_t relay_public[32];
    int mode = SS_RELAY_KEY(relay_public, argc == 3 ? argv[2] : "OPEN");
    if (!mode) { fprintf(stderr, "Use OPEN, or the relay's 64-digit public key from a trusted source.\n"); return 1; }
    unsigned relay_port;
    if (!SS_READ_PORT("Relay port", ALTCHATS_PORT, &relay_port)) return 1;
    if (!SS_NET_START()) return 1;
#ifdef _WIN32
    InitializeCriticalSection(&mutex);
#endif
    int connected = SS_CONNECT_CLIENT(&connection, argv[1], relay_port, relay_public, EVENT, NULL);
    if (!connected) {
        fprintf(stderr, "Relay connection/authentication failed. No unverified fallback.\n");
        SS_NET_END(); return 1;
    }
    printf("%s DMs trust this relay to introduce peers correctly.\n"
        "/display NAME, /peers, /dm ID, /accept ID, /close ID, /lobby, /exit\n",
        mode == 2 ? "OPEN relay. Identity not verified." : "Relay verified.");
#ifdef _WIN32
    HANDLE worker = (HANDLE)_beginthreadex(NULL, 0, RECEIVE, NULL, 0, NULL);
    if (!worker) { SS_END_CLIENT(&connection); SS_NET_END(); DeleteCriticalSection(&mutex); return 1; }
#else
    pthread_t worker;
    if (pthread_create(&worker, NULL, RECEIVE, NULL)) { SS_END_CLIENT(&connection); SS_NET_END(); return 1; }
#endif
    char input[SS_MESSAGE_MAX + 1] = {0}, display[SS_NAME_MAX + 1] = {0};
    uint32_t target = 0;
    while (1) {
        LOCK(); int done = ended; UNLOCK();
        if (done) break;
        if (target) printf("[DM #%lu] ", (unsigned long)target);
        if (*display) printf("%s (Me): ", display); else printf("(Me): ");
        fflush(stdout);
        if (!fgets(input, sizeof(input), stdin)) break;
        if (!strchr(input, '\n') && strlen(input) == sizeof(input) - 1) {
            int extra = getchar();
            if (extra != EOF) {
                while (extra != '\n' && extra != EOF) extra = getchar();
                SS_WIPE(input, sizeof(input)); printf("Message too long. Nothing sent.\n"); continue;
            }
        }
        if (!strcmp(input, "/exit\n") || !strcmp(input, "/exit")) break;
        if (!strncmp(input, "/display", 8) && (!input[8] || strchr(" \t\r\n", input[8]))) {
            char *name = input + 8;
            while (*name == ' ' || *name == '\t') name++;
            size_t n = strcspn(name, "\r\n");
            if (n > SS_NAME_MAX) printf("Display name too long (%d bytes maximum).\n", SS_NAME_MAX);
            else {
                LOCK(); int ok = SS_SET_NAME(&connection, (const uint8_t *)name, (int)n); UNLOCK();
                if (ok) { SS_WIPE(display, sizeof(display)); memcpy(display, name, n); }
                else printf("Display name could not be updated.\n");
            }
        } else if (!strcmp(input, "/lobby\n") || !strcmp(input, "/lobby")) target = 0;
        else if (!strcmp(input, "/peers\n") || !strcmp(input, "/peers")) {
            LOCK();
            printf("Connected peers:");
            for (unsigned i = 0; i < SS_CLIENT_MAX; i++) if (connection.members[i].id) printf(" #%lu", (unsigned long)connection.members[i].id);
            printf("\n"); UNLOCK();
        } else if (!strncmp(input, "/dm ", 4) || !strncmp(input, "/accept ", 8) || !strncmp(input, "/close ", 7)) {
            uint32_t peer;
            int action = !strncmp(input, "/dm ", 4) ? 1 : !strncmp(input, "/accept ", 8) ? 2 : 3;
            if (!ID(input + (action == 1 ? 4 : action == 2 ? 8 : 7), &peer)) printf("Enter a connected peer's numeric ID.\n");
            else {
                LOCK(); int ok;
                if (action == 1) ok = SS_DM_STATE(&connection, peer) != SS_DM_FREE || SS_START_DM(&connection, peer);
                else if (action == 2) ok = SS_ACCEPT_DM(&connection, peer);
                else ok = SS_CLOSE_DM(&connection, peer);
                UNLOCK();
                if (!ok) printf("DM action unavailable; check the peer, session state and buffer space.\n");
                else if (action != 3) target = peer;
                else if (target == peer) target = 0;
            }
        } else {
            LOCK();
            int ok = !ended && SS_SEND_TEXT(&connection, target, (const uint8_t *)display, (int)strlen(display),
                (const uint8_t *)input, (int)strlen(input));
            UNLOCK();
            if (!ok) printf("Nothing sent. Wait for the lobby/DM to be ready, or shorten the message and try again.\n");
        }
        SS_WIPE(input, sizeof(input));
    }
    SS_WIPE(input, sizeof(input)); SS_WIPE(display, sizeof(display));
    uint32_t closing = SS_TICKS();
    while ((uint32_t)(SS_TICKS() - closing) < 5000) {
        LOCK();
        if (ended || !connection.pending) { UNLOCK(); break; }
        SS_POLL socket = {connection.sock, SS_READ | SS_WRITE, 0};
        if (SS_WAIT(&socket, 1, 100) < 0 || !SS_CLIENT_IO(&connection, socket.ready)) ended = 1;
        UNLOCK();
    }
    LOCK(); ended = 1; SS_END_CLIENT(&connection); UNLOCK();
#ifdef _WIN32
    WaitForSingleObject(worker, INFINITE); CloseHandle(worker); DeleteCriticalSection(&mutex);
#else
    pthread_join(worker, NULL); pthread_mutex_destroy(&mutex);
#endif
    SS_WIPE(relay_public, sizeof(relay_public)); SS_NET_END();
    return 0;
}
