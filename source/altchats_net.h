#ifndef ALTCHATS_NET_H
#define ALTCHATS_NET_H
#ifndef _WIN32
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif
#define FD_SETSIZE 1024
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>
typedef SOCKET SS_SOCKET;
#define SS_INVALID INVALID_SOCKET
#define SS_SHUT SD_BOTH
#define SS_SHUT_WRITE SD_SEND
static inline int SS_NET_START(void) { WSADATA data; return WSAStartup(MAKEWORD(2, 2), &data) == 0; }
static inline void SS_NET_END(void) { WSACleanup(); }
static inline void SS_CLOSE(SS_SOCKET s) { if (s != SS_INVALID) closesocket(s); }
static inline uint32_t SS_TICKS(void) { return GetTickCount(); }
static inline int SS_RETRY(void) {
    int e = WSAGetLastError();
    return e == WSAEWOULDBLOCK || e == WSAEINTR;
}
static inline int SS_BIND_RETRY(void) { int e = WSAGetLastError(); return e == WSAEADDRINUSE || e == WSAEACCES; }
static inline int SS_NONBLOCK(SS_SOCKET s) { u_long value = 1; return ioctlsocket(s, FIONBIO, &value) == 0; }
static inline int SS_LISTENER_OPTIONS(SS_SOCKET s) {
    BOOL value = TRUE;
    return setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&value, sizeof(value)) == 0;
}
static inline int SS_RANDOM(uint8_t *out, size_t length) {
    HCRYPTPROV provider;
    if (length > UINT32_MAX || !CryptAcquireContextA(&provider, NULL, NULL, PROV_RSA_FULL,
        CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) return 0;
    int ok = CryptGenRandom(provider, (DWORD)length, out) != 0;
    CryptReleaseContext(provider, 0);
    return ok;
}
static inline int SS_CONNECT_PENDING(void) { int e = WSAGetLastError(); return e == WSAEWOULDBLOCK || e == WSAEINPROGRESS; }
static inline int SS_CONNECT_ERROR(SS_SOCKET s) {
    int error = 0, size = sizeof(error);
    return getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&error, &size) == 0 && !error;
}
static inline int SS_SEND(SS_SOCKET s, const void *p, int n) { return send(s, (const char *)p, n, 0); }
static inline int SS_RECV(SS_SOCKET s, void *p, int n) { return recv(s, (char *)p, n, 0); }
#else
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
typedef int SS_SOCKET;
#define SS_INVALID (-1)
#define SS_SHUT SHUT_RDWR
#define SS_SHUT_WRITE SHUT_WR
static inline int SS_NET_START(void) { return 1; }
static inline void SS_NET_END(void) { }
static inline void SS_CLOSE(SS_SOCKET s) { if (s != SS_INVALID) close(s); }
static inline uint32_t SS_TICKS(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) exit(EXIT_FAILURE);
    return (uint32_t)((uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000);
}
static inline int SS_RETRY(void) { return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR; }
static inline int SS_BIND_RETRY(void) { return errno == EADDRINUSE || errno == EACCES; }
static inline int SS_NONBLOCK(SS_SOCKET s) { int flags = fcntl(s, F_GETFL, 0); return flags >= 0 && fcntl(s, F_SETFL, flags | O_NONBLOCK) == 0; }
static inline int SS_LISTENER_OPTIONS(SS_SOCKET s) {
    int value = 1;
    return setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value)) == 0;
}
static inline int SS_RANDOM(uint8_t *out, size_t length) {
#ifdef SYS_getrandom
    while (length) {
        ssize_t n = syscall(SYS_getrandom, out, length, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && errno == ENOSYS) break;
        if (n <= 0) return 0;
        out += n; length -= (size_t)n;
    }
    if (!length) return 1;
#endif
    int source = open("/dev/random", O_RDONLY);
    if (source < 0) return 0;
    struct pollfd ready = {source, POLLIN, 0};
    int result;
    do { result = poll(&ready, 1, -1); } while (result < 0 && errno == EINTR);
    close(source);
    if (result <= 0 || !(ready.revents & POLLIN) || (ready.revents & (POLLERR | POLLHUP | POLLNVAL))) return 0;
    source = open("/dev/urandom", O_RDONLY);
    if (source < 0) return 0;
    while (length) {
        ssize_t n = read(source, out, length);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { close(source); return 0; }
        out += n; length -= (size_t)n;
    }
    close(source);
    return 1;
}
static inline int SS_CONNECT_PENDING(void) { return errno == EINPROGRESS || errno == EINTR; }
static inline int SS_CONNECT_ERROR(SS_SOCKET s) {
    int error = 0;
    socklen_t size = sizeof(error);
    return getsockopt(s, SOL_SOCKET, SO_ERROR, &error, &size) == 0 && !error;
}
static inline int SS_SEND(SS_SOCKET s, const void *p, int n) { return (int)send(s, p, (size_t)n, MSG_NOSIGNAL); }
static inline int SS_RECV(SS_SOCKET s, void *p, int n) { return (int)recv(s, p, (size_t)n, 0); }
#endif
static inline int SS_READ_PORT(const char *label, unsigned fallback, unsigned *port) {
    char input[32];
    while (1) {
        printf("%s [%u]: ", label, fallback); fflush(stdout);
        if (!fgets(input, sizeof(input), stdin)) return 0;
        int full = !strchr(input, '\n') && strlen(input) == sizeof(input) - 1;
        if (full) { int c; do { c = getchar(); } while (c != '\n' && c != EOF); }
        input[strcspn(input, "\r\n")] = 0;
        char *value = input;
        while (*value == ' ' || *value == '\t') value++;
        if (!full && !*value) { *port = fallback; return fallback >= 1 && fallback <= 65535; }
        char *end;
        unsigned long number = strtoul(value, &end, 10);
        while (*end == ' ' || *end == '\t') end++;
        if (!full && *value >= '0' && *value <= '9' && !*end && number >= 1 && number <= 65535) {
            *port = (unsigned)number; return 1;
        }
        printf("Enter a port from 1-65535, or press Enter for %u.\n", fallback);
    }
}
static inline SS_SOCKET SS_LISTEN(uint32_t host, unsigned *port, int backlog) {
    if (*port < 1 || *port > 65535) return SS_INVALID;
    if (*port < 1024) printf("Low ports may require extra permissions or already belong to other services.\n");
    for (unsigned candidate = *port; candidate <= 65535; candidate++) {
        SS_SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == SS_INVALID) return SS_INVALID;
        if (!SS_LISTENER_OPTIONS(sock)) { SS_CLOSE(sock); return SS_INVALID; }
        struct sockaddr_in address = {0};
        address.sin_family = AF_INET; address.sin_port = htons((uint16_t)candidate); address.sin_addr.s_addr = htonl(host);
        if (!bind(sock, (struct sockaddr *)&address, sizeof(address)) && !listen(sock, backlog)) {
            if (!SS_NONBLOCK(sock)) { SS_CLOSE(sock); return SS_INVALID; }
            *port = candidate; return sock;
        }
        int retry = SS_BIND_RETRY(); SS_CLOSE(sock);
        if (!retry) return SS_INVALID;
    }
    return SS_INVALID;
}
#define SS_READ 1
#define SS_WRITE 2
#define SS_ERROR 4
typedef struct { SS_SOCKET sock; int events, ready; } SS_POLL;
static inline int SS_WAIT(SS_POLL *items, int count, int timeout) {
#ifdef _WIN32
    fd_set reading, writing, errors;
    FD_ZERO(&reading); FD_ZERO(&writing); FD_ZERO(&errors);
    for (int i = 0; i < count; i++) {
        items[i].ready = 0;
        if (items[i].sock == SS_INVALID || !items[i].events) continue;
        if (items[i].events & SS_READ) FD_SET(items[i].sock, &reading);
        if (items[i].events & SS_WRITE) FD_SET(items[i].sock, &writing);
        FD_SET(items[i].sock, &errors);
    }
    struct timeval wait = {timeout / 1000, (timeout % 1000) * 1000};
    int result = select(0, &reading, &writing, &errors, &wait);
    if (result < 0) return SS_RETRY() ? 0 : -1;
    for (int i = 0; i < count; i++) {
        if (items[i].sock == SS_INVALID || !items[i].events) continue;
        if (FD_ISSET(items[i].sock, &reading)) items[i].ready |= SS_READ;
        if (FD_ISSET(items[i].sock, &writing)) items[i].ready |= SS_WRITE;
        if (FD_ISSET(items[i].sock, &errors)) items[i].ready |= SS_ERROR;
    }
#else
    struct pollfd ready[1024];
    if (count > 1024) return -1;
    for (int i = 0; i < count; i++) {
        items[i].ready = 0;
        ready[i].fd = items[i].events ? items[i].sock : -1;
        ready[i].events = (items[i].events & SS_READ ? POLLIN : 0) | (items[i].events & SS_WRITE ? POLLOUT : 0);
        ready[i].revents = 0;
    }
    int result = poll(ready, (nfds_t)count, timeout);
    if (result < 0) return errno == EINTR ? 0 : -1;
    for (int i = 0; i < count; i++) {
        if (ready[i].revents & POLLIN) items[i].ready |= SS_READ;
        if (ready[i].revents & POLLOUT) items[i].ready |= SS_WRITE;
        if (ready[i].revents & (POLLERR | POLLHUP | POLLNVAL)) items[i].ready |= SS_ERROR;
    }
#endif
    return result;
}
static inline int SS_HEX_PARSE(uint8_t out[32], const char *value) {
    unsigned count = 0;
    memset(out, 0, 32);
    for (; *value; value++) {
        unsigned char c = (unsigned char)*value;
        unsigned digit;
        if (c == '-' || c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
        if (c >= '0' && c <= '9') digit = c - '0';
        else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
        else return 0;
        if (count >= 64) return 0;
        out[count / 2] = (uint8_t)((out[count / 2] << 4) | digit);
        count++;
    }
    return count == 64;
}
static inline void SS_HEX(char out[65], const uint8_t value[32]) {
    static const char digits[] = "0123456789abcdef";
    for (unsigned i = 0; i < 32; i++) { out[2 * i] = digits[value[i] >> 4]; out[2 * i + 1] = digits[value[i] & 15]; }
    out[64] = 0;
}
#endif
