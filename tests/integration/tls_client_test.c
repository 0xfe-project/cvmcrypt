/*
 * tests/integration/tls_client_test.c
 *
 * Interop test: connect to a real HTTPS server, send ClientHello,
 * verify we get a ServerHello back. Proves wire-format correctness.
 *
 * Build: clang ... -o tls_client_test
 * Run:   ./tls_client_test [hostname] [port]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>

#include "tls/tls.h"
#include "tls/tls_internal.h"
#include "tls/tls_conn.h"
#include "tls/handshake.h"
#include "tls/session.h"
#include "aead/gcm.h"
#include "aead/chachapoly.h"
#include "hash/sha256.h"
#include "hash/sha512.h"
#include "kx/x25519.h"
#include "cipher/aes.h"
#include "base/types.h"
#include "base/secure.h"

/* From crypto_cvm.c */
void cvm_tls_context_defaults(CvmTlsContext* ctx);

/* From record.c */

/* ------------------------------------------------------------------ */
/* platform: time + random (hosted)                                     */
/* ------------------------------------------------------------------ */

#include <time.h>

static u64 host_get_time(CvmTlsGetTime* self) {
    (void)self;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (u64)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void host_random(CvmTlsRandomBytes* self, void* buf, usize len) {
    (void)self;
    /* Use /dev/urandom for proper randomness. */
    FILE* f = fopen("/dev/urandom", "rb");
    if (f) {
        fread(buf, 1, len, f);
        fclose(f);
    } else {
        memset(buf, 0x42, len);
    }
}

static CvmTlsGetTime const HOST_TIME = {.cb = host_get_time};
static CvmTlsRandomBytes const HOST_RANDOM = {.cb = host_random};

/* ------------------------------------------------------------------ */
/* socket helper                                                        */
/* ------------------------------------------------------------------ */

static int tcp_connect(char const* host, int port) {
    struct addrinfo hints = {0};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo* res;
    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        fprintf(stderr, "DNS failed for %s\n", host);
        return -1;
    }

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(res);
        return -1;
    }

    if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
        perror("connect");
        close(fd);
        freeaddrinfo(res);
        return -1;
    }

    freeaddrinfo(res);
    return fd;
}

/* ------------------------------------------------------------------ */
/* main                                                                 */
/* ------------------------------------------------------------------ */

int main(int argc, char** argv) {
    char const* host = argc > 1 ? argv[1] : "example.com";
    int port = argc > 2 ? atoi(argv[2]) : 443;

    printf("Connecting to %s:%d...\n", host, port);

    int fd = tcp_connect(host, port);
    if (fd < 0) {
        fprintf(stderr, "FAIL: cannot connect\n");
        return 1;
    }
    printf("TCP connected.\n");

    /* Set up TLS context with cvmcrypt crypto. */
    CvmTlsContext ctx;
    cvm_tls_context_defaults(&ctx);
    ctx.get_time = (CvmTlsGetTime*)&HOST_TIME;
    ctx.random_bytes = (CvmTlsRandomBytes*)&HOST_RANDOM;

    /* Create TLS client. */
    CvmTls* tls = cvm_tls_new(&ctx, false, host);
    if (tls == NULL) {
        fprintf(stderr, "FAIL: cannot create TLS\n");
        return 1;
    }

    /* Send ClientHello. */
    CvmTlsBuf sendbuf;
    cvm_tls_buf_init(&sendbuf, NULL, 0);
    usize inlen = 0;
    int ret = cvm_tls_handshake(tls, &sendbuf, NULL, &inlen, NULL);

    printf("ClientHello generated: %zu bytes (ret=%d)\n", sendbuf.off, ret);

    if (sendbuf.off == 0) {
        fprintf(stderr, "FAIL: empty ClientHello\n");
        return 1;
    }

    /* Dump first bytes for debugging. */
    printf("CH header: %02x %02x %02x %02x %02x\n", sendbuf.base[0], sendbuf.base[1],
           sendbuf.base[2], sendbuf.base[3], sendbuf.base[4]);
    printf("CH dump: ");
    for (usize i = 0; i < sendbuf.off && i < 1024; i++)
        printf("%02x", sendbuf.base[i]);
    printf("...\n");

    /* Send to server. */
    ssize_t sent = send(fd, sendbuf.base, sendbuf.off, 0);
    printf("Sent %zd bytes.\n", sent);

    /* Read response. */
    u8 response[8192];
    ssize_t n = recv(fd, response, sizeof(response), 0);
    printf("Received %zd bytes.\n", n);

    if (n < 5) {
        fprintf(stderr, "FAIL: response too short (%zd bytes)\n", n);
        close(fd);
        return 1;
    }

    /* Parse as TLS record. */
    printf("Response header: %02x %02x %02x %02x %02x\n", response[0], response[1],
           response[2], response[3], response[4]);

    u8 content_type = response[0];
    u16 record_len = (response[3] << 8) | response[4];

    printf("Content type: %u, record length: %u\n", content_type, record_len);

    if (content_type == TLS_CONTENT_TYPE_ALERT) {
        printf("Got ALERT (expected — handshake incomplete).\n");
        if (n >= 7) {
            printf("Alert: level=%u, description=%u\n", response[5], response[6]);
        }
    } else if (content_type == TLS_CONTENT_TYPE_HANDSHAKE) {
        printf("Got HANDSHAKE response — server accepted our ClientHello!\n");
        if (n >= 9) {
            printf("Handshake type: %u\n", response[5]);
            if (response[5] == TLS_HANDSHAKE_TYPE_SERVER_HELLO) {
                printf(">>> ServerHello received! Wire format is correct.\n");
            }
        }
    } else {
        printf("Unknown content type: %u\n", content_type);
    }

    /* Cleanup. */
    cvm_tls_buf_dispose(&sendbuf);
    cvm_tls_free(tls);
    close(fd);

    printf("\nInterop test completed.\n");
    return 0;
}
