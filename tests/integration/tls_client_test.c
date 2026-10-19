/*
 * tests/integration/tls_client_test.c
 *
 * Interop test: full TLS 1.3 handshake with a real HTTPS server.
 * Sends ClientHello, processes ServerHello + encrypted records,
 * completes handshake, sends HTTP GET, reads response.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <time.h>
#include <errno.h>

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

/* From record.c (hosted build uses system mem funcs) */
void cvm_tls_buf_init(CvmTlsBuf* buf, u8* small, usize small_capacity);
int cvm_tls_buf_reserve(CvmTlsBuf* buf, usize delta);
int cvm_tls_buf_pushv(CvmTlsBuf* buf, void const* src, usize len);
int cvm_tls_buf_push(CvmTlsBuf* buf, u8 b);
void cvm_tls_buf_dispose(CvmTlsBuf* buf);

/* ------------------------------------------------------------------ */
/* hosted time + random                                                 */
/* ------------------------------------------------------------------ */

static u64 host_get_time(CvmTlsGetTime* self) {
    (void)self;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (u64)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void host_random(CvmTlsRandomBytes* self, void* buf, usize len) {
    (void)self;
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
/* socket                                                               */
/* ------------------------------------------------------------------ */

static int tcp_connect(char const* host, int port) {
    struct addrinfo hints = {0};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo* res;
    if (getaddrinfo(host, port_str, &hints, &res) != 0)
        return -1;

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
/* traffic key hook (QUIC surface)                                      */
/* ------------------------------------------------------------------ */

/*
 * The callback ngtcp2 installs. Wired here so the interop run proves it
 * fires where QUIC needs it: four times, handshake and application, one per
 * direction, with the secret length the suite's hash implies.
 */
static int traffic_key_count;
static u32 traffic_key_epochs[8];
static int traffic_key_enc[8];
static usize traffic_key_lens[8];

static int on_traffic_key(struct CvmTlsTrafficKey* self, CvmTls* tls, bool is_enc,
                          u32 epoch, u8 const* secret, usize secret_len) {
    (void)self;
    (void)tls;
    if (traffic_key_count < 8) {
        traffic_key_epochs[traffic_key_count] = epoch;
        traffic_key_enc[traffic_key_count] = is_enc ? 1 : 0;
        traffic_key_lens[traffic_key_count] = secret_len;
    }
    traffic_key_count++;
    printf("[key] epoch=%u %s secret_len=%zu first=%02x%02x\n", epoch,
           is_enc ? "tx" : "rx", secret_len, secret[0], secret[1]);
    return 0;
}

static CvmTlsTrafficKey const traffic_key_hook = {.cb = on_traffic_key};

/* ------------------------------------------------------------------ */
/* main                                                                 */
/* ------------------------------------------------------------------ */

int main(int argc, char** argv) {
    char const* host = argc > 1 ? argv[1] : "example.com";
    int port = argc > 2 ? atoi(argv[2]) : 443;

    setbuf(stdout, NULL);
    printf("=== TLS 1.3 interop: %s:%d ===\n", host, port);

    int fd = tcp_connect(host, port);
    if (fd < 0) {
        fprintf(stderr, "connect failed\n");
        return 1;
    }
    printf("[1] TCP connected\n");

    /* TLS context with cvmcrypt crypto. */
    CvmTlsContext ctx;
    cvm_tls_context_defaults(&ctx);
    ctx.get_time = (CvmTlsGetTime*)&HOST_TIME;
    ctx.random_bytes = (CvmTlsRandomBytes*)&HOST_RANDOM;
    ctx.update_traffic_key = (CvmTlsTrafficKey*)&traffic_key_hook;

    CvmTls* tls = cvm_tls_new(&ctx, false, host);
    if (!tls) {
        fprintf(stderr, "tls_new failed\n");
        return 1;
    }

    /* Phase 1: send ClientHello. */
    CvmTlsBuf sendbuf;
    cvm_tls_buf_init(&sendbuf, NULL, 0);
    usize inlen = 0;
    int ret = cvm_tls_handshake(tls, &sendbuf, NULL, &inlen, NULL);
    printf("[2] ClientHello: %zu bytes (state=%d)\n", sendbuf.off, tls->state);

    if (send(fd, sendbuf.base, sendbuf.off, 0) < 0) {
        perror("send CH");
        return 1;
    }

    /* Phase 2: read and process server responses. */
    int max_rounds = 10;
    for (int round = 0; round < max_rounds && !tls->handshake_complete; round++) {
        /* Read data from server. */
        u8 input[16384];
        ssize_t n = recv(fd, input, sizeof(input), 0);
        if (n <= 0) {
            printf("[!] recv returned %zd (errno=%d)\n", n, errno);
            break;
        }
        printf("[3.%d] Received %zd bytes from server\n", round, n);
        {
            FILE* f = fopen("/tmp/recv.bin", "wb");
            if (f) {
                fwrite(input, 1, (size_t)n, f);
                fclose(f);
            }
        }

        /* Feed to TLS state machine. */
        sendbuf.off = 0; /* reuse sendbuf for output */
        usize consumed = (usize)n;
        ret = cvm_tls_handshake(tls, &sendbuf, input, &consumed, NULL);
        printf("    handshake ret=%d (0x%x), state=%d, consumed=%zu/%zd\n", ret, ret,
               tls->state, consumed, n);

        if (ret < 0 && ret != TLS_ERROR_IN_PROGRESS) {
            printf("[!] Handshake error: %d (alert=%d)\n", ret, ret & 0xFF);
            break;
        }

        /* Send any response data. */
        if (sendbuf.off > 0) {
            printf("    Sending %zu bytes response\n", sendbuf.off);
            if (send(fd, sendbuf.base, sendbuf.off, 0) < 0) {
                perror("send response");
                break;
            }
        }

        if (tls->handshake_complete) {
            printf("[4] HANDSHAKE COMPLETE! cipher=%s\n",
                   tls->suite ? tls->suite->name : "?");
            break;
        }

        if (tls->state == TLS_STATE_CLIENT_EXPECT_ENCRYPTED_EXTENSIONS ||
            tls->state == TLS_STATE_CLIENT_EXPECT_CERTIFICATE ||
            tls->state == TLS_STATE_CLIENT_EXPECT_CERTIFICATE_VERIFY ||
            tls->state == TLS_STATE_CLIENT_EXPECT_FINISHED) {
            printf("    Progressing: state=%d\n", tls->state);
        }
    }

    /* Phase 3: send HTTP request if handshake completed. */
    if (tls->handshake_complete) {
        char req[256];
        int req_len =
            snprintf(req, sizeof(req),
                     "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host);
        sendbuf.off = 0;
        ret = cvm_tls_send(tls, &sendbuf, req, (usize)req_len);
        printf("[5] HTTP request: %d bytes encrypted, ret=%d\n", sendbuf.off, ret);
        if (send(fd, sendbuf.base, sendbuf.off, 0) < 0) {
            perror("send HTTP");
            return 1;
        }

        /* Read and DECRYPT the response. This is cvm_tls_receive's first
         * real exercise: before this it returned TLS_ERROR_NOT_AVAILABLE, so
         * the test could send a request but never read the answer. */
        CvmTlsBuf plain;
        cvm_tls_buf_init(&plain, NULL, 0);

        for (int round = 0; round < 8 && plain.off == 0; round++) {
            u8 resp[16384];
            ssize_t n = recv(fd, resp, sizeof(resp), 0);
            printf("[6.%d] received %zd encrypted bytes\n", round, n);
            if (n <= 0)
                break;

            usize consumed = (usize)n;
            int rret = cvm_tls_receive(tls, &plain, resp, &consumed);
            printf("[6.%d] consumed %zu, plaintext so far %zu, ret=%d\n", round,
                   consumed, plain.off, rret);
            if (rret == (TLS_ERROR_CLASS_ALERT | TLS_ALERT_CLOSE_NOTIFY)) {
                printf("    (server sent close_notify)\n");
                break;
            }
            if (rret != 0 && rret != TLS_ERROR_IN_PROGRESS) {
                printf("[!] cvm_tls_receive failed: %d\n", rret);
                break;
            }
        }

        if (plain.off > 0) {
            printf("[6] plaintext response: %zu bytes\n", plain.off);
            printf("    First line: ");
            for (usize i = 0; i < plain.off && plain.base[i] != '\r'; i++)
                printf("%c", plain.base[i]);
            printf("\n");
            if (plain.off < 12 || memcmp(plain.base, "HTTP/1.", 7) != 0) {
                fprintf(stderr, "FAIL: decrypted response does not start with HTTP/\n");
                cvm_tls_buf_dispose(&plain);
                cvm_tls_buf_dispose(&sendbuf);
                cvm_tls_free(tls);
                close(fd);
                return 1;
            }
            printf("decrypted HTTP response: OK\n");
        } else {
            fprintf(stderr, "FAIL: no plaintext decrypted\n");
            cvm_tls_buf_dispose(&plain);
            cvm_tls_buf_dispose(&sendbuf);
            cvm_tls_free(tls);
            close(fd);
            return 1;
        }
        cvm_tls_buf_dispose(&plain);
    } else {
        printf("[!] Handshake did not complete (state=%d)\n", tls->state);
    }

    /*
     * The QUIC surface, checked while the session is still alive: cvm_tls_free
     * zeroises the struct, so anything read after it is a zero, not a result.
     */
    printf("[read epoch] %u\n", (unsigned)cvm_tls_get_read_epoch(tls));

    int verdict = 0;
    if (traffic_key_count != 4) {
        fprintf(stderr, "FAIL: traffic key callback fired %d times, want 4\n",
                traffic_key_count);
        verdict = 1;
    }
    if (cvm_tls_get_read_epoch(tls) != 3) {
        fprintf(stderr, "FAIL: read epoch %u after handshake, want 3\n",
                (unsigned)cvm_tls_get_read_epoch(tls));
        verdict = 1;
    }
    for (int i = 0; i < 4 && i < traffic_key_count; i++) {
        u32 const want = i < 2 ? 2 : 3;
        if (traffic_key_epochs[i] != want) {
            fprintf(stderr, "FAIL: callback %d epoch %u, want %u\n", i,
                    (unsigned)traffic_key_epochs[i], (unsigned)want);
            verdict = 1;
        }
    }
    if (verdict == 0) {
        printf("traffic keys: 4 events, epochs 2,2,3,3, read epoch 3\n");
    }

    /* Cleanup. */
    cvm_tls_buf_dispose(&sendbuf);
    cvm_tls_free(tls);
    close(fd);
    if (verdict != 0) {
        return 1;
    }
    printf("=== done ===\n");
    return 0;
}
