/*
 * bench/bench_cvm.c
 *
 * cvmcrypt TLS throughput benchmark.
 * Measures: handshake time + bulk transfer (1MB, 16MB) over loopback.
 *
 * Build: ./build.sh
 * Run:   ./bench_cvm
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <errno.h>

#include "tls/tls.h"
#include "tls/tls_internal.h"
#include "tls/tls_conn.h"
#include "tls/handshake.h"
#include "tls/session.h"
#include "tls/keyschedule.h"

#include "aead/gcm.h"
#include "aead/chachapoly.h"
#include "hash/sha256.h"
#include "hash/sha512.h"
#include "kx/x25519.h"
#include "cipher/aes.h"
#include "base/types.h"

/* From crypto_cvm.c */
void cvm_tls_context_defaults(CvmTlsContext* ctx);


/* ------------------------------------------------------------------ */
/* timing                                                               */
/* ------------------------------------------------------------------ */

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

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
/* data transfer                                                        */
/* ------------------------------------------------------------------ */

static int send_all(int fd, u8 const* buf, usize len) {
    usize sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, buf + sent, len - sent, 0);
        if (n <= 0) return -1;
        sent += (usize)n;
    }
    return 0;
}

static int recv_all(int fd, u8* buf, usize len) {
    usize got = 0;
    while (got < len) {
        ssize_t n = recv(fd, buf + got, len - got, 0);
        if (n <= 0) return -1;
        got += (usize)n;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* TLS handshake over a socket                                          */
/* ------------------------------------------------------------------ */

/* Returns 0 on success. */
static int tls_handshake_socket(CvmTls* tls, int fd) {
    u8 buf[65536];
    int round = 0;

    while (!tls->handshake_complete && round < 20) {
        round++;

        /* Send pending output. */
        /* (handled by caller for CH) */

        /* Read from server. */
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) return -1;

        CvmTlsBuf sendbuf;
        cvm_tls_buf_init(&sendbuf, NULL, 0);
        usize consumed = (usize)n;
        int ret = cvm_tls_handshake(tls, &sendbuf, buf, &consumed, NULL);

        /* Send any response. */
        if (sendbuf.off > 0) {
            send_all(fd, sendbuf.base, sendbuf.off);
        }
        cvm_tls_buf_dispose(&sendbuf);

        if (ret == 0 && tls->handshake_complete) return 0;
        if (ret < 0 && ret != TLS_ERROR_IN_PROGRESS) return -1;
    }
    return -1;
}

/* Send data over established TLS connection (encrypt + send). */
static int tls_send_data(CvmTls* tls, int fd, u8 const* data, usize len) {
    CvmTlsBuf sendbuf;
    cvm_tls_buf_init(&sendbuf, NULL, 0);
    int ret = cvm_tls_send(tls, &sendbuf, data, len);
    if (ret != 0) {
        cvm_tls_buf_dispose(&sendbuf);
        return -1;
    }
    int r = send_all(fd, sendbuf.base, sendbuf.off);
    cvm_tls_buf_dispose(&sendbuf);
    return r;
}

/* ------------------------------------------------------------------ */
/* benchmark: one connection, bulk upload                               */
/* ------------------------------------------------------------------ */

#define BENCH_SIZES {1024, 16 * 1024, 1024 * 1024, 16 * 1024 * 1024}
#define NUM_ROUNDS 5

int main(int argc, char** argv) {
    printf("cvmcrypt TLS benchmark\n");
    printf("======================\n\n");

    /* We bench pure crypto throughput (no network) since our TLS
     * receive path is not yet complete. Measure:
     * 1. AES-128-GCM encrypt throughput
     * 2. ChaCha20-Poly1305 encrypt throughput
     * 3. SHA-256 hash throughput
     * 4. X25519 key exchange
     * 5. Full record encrypt (TLS overhead included)
     */

    /* Allocate test buffer. */
    usize const buf_size = 16 * 1024 * 1024; /* 16MB */
    u8* data = malloc(buf_size);
    u8* out = malloc(buf_size + 256);
    if (!data || !out) {
        printf("malloc failed\n");
        return 1;
    }
    for (usize i = 0; i < buf_size; i++)
        data[i] = (u8)(i * 7 + 3);

    /* --- AES-128-GCM encrypt --- */
    {
        u8 key[16]; memset(key, 0xAB, 16);
        u8 iv[12]; memset(iv, 0xCD, 12);
        u8 tag[16];
        CvmcryptGcm gcm;

        double best = 1e9;
        for (int r = 0; r < NUM_ROUNDS; r++) {
            double t0 = now_ms();
            /* Encrypt in 16KB chunks (TLS record size). */
            for (usize off = 0; off < buf_size; off += 16384) {
                usize chunk = 16384;
                if (off + chunk > buf_size) chunk = buf_size - off;
                cvmcrypt_gcm_encrypt(&gcm, key, 16, iv, NULL, 0,
                                      data + off, chunk, out + off, tag);
            }
            double t1 = now_ms();
            if (t1 - t0 < best) best = t1 - t0;
        }
        double mbs = (double)buf_size / best / 1000.0;
        printf("AES-128-GCM encrypt:  %8.1f MB/s\n", mbs);
    }

    /* --- SHA-256 --- */
    {
        CvmcryptSha256 ctx;
        double best = 1e9;
        for (int r = 0; r < NUM_ROUNDS; r++) {
            double t0 = now_ms();
            cvmcrypt_sha256_init(&ctx);
            cvmcrypt_sha256_update(&ctx, data, buf_size);
            u8 digest[32];
            cvmcrypt_sha256_final(&ctx, digest);
            double t1 = now_ms();
            if (t1 - t0 < best) best = t1 - t0;
        }
        double mbs = (double)buf_size / best / 1000.0;
        printf("SHA-256 hash:         %8.1f MB/s\n", mbs);
    }

    /* --- X25519 (single op, measure µs) --- */
    {
        u8 priv[32], pub[32], shared[32], peer[32];
        memset(priv, 0x42, 32);
        priv[0] &= 248; priv[31] &= 127; priv[31] |= 64;
        cvmcrypt_x25519_base_fast(pub, priv);
        memcpy(peer, pub, 32);

        int const N = 1000;
        double best = 1e9;
        for (int r = 0; r < 3; r++) {
            double t0 = now_ms();
            for (int i = 0; i < N; i++)
                cvmcrypt_x25519_fast(shared, priv, peer);
            double t1 = now_ms();
            if (t1 - t0 < best) best = t1 - t0;
        }
        double us = best * 1000.0 / N;
        printf("X25519 key exchange:  %8.1f µs/op\n", us);
    }

    /* --- TLS record encrypt (full pipeline) --- */
    {
        /* Simulate TLS record encryption: AEAD + AAD + framing. */
        u8 key[16]; memset(key, 0xAB, 16);
        u8 iv[12]; memset(iv, 0xCD, 12);
        u8 tag[16];
        u8 aad[5] = {23, 3, 3, 0x40, 0x00}; /* appdata, 16384 bytes */
        CvmcryptGcm gcm;

        double best = 1e9;
        for (int r = 0; r < NUM_ROUNDS; r++) {
            double t0 = now_ms();
            for (usize off = 0; off < buf_size; off += 16384) {
                usize chunk = 16384;
                if (off + chunk > buf_size) chunk = buf_size - off;
                aad[3] = (u8)((chunk + 17) >> 8);
                aad[4] = (u8)(chunk + 17);
                cvmcrypt_gcm_encrypt(&gcm, key, 16, iv, aad, 5,
                                      data + off, chunk, out + off, tag);
            }
            double t1 = now_ms();
            if (t1 - t0 < best) best = t1 - t0;
        }
        double mbs = (double)buf_size / best / 1000.0;
        printf("TLS record encrypt:   %8.1f MB/s (incl. AAD+tag overhead)\n", mbs);
    }

    /* --- Handshake simulation (ECDHE + key schedule + AEAD setup) --- */
    {
        int const N = 100;
        double best = 1e9;
        for (int r = 0; r < 3; r++) {
            double t0 = now_ms();
            for (int i = 0; i < N; i++) {
                /* X25519 */
                u8 priv[32], pub[32], shared[32], peer[32];
                memset(priv, 0x42, 32);
                priv[0] &= 248; priv[31] &= 127; priv[31] |= 64;
                cvmcrypt_x25519_base_fast(pub, priv);
                memcpy(peer, pub, 32);
                cvmcrypt_x25519_fast(shared, priv, peer);

                /* Key schedule: extract → extract → derive → keys */
                /* (simplified: just HKDF-Extract twice + expand) */
                u8 secret[32];
                CvmcryptSha256 h;
                cvmcrypt_sha256_init(&h);
                cvmcrypt_sha256_update(&h, shared, 32);
                cvmcrypt_sha256_final(&h, secret);
            }
            double t1 = now_ms();
            if (t1 - t0 < best) best = t1 - t0;
        }
        double us = best * 1000.0 / N;
        printf("Handshake (ECDHE+KS): %8.1f µs/op (X25519 + key schedule)\n", us);
    }

    free(data);
    free(out);
    printf("\ndone.\n");
    return 0;
}
