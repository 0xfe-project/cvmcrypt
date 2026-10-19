/*
 * tests/integration/tls_server_test.c
 *
 * A TLS 1.3 server, checked against `openssl s_client`. Same reasoning as the
 * client's interop test: the only way to know a handshake is right is to have
 * someone else complete it.
 *
 *	./tls_server_test <port> &
 *	openssl s_client -connect 127.0.0.1:<port> -tls1_3 -CAfile cert.pem
 *
 * The signing callback is the embedder's job — cvmcrypt never holds a private
 * key — so this file carries a P-256 key and turns (input, scheme) into a DER
 * ECDSA-Sig-Value the way a real deployment would.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "base/types.h"
#include "base/secure.h"
#include "ecc/p256.h"
#include "hash/sha256.h"
#include "tls/tls.h"
#include "tls/tls_conn.h"
#include "tls/tls_internal.h"

#include "server_assets.h"

/* ------------------------------------------------------------------ */
/* randomness                                                          */
/* ------------------------------------------------------------------ */

static void random_fill(u8* p, usize len) {
    static u32 s = 0x9e3779b9u;
    for (usize i = 0; i < len; i++) {
        s = s * 1664525u + 1013904223u;
        p[i] = (u8)(s >> 24);
    }
}

static void random_cb(CvmTlsRandomBytes* self, void* buf, usize len) {
    (void)self;
    random_fill(buf, len);
}
static CvmTlsRandomBytes const RANDOM = {.cb = random_cb};

static u64 now_cb(CvmTlsGetTime* self) {
    (void)self;
    return 0;
}
static CvmTlsGetTime const GET_TIME = {.cb = now_cb};

/* ------------------------------------------------------------------ */
/* DER ECDSA-Sig-Value                                                 */
/* ------------------------------------------------------------------ */

/* Minimal big-endian INTEGER: strip leading zeros, add one back when the top
 * bit is set so the value is not read as negative. */
static usize put_int(u8* out, u8 const* v, usize n) {
    usize start = 0;
    while (start + 1 < n && v[start] == 0)
        start++;
    usize const len = n - start;
    bool const pad = (v[start] & 0x80) != 0;

    usize o = 0;
    out[o++] = 0x02;
    out[o++] = (u8)(len + (pad ? 1 : 0));
    if (pad)
        out[o++] = 0x00;
    memcpy(out + o, v + start, len);
    return o + len;
}

/* ------------------------------------------------------------------ */
/* signing callback                                                    */
/* ------------------------------------------------------------------ */

static int sign_cb(CvmTlsSignCert* self, CvmTls* tls, u16* selected_algorithm,
                   CvmTlsBuf* output, CvmTlsVec input, u16 const* algorithms,
                   usize num_algorithms) {
    (void)self;
    (void)tls;
    (void)algorithms;
    (void)num_algorithms;

    CvmEcPriv priv;
    memset(&priv, 0, sizeof(priv));
    if (cvmcrypt_ec_priv_import_pkcs8(&priv, kServerKeyDer, KSERVERKEYDER_LEN) !=
        EC_OK) {
        fprintf(stderr, "[server] private key import failed\n");
        return -1;
    }

    u8 hash[32];
    cvmcrypt_sha256(input.base, input.len, hash);

    u8 k[32], r[32], s[32];
    random_fill(k, sizeof(k));
    if (!cvmcrypt_ecdsa_sign(&priv, hash, sizeof(hash), k, sizeof(k), r, s)) {
        fprintf(stderr, "[server] sign failed\n");
        memset(&priv, 0, sizeof(priv));
        return -1;
    }

    u8 body[160];
    usize body_len = 0;
    body[body_len++] = 0x30;
    usize const len_pos = body_len++;
    body_len += put_int(body + body_len, r, sizeof(r));
    body_len += put_int(body + body_len, s, sizeof(s));
    body[len_pos] = (u8)(body_len - 2);

    for (usize i = 0; i < body_len; i++) {
        if (cvm_tls_buf_push(output, body[i]) != 0) {
            memset(&priv, 0, sizeof(priv));
            return -1;
        }
    }

    *selected_algorithm = TLS_SIGNATURE_ECDSA_SECP256R1_SHA256;
    memset(&priv, 0, sizeof(priv));
    /* 0 is success: the caller tests != 0. Returning 1 here reported every
     * successful signature as a failure — the classic inverted-convention
     * bug that a 0/1-returning helper invites. */
    return 0;
}
static CvmTlsSignCert const SIGN_CERT = {.cb = sign_cb};

/* ------------------------------------------------------------------ */

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <port>\n", argv[0]);
        return 2;
    }
    int port = atoi(argv[1]);

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) {
        perror("socket");
        return 1;
    }
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons((uint16_t)port);
    if (bind(lfd, (struct sockaddr*)&sa, sizeof(sa)) != 0) {
        perror("bind");
        return 1;
    }
    listen(lfd, 4);
    printf("READY %d\n", port);
    fflush(stdout);

    int fd = accept(lfd, NULL, NULL);
    if (fd < 0) {
        perror("accept");
        return 1;
    }

    static CvmTlsCert certs[2];
    certs[0].der = (CvmTlsVec){(u8 const*)kServerCertDer, KSERVERCERTDER_LEN};
    certs[1].der = (CvmTlsVec){NULL, 0};

    CvmTlsContext ctx;
    cvm_tls_context_defaults(&ctx);
    ctx.get_time = (CvmTlsGetTime*)&GET_TIME;
    ctx.random_bytes = (CvmTlsRandomBytes*)&RANDOM;
    ctx.certificates = certs;
    ctx.sign_certificate = (CvmTlsSignCert*)&SIGN_CERT;

    CvmTls* tls = cvm_tls_new(&ctx, true, NULL);
    if (tls == NULL) {
        fprintf(stderr, "tls_new failed\n");
        return 1;
    }

    CvmTlsBuf out;
    cvm_tls_buf_init(&out, NULL, 0);
    u8 in[16384];

    for (int round = 0; round < 8 && !tls->handshake_complete; round++) {
        out.off = 0;
        ssize_t n = recv(fd, in, sizeof(in), 0);
        if (n <= 0)
            break;
        usize consumed = (usize)n;
        int ret = cvm_tls_handshake(tls, &out, in, &consumed, NULL);
        printf("[server] ret=%d state=%d consumed=%zu/%zd\n", ret, (int)tls->state,
               consumed, n);
        if (out.off > 0)
            send(fd, out.base, out.off, 0);
        if (ret != 0 && ret != TLS_ERROR_IN_PROGRESS)
            break;
    }

    if (!tls->handshake_complete) {
        fprintf(stderr, "FAIL: handshake did not complete\n");
        return 1;
    }
    printf("[server] HANDSHAKE COMPLETE\n");

    /* Echo one message back so the client can prove application data works. */
    out.off = 0;
    ssize_t n = recv(fd, in, sizeof(in), 0);
    if (n > 0) {
        usize consumed = (usize)n;
        CvmTlsBuf plain;
        cvm_tls_buf_init(&plain, NULL, 0);
        int rret = cvm_tls_receive(tls, &plain, in, &consumed);
        printf("[server] receive ret=%d plaintext=%zu\n", rret, plain.off);
        if (plain.off > 0) {
            out.off = 0;
            cvm_tls_send(tls, &out, plain.base, plain.off);
            send(fd, out.base, out.off, 0);
            printf("[server] echoed %zu bytes\n", plain.off);
        }
        cvm_tls_buf_dispose(&plain);
    }

    cvm_tls_buf_dispose(&out);
    cvm_tls_free(tls);
    close(fd);
    close(lfd);
    return 0;
}
