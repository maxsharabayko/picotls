#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if WIN32
#include <Ws2tcpip.h>

inline int SysInitializeNetwork()
{
    WORD wVersionRequested = MAKEWORD(2, 2);
    WSADATA wsaData;
    return WSAStartup(wVersionRequested, &wsaData) == 0;
}

inline void SysCleanupNetwork()
{
    WSACleanup();
}
#else
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
// Nothing needs to be done on POSIX; this is a Windows problem.
inline bool SysInitializeNetwork() { return true; }
inline void SysCleanupNetwork() {}
#endif
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <picotls.h>
#include <picotls/openssl.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/pem.h>

#include <openssl/applink.c>

#define CERT_PATH "../certs/MyCertificate.crt"
#define PKEY_PATH "../certs/MyKey.key"

ptls_context_t *ctx = NULL;
ptls_handshake_properties_t *hsprop = NULL;
const int signals_list[] = { SIGINT, SIGTERM };

void ossl_start(void) {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

#if !defined(OPENSSL_NO_ENGINE)
    ENGINE_load_builtin_engines();
    ENGINE_register_all_ciphers();
    ENGINE_register_all_digests();
#endif
}

int read_cert(ptls_openssl_verify_certificate_t *verify_certificate) {
    FILE *fp;
    X509 *cert;

    if ((fp = fopen(CERT_PATH, "r")) == NULL) {
        fprintf(stderr, "Failed to open certificate file at %s\n", CERT_PATH);
        return -1;
    }

    while((cert = PEM_read_X509(fp, NULL, NULL, NULL)) != NULL) {
        ptls_iovec_t *dst = ctx->certificates.list + ctx->certificates.count++;
        dst->len = i2d_X509(cert, &dst->base);
    }

    fclose(fp);
    if (ctx->certificates.count == 0) {
        fprintf(stderr, "Failed to load certificates from file at %s\n", CERT_PATH);
        return -1;
    }

    if (ptls_openssl_init_verify_certificate(verify_certificate, NULL) != 0) {
        fprintf(stderr, "Failed to verify certificate from file at %s\n", CERT_PATH);
        return -1;
    }
    ctx->verify_certificate = &verify_certificate->super;
    return 0;
}

int read_pkey(ptls_openssl_sign_certificate_t *sign_certificate) {
    FILE *fp;

    if ((fp = fopen(PKEY_PATH, "r")) == NULL) {
        fprintf(stderr, "Failed to open private key file at %s\n", PKEY_PATH);
        return -1;
    }

    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (pkey == NULL) {
        fprintf(stderr, "Failed to load private key from file at %s\n", PKEY_PATH);
        return -1;
    }

    int rv = ptls_openssl_init_sign_certificate(sign_certificate, pkey);
    EVP_PKEY_free(pkey);
    if (rv)
        fprintf(stderr, "Failed to sign private key from file at %s\n", PKEY_PATH);
    return rv;
}

int resolve_address(struct sockaddr *sa, socklen_t *salen, const char *host, const char *port) {
    struct addrinfo hints, *res;
    int err;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV | AI_PASSIVE;

    if ((err = getaddrinfo(host, port, &hints, &res)) != 0 || res == NULL) {
        fprintf(stderr, "Failed to resolve address '%s:%s': %s\n", host, port,
                err != 0 ? gai_strerror(err) : "getaddrinfo returned NULL\n");
        return -1;
    }

    memcpy(sa, res->ai_addr, res->ai_addrlen);
    *salen = res->ai_addrlen;
    freeaddrinfo(res);
    return 0;
}

int write_all(int fd, const uint8_t *data, size_t len) {
    ssize_t wret;
    while (len != 0) {
        while ((wret = write(fd, data, len)) == -1 && errno == EINTR)
            ;
        if (wret <= 0) {
            fprintf(stderr, "Write to %d failed.\n", fd);
            return -1;
        }
        data += wret;
        len -= wret;
    }
    return 0;
}

int do_handshake(int fd, ptls_t *tls, ptls_buffer_t *wbuf, char *rbuf, size_t *rbuf_len, ptls_handshake_properties_t *hsprop, ptls_iovec_t unused) {
    size_t input_len = *rbuf_len;
    int ret;
    ssize_t rret = 0;
    *rbuf_len = 0;

    while ((ret = ptls_handshake(tls, wbuf, rbuf, rbuf_len, hsprop)) == PTLS_ERROR_IN_PROGRESS) {
        if (write_all(fd, wbuf->base, wbuf->off) != 0)
            return -1;
        wbuf->off = 0;

        while ((rret = read(fd, rbuf, input_len)) == -1 && errno == EINTR)
            ;

        if (rret < 0) {
            perror("Read from client failed");
            return -1;
        }
        *rbuf_len = rret;
    }

    if (ret != PTLS_ALERT_CLOSE_NOTIFY) {
        fprintf(stderr, "Handshake failed with error code %d.\n", ret);
        return -1;
    }

    if (write_all(fd, wbuf->base, wbuf->off) != 0)
        return -1;

    if (rret != *rbuf_len)
        memmove(rbuf, rbuf + *rbuf_len, rret - *rbuf_len);
    *rbuf_len = rret - *rbuf_len;
    return 0;
}

int decrypt_and_print(ptls_t *tls, const uint8_t *input, size_t inlen) {
    ptls_buffer_t decryptbuf;
    uint8_t decryptbuf_small[1024];
    int ret;

    ptls_buffer_init(&decryptbuf, decryptbuf_small, sizeof(decryptbuf_small));
    while (inlen != 0) {
        size_t consumed = inlen;
        if ((ret = ptls_receive(tls, &decryptbuf, input, &consumed)) != 0) {
            fprintf(stderr, "Failed to decrypt: %d\n", ret);
            ret = -1;
            goto exit;
        }
        input += consumed;
        inlen -= consumed;
        if (decryptbuf.off != 0) {
            if (write_all(1, decryptbuf.base, decryptbuf.off) != 0) {
                ret = -1;
                goto exit;
            }
            decryptbuf.off = 0;
        }
    }
    ret = 0;
exit:
    ptls_buffer_dispose(&decryptbuf);
    return ret;
}

int handle_connection(int server, int client) {
    int rv = 0;
    char rbuf[1024], wbuf_small[1024];
    ptls_buffer_t wbuf;
    printf("Connection received\n");

    ptls_t *tls = ptls_new(ctx, 1);
    ptls_buffer_init(&wbuf, wbuf_small, sizeof(wbuf_small));

    size_t rbuf_len = sizeof(rbuf);
    if (do_handshake(client, tls, &wbuf, rbuf, &rbuf_len, hsprop, (ptls_iovec_t){ NULL, 0 }) != 0) {
        rv = -1;
        goto exit;
    }
    wbuf.off = 0;

    if (decrypt_and_print(tls, (const uint8_t*)rbuf, rbuf_len) != 0) {
        rv = -1;
        goto exit;
    }

    // Send a message to the client:
    if ((rv = ptls_send(tls, &wbuf, "Hello, World!\n", strlen("Hello, World!\n"))) != 0) {
        fprintf(stderr, "Failed to encrypt message to client: %d\n", rv);
        rv = -1;
        goto exit;
    }

    if (write_all(client, wbuf.base, wbuf.off) != 0) {
        rv = -1;
        goto exit;
    }

exit:
    ptls_buffer_dispose(&wbuf);
    ptls_free(tls);
    return rv;
}

int run_server(struct sockaddr *sa, socklen_t sa_len) {
    int fd, on = 1;

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket(2) failed");
        return -1;
    } else if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
        return -1;
#if !WIN32
        // Setting SO_REUSEADDR on a socket in Windows behaves like setting SO_REUSEPORT
        // and SO_REUSEADDR on a socket in BSD, with one exception :
        // Prior to Windows 2003, a socket with SO_REUSEADDR could always been bound
        // to exactly the same source addressand port as an already bound socket,
        // even if the other socket did not have this option set when it was bound.
        // This behavior allowed an application "to steal" the connected port of another application.
    } else if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) != 0) {
        perror("setsockopt(SO_REUSEPORT) failed");
        return -1;
#endif
    } else if (bind(fd, sa, sa_len) != 0) {
        perror("bind(2) failed");
        return -1;
    } else if (listen(fd, SOMAXCONN) != 0) {
        perror("listen(2) failed");
        return -1;
    }

    fd_set active_fd_set;
    FD_ZERO(&active_fd_set);
    FD_SET(fd, &active_fd_set);
    const int maxfd = fd;

    int rv = 0;
    while (1) {
        int sel_rv = select(maxfd + 1, &active_fd_set, NULL, NULL, NULL);
        if (sel_rv < 0) {
            if (errno == EINTR)
                break;
            else {
                perror("select failed");
                rv = -1;
                break;
            }
        }

        if (FD_ISSET(fd, &active_fd_set)) {
            int connection;
            if ((connection = accept(fd, NULL, 0)) != -1) {
                handle_connection(fd, connection);
                close(connection);
            }
        }
    }

    close(fd);
    return rv;
}

void signal_handler(int info) {

}

int main(int argc, char *argv[]) {
    ossl_start();

    struct sockaddr_storage sa;
    socklen_t sa_len;
    ptls_iovec_t certs[16] = { { NULL } };
    ptls_openssl_sign_certificate_t sign_cert = { { NULL } };
    ptls_openssl_verify_certificate_t verify_certificate = { { NULL } };
    ptls_handshake_properties_t h = { { { NULL } } };

    ptls_context_t c = {
        ptls_openssl_random_bytes,
        ptls_openssl_key_exchanges,
        ptls_openssl_cipher_suites,
        { 0 }, // certificates are initialized below
        NULL,
        NULL,
        &sign_cert.super
    };

    c.certificates.list = certs;
    c.certificates.count = 0;

    ctx = &c;
    hsprop = &h;

    // Setup signal handlers
    int i, rv = 0;
    for (i = 0; i < (sizeof(signals_list) / sizeof(int)); i++) {
        if (signal(signals_list[i], signal_handler) == SIG_ERR) {
            fprintf(stderr, "Failed to setup signal handlers\n");
            rv = -1;
        }
    }
    SysInitializeNetwork();

    if (rv == 0)
        rv = read_cert(&verify_certificate);
    if (rv == 0)
        rv = read_pkey(&sign_cert);
    if (rv == 0)
        rv = resolve_address((struct sockaddr*)&sa, &sa_len, "127.0.0.1", "8000");
    if (rv == 0)
        rv = run_server((struct sockaddr*)&sa, sa_len);

    printf("\nProgram exited with code %d.\n", rv);
    SysCleanupNetwork();
    return rv;
}
