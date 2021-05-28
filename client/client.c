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
#pragma comment(lib, "Ws2_32.lib")
#else
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
// Nothing needs to be done on POSIX; this is a Windows problem.
inline int SysInitializeNetwork() { return 1; }
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

#if WIN32
#include <openssl/applink.c>
#endif

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
#if WIN32
        while ((wret = send(fd, data, len, 0)) == -1 && errno == EINTR)
            ;
#else
        while ((wret = write(fd, data, len)) == -1 && errno == EINTR)
            ;
#endif
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

#if WIN32
        while ((rret = recv(fd, rbuf, input_len, 0)) == -1 && errno == EINTR)
            ;
#else
        while ((rret = read(fd, rbuf, input_len)) == -1 && errno == EINTR)
            ;
#endif

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

int handle_decrypted_data(const uint8_t* input, size_t input_size)
{
    fprintf(stderr, "Received: %s.\n", input);
    return 0;
}

int handle_input(ptls_t* tls, const uint8_t* input, size_t input_size)
{
    size_t input_off = 0;
    ptls_buffer_t plaintextbuf;
    int ret;

    if (input_size == 0)
        return 0;

    ptls_buffer_init(&plaintextbuf, "", 0);

    do {
        size_t consumed = input_size - input_off;
        ret = ptls_receive(tls, &plaintextbuf, input + input_off, &consumed);
        input_off += consumed;
    } while (ret == 0 && input_off < input_size);

    if (ret == 0)
    {
        fprintf(stderr, "Decode success. Input size was %d.\n", input_size);
        *(plaintextbuf.base + plaintextbuf.off) = 0; // terminating null
        ret = handle_decrypted_data(plaintextbuf.base, plaintextbuf.off);
    }
    else
    {
        fprintf(stderr, "Decode error: %d. Input size was %d.\n", ret, input_size);

    }

    ptls_buffer_dispose(&plaintextbuf);

    return ret;
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

int handle_connection(int client) {
    int rv = 0;
    char rbuf[1024], wbuf_small[1024];
    ptls_buffer_t wbuf;
    printf("Initializing TLS connection\n");

    // (0: client, 1 : server).
    ptls_t *tls = ptls_new(ctx, 0);
    ptls_buffer_init(&wbuf, wbuf_small, sizeof(wbuf_small));

    const char* server_name = "127.0.0.1";
    ptls_set_server_name(tls, server_name, 0);

    size_t rbuf_len = sizeof(rbuf);
    if (do_handshake(client, tls, &wbuf, rbuf, &rbuf_len, hsprop, (ptls_iovec_t){ NULL, 0 }) != 0) {
        rv = -1;
        goto exit;
    }
    wbuf.off = 0;

    printf("Handshake done.\n");

    /*if (decrypt_and_print(tls, (const uint8_t*)rbuf, rbuf_len) != 0) {
        rv = -1;
        goto exit;
    }*/

    // Receive a message from the server
#if WIN32
    rbuf_len = sizeof(rbuf);
    while ((rv = recv(client, rbuf, rbuf_len, 0)) == -1 && errno == EINTR)
        ;
#else
    while ((rv = read(client, rbuf, rbuf_len)) == -1 && errno == EINTR)
        ;
#endif

    handle_input(tls, (const uint8_t*)rbuf, rbuf_len);

exit:
    ptls_buffer_dispose(&wbuf);
    ptls_free(tls);
    return rv;
}

int run_client(struct sockaddr *sa, socklen_t sa_len) {
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
    }
    
    if (connect(fd, sa, sa_len) != 0)
    {
        perror("connect() failed");
        return -1;
    }

    perror("connected, doing TLS handshake...");

  
    handle_connection(fd);
#if WIN32
    closesocket(fd);
#else
    close(fd);
#endif

#if WIN32
    closesocket(fd);
#else
    close(fd);
#endif
    return 0;
}

void signal_handler(int info) {

}

int main(int argc, char *argv[]) {
    ossl_start();

    struct sockaddr_storage sa;
    socklen_t sa_len;
    ptls_iovec_t certs[16] = { { NULL } };
    ptls_openssl_sign_certificate_t sign_cert = { { NULL } };
    ptls_handshake_properties_t h = { { { NULL } } };

    //ptls_openssl_verify_certificate_t verifier;
    //ptls_openssl_init_verify_certificate(&verifier, NULL);

    ptls_context_t c = {
        ptls_openssl_random_bytes,
        &ptls_get_time,
        ptls_openssl_key_exchanges,
        ptls_openssl_cipher_suites,
        { NULL, 0 },
        NULL, // esni
        NULL, // on_client_hello
        NULL, // emit_certificate
        &sign_cert.super, // sign_certificate
        NULL //&verifier.super  // verify_certificate
    };

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
        rv = resolve_address((struct sockaddr*)&sa, &sa_len, "127.0.0.1", "8000");
    if (rv == 0)
        rv = run_client((struct sockaddr*)&sa, sa_len);

    printf("\nProgram exited with code %d.\n", rv);
    SysCleanupNetwork();
    return rv;
}
