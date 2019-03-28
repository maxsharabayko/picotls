/*
 * Copyright (c) 2016 DeNA Co., Ltd., Kazuho Oku
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifdef _WINDOWS
#include "wincompat.h"
#endif
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "picotls.h"
#include "picotls/ffx.h"
#include "picotls/minicrypto.h"
#include "picotls/openssl.h"

#ifdef _WINDOWS
#define BENCH_OS "windows"
#ifdef _DEBUG
#define BENCH_MODE "check"
#else
#define BENCH_MODE "release"
#endif
#else
#define BENCH_OS "linux"
#ifdef NDEBUG
#define BENCH_MODE "release"
#else
#define BENCH_MODE "check"
#endif
#endif

/* Time in microseconds */
static bench_time()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

/* Single measurement.
 */

#define BENCH_BATCH 1000

static bench_run_one(ptls_aead_context_t *e, ptls_aead_context_t *d, size_t n, size_t l, uint64_t *t_enc, uint64_t *t_dec,
                     uint64_t *s)
{
    int ret = 0;
    uint8_t *v_in = NULL;
    uint8_t *v_enc[BENCH_BATCH];
    uint8_t *v_dec = NULL;
    uint64_t h[4];

    *t_enc = 0;
    *t_dec = 0;
    *s = 0;

    memset(v_enc, 0, sizeof(v_enc));
    memset(h, 0, sizeof(h));
    v_in = (uint8_t *)malloc(l);
    v_dec = (uint8_t *)malloc(l);
    if (v_in == NULL || v_dec == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
    }

    for (size_t i = 0; ret == 0 && i < BENCH_BATCH; i++) {
        v_enc[i] = (uint8_t *)malloc(l + PTLS_MAX_DIGEST_SIZE);
        if (v_enc[i] == 0) {
            ret = PTLS_ERROR_NO_MEMORY;
        }
    }

    if (ret == 0) {
        memset(v_in, 0, l);

        for (size_t k = 0; k < n;) {
            size_t e_len;
            size_t d_len;
            size_t i_max = ((n - k) > BENCH_BATCH) ? BENCH_BATCH : n - k;
            uint64_t old_h = h[0];
            uint64_t t_start = bench_time();
            uint64_t t_medium;
            uint64_t t_end;

            for (size_t i = 0; i < i_max; i++) {
                h[0]++;

                ptls_aead_encrypt_init(e, h[0], h, sizeof(h));
                e_len = ptls_aead_encrypt_update(e, v_enc[i], v_in, l);
                e_len += ptls_aead_encrypt_final(e, v_enc[i] + e_len);

                *s += (v_enc[i])[l];
            }

            t_medium = bench_time();

            h[0] = old_h;

            for (size_t i = 0; i < i_max; i++) {
                h[0]++;

                d_len = ptls_aead_decrypt(d, v_dec, v_enc[i], e_len, h[0], h, sizeof(h));
                if (d_len != l) {
                    ret = PTLS_ALERT_DECRYPT_ERROR;
                    break;
                }
                *s += v_dec[0];
            }

            t_end = bench_time();

            *t_enc += t_medium - t_start;
            *t_dec += t_end - t_medium;

            k += i_max;
        }
    }

    if (v_in != NULL) {
        free(v_in);
    }

    for (size_t i = 0; i < BENCH_BATCH; i++) {
        if (v_enc[i] != NULL) {
            free(v_enc[i]);
        }
    }

    if (v_dec != NULL) {
        free(v_dec);
    }

    return ret;
}

/* Measure one specific aead implementation
 */
static int bench_run_aead(int basic_ref, uint32_t s0, const char *prefix, const char *algo_name, ptls_aead_algorithm_t *aead, ptls_hash_algorithm_t *hash, size_t n, size_t l, uint64_t *s)
{
    int ret = 0;

    uint8_t secret[PTLS_MAX_SECRET_SIZE];
    ptls_aead_context_t *e;
    ptls_aead_context_t *d;
    uint64_t t_e = 0;
    uint64_t t_d = 0;

    *s += s0;

    memset(secret, 'z', sizeof(secret));
    e = ptls_aead_new(aead, hash, 1, secret, NULL);
    d = ptls_aead_new(aead, hash, 0, secret, NULL);

    if (e == NULL || d == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
    } else {
        ret = bench_run_one(e, d, n, l, &t_e, &t_d, s);
        if (ret == 0) {
            printf("%s, %d, %s, %d, %s, %s, %d, %d, %d, %d,\n", BENCH_OS, (int)(8*sizeof(size_t)), BENCH_MODE, basic_ref, prefix, algo_name, (int)n, (int)l, (int)t_e,
                   (int)t_d);
        }
    }

    if (e) {
        ptls_aead_free(e);
    }

    if (d) {
        ptls_aead_free(d);
    }

    return ret;
}

typedef struct st_ptls_bench_entry_t {
    const char *provider;
    const char *algo_name;
    ptls_aead_algorithm_t *aead;
    ptls_hash_algorithm_t *hash;
} ptls_bench_entry_t;

static ptls_bench_entry_t aead_list[] = {
    {"minicrypto", "aes128gcm", &ptls_minicrypto_aes128gcm, &ptls_minicrypto_sha256},
    {"minicrypto", "aes256gcm", &ptls_minicrypto_aes256gcm, &ptls_minicrypto_sha384},
    {"minicrypto", "chacha20poly1305", &ptls_minicrypto_chacha20poly1305, &ptls_minicrypto_sha256},
#if PTLS_OPENSSL_HAVE_CHACHA20_POLY1305
    {"openssl", "chacha20poly1305", &ptls_openssl_chacha20poly1305, &ptls_minicrypto_sha256},
#endif
    {"openssl", "aes128gcm", &ptls_openssl_aes128gcm, &ptls_minicrypto_sha256},
    {"openssl", "aes256gcm", &ptls_openssl_aes256gcm, &ptls_minicrypto_sha384}};

static size_t nb_aead_list = sizeof(aead_list) / sizeof(ptls_bench_entry_t);

int bench_basic(uint32_t *x)
{
    uint32_t s = 0;
    uint64_t t_start = bench_time();

    /* Evaluate the current CPU */
    for (uint32_t i = 0; i < 10000000; i++) {
        s += i;
    }
    *x = s;

    return (int)(bench_time() - t_start);
}

int main(int argc, char **argv)
{
    int ret = 0;
    uint32_t x = 0;
    uint64_t s = 0;
    int basic_ref = bench_basic(&x);
    
    printf("OS, cpu bits, mode, 10M ops, package, algorithm, N, L, encrypt us, decrypt us,\n");
    

    for (size_t i = 0; ret == 0 && i < nb_aead_list; i++) {
        ret = bench_run_aead(basic_ref, x, aead_list[i].provider, aead_list[i].algo_name, aead_list[i].aead, aead_list[i].hash, 1000,
                             1500, &s);
    }

    return ret;
}
