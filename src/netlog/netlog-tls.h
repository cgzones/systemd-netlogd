/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <stdbool.h>

#include "socket-util.h"
#include "openssl-util.h"

typedef struct TLSManager TLSManager;

struct TLSManager {
        SSL_CTX *ctx;
        BIO *bio;
        SSL *ssl;

        int fd;

        bool connected;
};

void tls_manager_free(TLSManager *m);
int tls_manager_init(TLSManager **ret);

int tls_connect(TLSManager *m, SocketAddress *addr);
void tls_disconnect(TLSManager *m);

int tls_stream_writev(TLSManager *m, const struct iovec *iov, size_t iovcnt);

DEFINE_TRIVIAL_CLEANUP_FUNC(TLSManager*, tls_manager_free);
